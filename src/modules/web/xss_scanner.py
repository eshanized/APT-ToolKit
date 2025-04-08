# src/modules/web/xss_scanner.py
import re
import time
import threading
from typing import Any, Dict, List, Optional, Tuple, Union
from concurrent.futures import ThreadPoolExecutor, as_completed
from enum import Enum, auto
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

import requests

from src.core.scan_manager import ScanResult, ScanStatus, ScanTarget
from src.utils.logger import get_logger
from src.utils.validators import validate_url, sanitize_input
from src.core.event_system import Event, event_system
from src.utils.network import NetworkHelpers
from src.utils.config import config

logger = get_logger(__name__, structured=True)

class XSSType(Enum):
    """Enumeration of XSS attack types with severity levels"""
    REFLECTED = (auto(), "medium")
    STORED = (auto(), "high")
    DOM_BASED = (auto(), "medium")
    BLIND = (auto(), "high")

    def __init__(self, value, severity):
        self._value_ = value
        self.severity = severity

class XSSResult:
    """Detailed result container for XSS tests"""
    
    def __init__(self):
        self.vulnerable = False
        self.type: Optional[XSSType] = None
        self.payload: Optional[str] = None
        self.evidence: Optional[str] = None
        self.parameter: Optional[str] = None
        self.context: Optional[str] = None
        self.response_length: Optional[int] = None
        self.response_code: Optional[int] = None
        
    def to_dict(self) -> Dict[str, Any]:
        return {
            "vulnerable": self.vulnerable,
            "type": self.type.name if self.type else None,
            "severity": self.type.severity if self.type else None,
            "payload": self.payload,
            "evidence": self.evidence,
            "parameter": self.parameter,
            "context": self.context,
            "response_length": self.response_length,
            "response_code": self.response_code
        }

class XSSScanner:
    """Advanced XSS detection module with multiple techniques"""
    
    # Payloads categorized by context and injection type
    PAYLOADS = {
        "html": [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg/onload=alert(1)>",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>"
        ],
        "attribute": [
            "\" onmouseover=alert(1) x=\"",
            "' onmouseover=alert(1) x='",
            "javascript:alert(1)"
        ],
        "javascript": [
            "';alert(1)//",
            "\";alert(1)//",
            "alert(1)",
            "eval(String.fromCharCode(97,108,101,114,116,40,49,41))"
        ],
        "dom": [
            "#<img src=x onerror=alert(1)>",
            "#javascript:alert(1)",
            "?param=<script>alert(1)</script>"
        ]
    }
    
    # Context detection patterns
    CONTEXT_PATTERNS = {
        "html": r"(?i)<[a-z][^>]*>.*{input}.*<\/[a-z]+>",
        "attribute": r"(?i)(<[a-z]+[^>]*\s[a-z-]+=['\"]?.*){input}",
        "javascript": r"(?i)(var\s+\w+\s*=\s*['\"]|\(\s*['\"]|=\s*['\"]).*{input}",
        "url": r"(?i)(href|src|action)\s*=\s*['\"]?.*{input}"
    }
    
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
        Initialize XSS scanner
        
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
            "XSSScanner initialized",
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
        logger.info("XSS scan stopped by request")

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
                "Request failed during XSS test",
                extra={"data": {"url": self.url, "error": str(e)}}
            )
            raise

    def _detect_context(self, param: str, value: str = "CONTEXT_TEST") -> Optional[str]:
        """Detect injection context for a parameter"""
        try:
            # Prepare test data
            test_params = None
            test_data = None
            
            if self.method == "GET":
                test_params = self.query_params.copy()
                test_params[param] = [value]
                request_params = {k: v[0] if len(v) == 1 else v for k, v in test_params.items()}
                response = self._send_request(params=request_params)
            else:
                test_data = self.original_data.copy()
                test_data[param] = value
                response = self._send_request(data=test_data)
            
            # Check response for context patterns
            response_text = response.text.replace(value, "{input}")
            
            for context_type, pattern in self.CONTEXT_PATTERNS.items():
                if re.search(pattern.format(input="{input}"), response_text, re.IGNORECASE):
                    return context_type
                    
            return None
                
        except Exception as e:
            logger.warning(
                "Context detection failed",
                extra={"data": {"parameter": param, "error": str(e)}}
            )
            return None

    def _test_payload(
        self,
        param: str,
        payload: str,
        context: str,
        xss_type: XSSType
    ) -> Optional[XSSResult]:
        """Test a single XSS payload against a parameter"""
        if self._stop_event.is_set():
            return None
            
        result = XSSResult()
        result.parameter = param
        result.payload = payload
        result.type = xss_type
        result.context = context
        
        try:
            # Prepare test data
            test_params = None
            test_data = None
            
            if self.method == "GET":
                test_params = self.query_params.copy()
                test_params[param] = [payload]
                request_params = {k: v[0] if len(v) == 1 else v for k, v in test_params.items()}
                response = self._send_request(params=request_params)
            else:
                test_data = self.original_data.copy()
                test_data[param] = payload
                response = self._send_request(data=test_data)
                
            result.response_code = response.status_code
            result.response_length = len(response.content)
            
            # Check if payload was reflected and executed
            if self._check_payload_success(payload, response.text, context):
                result.vulnerable = True
                result.evidence = f"Payload executed in {context} context"
                return result
                
        except Exception as e:
            logger.debug(
                "Payload test failed",
                extra={
                    "data": {
                        "parameter": param,
                        "payload": payload,
                        "context": context,
                        "error": str(e)
                    }
                }
            )
        
        return None

    def _check_payload_success(self, payload: str, response_text: str, context: str) -> bool:
        """Check if XSS payload was successful"""
        # Simple check for reflected payload
        if payload not in response_text:
            return False
            
        # Context-specific checks
        if context == "html":
            # Check if script tags or event handlers are intact
            return ("<script>" in payload and "<script>" in response_text) or \
                   ("onerror=" in payload and "onerror=" in response_text)
        elif context == "attribute":
            # Check if event handler is intact
            return "onmouseover=" in payload and "onmouseover=" in response_text
        elif context == "javascript":
            # Check if JS code is intact
            return "alert(1)" in payload and "alert(1)" in response_text
        elif context == "url":
            # Check if URL-based payload is intact
            return "javascript:" in payload and "javascript:" in response_text
            
        return False

    def _test_parameter(
        self,
        param: str,
        contexts: List[str] = None,
        xss_types: List[XSSType] = None
    ) -> List[XSSResult]:
        """Test all payloads against a single parameter"""
        if self._stop_event.is_set():
            return []
            
        contexts = contexts or list(self.PAYLOADS.keys())
        xss_types = xss_types or list(XSSType)
        results = []
        
        # First detect context if not provided
        detected_context = self._detect_context(param)
        if detected_context:
            contexts = [detected_context]
        
        for context in contexts:
            if self._stop_event.is_set():
                break
                
            payloads = self.PAYLOADS.get(context, [])
            
            for payload in payloads:
                if self._stop_event.is_set():
                    break
                    
                # Determine XSS type based on payload and context
                if context == "dom":
                    xss_type = XSSType.DOM_BASED
                elif "onerror" in payload or "onload" in payload:
                    xss_type = XSSType.STORED
                else:
                    xss_type = XSSType.REFLECTED
                    
                result = self._test_payload(param, payload, context, xss_type)
                if result:
                    results.append(result)
                    if result.vulnerable:
                        return results  # Early exit if vulnerability found
                        
        return results

    def scan(
        self,
        params: Optional[List[str]] = None,
        contexts: Optional[List[str]] = None,
        xss_types: Optional[List[XSSType]] = None
    ) -> ScanResult:
        """
        Perform comprehensive XSS scan
        
        Args:
            params: Specific parameters to test (None for all)
            contexts: Specific contexts to test (None for all)
            xss_types: Specific XSS types to test (None for all)
            
        Returns:
            ScanResult with vulnerability information
        """
        scan_result = ScanResult(
            module="XSSScanner",
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
                    executor.submit(self._test_parameter, param, contexts, xss_types): param
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
                                    "type": "xss",
                                    "severity": result.type.severity,
                                    "details": result.to_dict()
                                }
                            )
                            
            if vulnerabilities:
                scan_result.status = ScanStatus.VULNERABLE
                scan_result.data = {
                    "vulnerabilities": vulnerabilities,
                    "summary": {
                        "total": len(vulnerabilities),
                        "by_type": {
                            typ.name: len([v for v in vulnerabilities if v["type"] == typ.name])
                            for typ in XSSType
                        },
                        "by_context": {
                            ctx: len([v for v in vulnerabilities if v["context"] == ctx])
                            for ctx in self.PAYLOADS.keys()
                        }
                    }
                }
            else:
                scan_result.status = ScanStatus.COMPLETED
                scan_result.data = {"message": "No XSS vulnerabilities found"}
                
        except Exception as e:
            logger.error(
                "XSS scan failed",
                extra={"data": {"error": str(e), "url": self.url}},
                exc_info=True
            )
            scan_result.status = ScanStatus.FAILED
            scan_result.data = {"error": str(e)}
            
        return scan_result

# Example usage:
# target = ScanTarget(host="http://example.com/search.php")
# scanner = XSSScanner(target)
# result = scanner.scan()
# print(result.to_json())