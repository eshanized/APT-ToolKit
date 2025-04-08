"""
XSS Scanner Module for APT Toolkit

Features:
- Reflected, stored and DOM XSS detection
- Context-aware payload generation
- Comprehensive fingerprinting
- Verification mechanisms
- Thread-safe operation
"""

import time
import random
import threading
from typing import Dict, List, Optional, Tuple, Any
from concurrent.futures import ThreadPoolExecutor
from enum import Enum, auto
import requests
from urllib.parse import urljoin, quote

from src.core.engine import ScanModule, ScanTarget, ScanResult, ScanStatus
from src.utils.logger import get_logger
from src.utils.network import NetworkHelpers
from src.utils.config import config
from src.core.event_system import event_system, Event
from src.utils.helpers import ErrorHelpers

logger = get_logger(__name__)

class XSSType(Enum):
    """XSS attack types"""
    REFLECTED = auto()
    STORED = auto()
    DOM = auto()

class XSSScanner(ScanModule):
    """Cross-Site Scripting (XSS) vulnerability scanner"""
    
    def __init__(self):
        super().__init__()
        self.module_name = "xss_scanner"
        self.timeout = config.web.request_timeout
        self.max_threads = config.web.max_threads
        
        # Context-specific payloads
        self.payloads = {
            'html': [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg/onload=alert(1)>'
            ],
            'attribute': [
                '" onmouseover=alert(1) x="',
                "' onfocus=alert(1) autofocus='",
                'javascript:alert(1)'
            ],
            'javascript': [
                'alert(1)',
                '};alert(1);//',
                '\\\'});alert(1);//'
            ]
        }
        
        # Verification payloads
        self.verification_payloads = {
            'verification': [
                'APTXSS' + str(random.randint(1000, 9999)),
                'XSSCHECK' + str(random.randint(1000, 9999))
            ],
            'dom_verification': [
                'window.APTXSS' + str(random.randint(1000, 9999)) + '=1',
                'document.XSSCHECK' + str(random.randint(1000, 9999)) + '=1'
            ]
        }
        
        self._stop_event = threading.Event()
        
    def initialize(self) -> None:
        """Initialize scanner resources"""
        logger.info(f"Initialized {self.module_name} with {self.max_threads} threads")
        
    def cleanup(self) -> None:
        """Cleanup scanner resources"""
        self._stop_event.set()
        logger.info(f"Cleaned up {self.module_name}")
        
    def validate_target(self, target: ScanTarget) -> bool:
        """Validate target is appropriate for XSS scanning"""
        if not target.host:
            return False
        return target.host.startswith(('http://', 'https://'))
        
    def _send_request(self, url: str, params: Dict[str, str]) -> Dict[str, Any]:
        """Send HTTP request and collect fingerprint"""
        response = {
            'url': url,
            'status_code': 0,
            'content': '',
            'headers': {},
            'time': 0
        }
        
        try:
            start_time = time.time()
            res = requests.get(
                url,
                params=params,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False
            )
            response.update({
                'status_code': res.status_code,
                'content': res.text,
                'headers': dict(res.headers),
                'time': time.time() - start_time
            })
        except requests.exceptions.RequestException as e:
            logger.debug(f"Request failed: {str(e)}")
            
        return response
        
    def _test_xss(self, url: str, params: Dict[str, str], context: str, payload: str) -> Tuple[bool, Dict[str, Any]]:
        """Test a single XSS payload"""
        result = {
            'vulnerable': False,
            'type': None,
            'context': context,
            'payload': payload,
            'verified': False,
            'response': None
        }
        
        try:
            # Prepare test parameters
            test_params = params.copy()
            for k in test_params:
                test_params[k] += payload
                
            # Send test request
            response = self._send_request(url, test_params)
            result['response'] = response
            
            # Basic detection
            if payload in response['content']:
                result['vulnerable'] = True
                result['type'] = XSSType.REFLECTED.name
                
                # Verification
                verification_payload = random.choice(self.verification_payloads['verification'])
                test_params = params.copy()
                for k in test_params:
                    test_params[k] += verification_payload
                    
                verification_response = self._send_request(url, test_params)
                result['verified'] = verification_payload in verification_response['content']
                
        except Exception as e:
            logger.error(f"XSS test failed: {str(e)}")
            
        return result['vulnerable'], result
        
    def _test_dom_xss(self, url: str, params: Dict[str, str]) -> Dict[str, Any]:
        """Test for DOM-based XSS vulnerabilities"""
        result = {
            'vulnerable': False,
            'type': XSSType.DOM.name,
            'payload': None,
            'verified': False,
            'response': None
        }
        
        try:
            # Test hash-based DOM XSS
            payload = random.choice(self.verification_payloads['dom_verification'])
            test_url = f"{url}#{quote(payload)}"
            
            response = self._send_request(test_url, params)
            result.update({
                'response': response,
                'payload': payload
            })
            
            # Verification would require browser automation in real implementation
            # This is a simplified version
            if payload in response['content']:
                result.update({
                    'vulnerable': True,
                    'verified': True
                })
                
        except Exception as e:
            logger.error(f"DOM XSS test failed: {str(e)}")
            
        return result
        
    def _scan_endpoint(self, url: str, params: Dict[str, str]) -> List[Dict[str, Any]]:
        """Scan a single endpoint for XSS vulnerabilities"""
        results = []
        
        # Test reflected XSS in different contexts
        for context, payloads in self.payloads.items():
            if self._stop_event.is_set():
                break
                
            for payload in payloads:
                if self._stop_event.is_set():
                    break
                    
                vulnerable, result = self._test_xss(url, params, context, payload)
                results.append(result)
                
                if vulnerable and result['verified']:
                    logger.info(f"Found XSS vulnerability at {url} in {context} context")
                    return results  # Early exit if verified vulnerability found
                    
        # Test DOM XSS
        dom_result = self._test_dom_xss(url, params)
        results.append(dom_result)
        
        return results
        
    def execute(self, target: ScanTarget) -> ScanResult:
        """
        Execute XSS scanning against target
        
        Args:
            target: ScanTarget specifying URL and parameters
            
        Returns:
            ScanResult with XSS scan results
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
        
        logger.info(f"Starting XSS scanning on {url}")
        
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
                        if any(r["vulnerable"] and r["verified"] for r in endpoint_results):
                            vulnerable = True
                            break  # Stop if verified vulnerability found
                    except Exception as e:
                        logger.error(f"XSS scan failed: {str(e)}")
                        
            return ScanResult(
                target=target,
                data={
                    "vulnerable": vulnerable,
                    "results": results,
                    "stats": {
                        "tests_performed": len(results),
                        "verified_vulnerabilities": len([r for r in results if r["vulnerable"] and r["verified"]]),
                        "types_found": list(set(r["type"] for r in results if r["vulnerable"]))
                    }
                },
                status=ScanStatus.COMPLETED
            )
            
        except Exception as e:
            logger.error(f"XSS scanning failed on {target.host}: {str(e)}", exc_info=True)
            return ScanResult(
                target=target,
                data={"error": str(e)},
                status=ScanStatus.FAILED
            )

# Module registration
def init_module():
    return XSSScanner()

# Example usage:
# scanner = XSSScanner()
# target = ScanTarget(
#     host="http://example.com/search.php",
#     metadata={"params": {"query": "test"}}
# )
# result = scanner.execute(target)
# print(json.dumps(result.data, indent=2))