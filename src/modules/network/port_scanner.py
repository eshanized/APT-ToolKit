"""
Port Scanner Module for APT Toolkit

Features:
- TCP connect scanning
- Configurable port ranges
- Common port list
- Thread-safe operation
- Rate limiting
- Progress reporting
"""

import socket
import time
from typing import List, Optional, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from enum import Enum, auto

from src.core.engine import ScanModule, ScanTarget, ScanResult, ScanStatus
from src.utils.logger import get_logger
from src.utils.network import NetworkHelpers
from src.utils.config import config
from src.core.event_system import event_system, Event

logger = get_logger(__name__)

class PortState(Enum):
    """Port scanning result states"""
    OPEN = auto()
    CLOSED = auto()
    FILTERED = auto()
    ERROR = auto()

class PortScanner(ScanModule):
    """Advanced port scanning module"""
    
    def __init__(self):
        super().__init__()
        self.module_name = "port_scanner"
        self.timeout = config.network.port_scan_timeout
        self.max_threads = config.network.max_port_threads
        self.common_ports = self._load_common_ports()
        
    def _load_common_ports(self) -> List[int]:
        """Load commonly targeted ports"""
        return [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
            993, 995, 1723, 3306, 3389, 5900, 8080
        ]
        
    def initialize(self) -> None:
        """Initialize scanner resources"""
        logger.info(f"Initialized {self.module_name} with {self.max_threads} threads")
        
    def cleanup(self) -> None:
        """Cleanup scanner resources"""
        logger.info(f"Cleaning up {self.module_name}")
        
    def validate_target(self, target: ScanTarget) -> bool:
        """Validate target is appropriate for port scanning"""
        if not target.host:
            return False
        return NetworkHelpers.validate_ip_or_domain(target.host)
        
    def _scan_port(self, target: ScanTarget, port: int) -> Dict[str, Any]:
        """Scan a single port"""
        result = {
            "port": port,
            "state": PortState.ERROR,
            "error": None,
            "service": None,
            "protocol": target.protocol
        }
        
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                
                # Check if we should interrupt
                if self._interrupt.is_set():
                    return result
                    
                start_time = time.time()
                conn_result = sock.connect_ex((target.host, port))
                elapsed = time.time() - start_time
                
                if conn_result == 0:
                    result["state"] = PortState.OPEN
                    # Try to grab quick banner if port is open
                    try:
                        banner = sock.recv(1024)
                        if banner:
                            result["service"] = banner.decode(errors='ignore').strip()
                    except:
                        pass
                else:
                    result["state"] = PortState.CLOSED
                    
                result["response_time"] = elapsed
                
        except socket.timeout:
            result["state"] = PortState.FILTERED
        except Exception as e:
            result["error"] = str(e)
            
        return result
        
    def _scan_ports(self, target: ScanTarget, ports: List[int]) -> List[Dict[str, Any]]:
        """Scan multiple ports on a target"""
        results = []
        completed = 0
        total = len(ports)
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self._scan_port, target, port): port
                for port in ports
            }
            
            for future in as_completed(futures):
                if self._interrupt.is_set():
                    break
                    
                try:
                    result = future.result()
                    results.append(result)
                    completed += 1
                    
                    # Report progress
                    progress = (completed / total) * 100
                    event_system.emit(
                        "scan_progress",
                        module=self.module_name,
                        target=target.host,
                        progress=progress,
                        current=completed,
                        total=total
                    )
                except Exception as e:
                    logger.error(f"Port scan failed: {str(e)}")
                    
        return results
        
    def execute(self, target: ScanTarget) -> ScanResult:
        """
        Execute port scan against target
        
        Args:
            target: ScanTarget specifying host and optional ports
            
        Returns:
            ScanResult with port scan results
        """
        if not self.validate_target(target):
            logger.error(f"Invalid scan target: {target.host}")
            return ScanResult(
                target=target,
                data={"error": "Invalid target"},
                status=ScanStatus.FAILED
            )
            
        # Determine ports to scan
        ports_to_scan = target.ports or self.common_ports
        if not ports_to_scan:
            ports_to_scan = list(range(1, 1025))  # Default to well-known ports
            
        logger.info(
            f"Starting port scan on {target.host} for {len(ports_to_scan)} ports "
            f"(protocol: {target.protocol})"
        )
        
        try:
            scan_data = self._scan_ports(target, ports_to_scan)
            
            return ScanResult(
                target=target,
                data={
                    "ports": scan_data,
                    "open_ports": [
                        p["port"] for p in scan_data 
                        if p["state"] == PortState.OPEN
                    ],
                    "stats": {
                        "total": len(scan_data),
                        "open": len([p for p in scan_data if p["state"] == PortState.OPEN]),
                        "filtered": len([p for p in scan_data if p["state"] == PortState.FILTERED]),
                        "errors": len([p for p in scan_data if p["state"] == PortState.ERROR])
                    }
                },
                status=ScanStatus.COMPLETED
            )
            
        except Exception as e:
            logger.error(f"Port scan failed on {target.host}: {str(e)}", exc_info=True)
            return ScanResult(
                target=target,
                data={"error": str(e)},
                status=ScanStatus.FAILED
            )

# Module registration
def init_module():
    return PortScanner()

# Example usage:
# scanner = PortScanner()
# target = ScanTarget(host="example.com", ports=[22, 80, 443])
# result = scanner.execute(target)
# print(json.dumps(result.data, indent=2))