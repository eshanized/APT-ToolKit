"""
Service Detection Module for APT Toolkit

Performs service identification on open ports via:
- Banner grabbing
- SSL/TLS inspection
- Known service fingerprinting
- Optional protocol probes (HTTP, FTP, SMTP, etc.)
"""

import socket
import ssl
import json
from typing import Dict, List, Tuple, Optional
from concurrent.futures import ThreadPoolExecutor

from src.core.engine import ScanModule
from src.utils.helpers import ErrorHelpers
from src.utils.logger import get_logger
from src.utils.network import NetworkHelpers
from src.utils.config import config

logger = get_logger(__name__)


class ServiceDetector(ScanModule):
    """Module to identify services and versions on open ports"""

    def __init__(self):
        super().__init__()
        self.module_name = "service_detection"
        self.timeout = config.network.service_timeout
        self.max_threads = config.network.max_service_threads
        self.known_services = self._load_service_signatures()

    def _load_service_signatures(self) -> Dict[int, str]:
        """Load known port-to-service mappings (can be extended to fingerprints)"""
        return {
            21: "ftp",
            22: "ssh",
            23: "telnet",
            25: "smtp",
            53: "dns",
            80: "http",
            110: "pop3",
            111: "rpcbind",
            135: "msrpc",
            139: "netbios-ssn",
            143: "imap",
            443: "https",
            445: "smb",
            465: "smtps",
            587: "smtp",
            993: "imaps",
            995: "pop3s",
            3306: "mysql",
            3389: "rdp",
            5432: "postgresql",
            6379: "redis",
            8080: "http-proxy",
            8443: "https-alt"
        }

    def _grab_banner(self, host: str, port: int) -> Optional[str]:
        """Connect to service and attempt to read banner"""
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)
                try:
                    banner = sock.recv(1024)
                    return banner.decode(errors='ignore').strip()
                except Exception:
                    return None
        except Exception as e:
            logger.debug(f"Banner grab failed on {host}:{port} - {str(e)}")
            return None

    def _check_ssl(self, host: str, port: int) -> Optional[str]:
        """Check for SSL/TLS certificate to infer HTTPS or secure protocol"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    if cert:
                        return "ssl/tls"
        except Exception as e:
            logger.debug(f"SSL check failed on {host}:{port} - {str(e)}")
        return None

    def _identify_service(self, host: str, port: int) -> Dict[str, str]:
        """Identify service running on the port using banner, SSL, and known mapping"""
        info = {
            "port": port,
            "service": "unknown",
            "version": "",
            "ssl": False,
            "banner": ""
        }

        # Known service mapping
        if port in self.known_services:
            info["service"] = self.known_services[port]

        # SSL/TLS check
        ssl_type = self._check_ssl(host, port)
        if ssl_type:
            info["ssl"] = True
            if port in [443, 465, 993, 995, 8443]:
                info["service"] = info["service"] or "https"

        # Banner grabbing
        banner = self._grab_banner(host, port)
        if banner:
            info["banner"] = banner
            banner_lower = banner.lower()

            # Basic banner fingerprinting
            if "apache" in banner_lower:
                info["service"] = "http"
                info["version"] = banner
            elif "nginx" in banner_lower:
                info["service"] = "http"
                info["version"] = banner
            elif "smtp" in banner_lower:
                info["service"] = "smtp"
                info["version"] = banner
            elif "ftp" in banner_lower:
                info["service"] = "ftp"
                info["version"] = banner
            elif "ssh" in banner_lower:
                info["service"] = "ssh"
                info["version"] = banner

        return info

    def _scan_host_ports(self, host: str, ports: List[int]) -> List[Dict[str, str]]:
        """Scan all ports on a host to detect running services"""
        results = []

        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = {
                executor.submit(self._identify_service, host, port): port
                for port in ports
            }

            for future in futures:
                try:
                    result = future.result()
                    if result:
                        results.append(result)
                except Exception as e:
                    logger.error(f"Service detection failed on {host}:{futures[future]}: {str(e)}")

        return results

    def execute(self, target: str, open_ports: List[int]) -> Dict[str, List[Dict[str, str]]]:
        """Run service detection on given target and ports"""
        if not NetworkHelpers.validate_ip_or_domain(target):
            logger.error(f"Invalid host target: {target}")
            return {"error": "Invalid host target"}

        logger.info(f"Starting service detection for {target} on {len(open_ports)} ports")
        result = self._scan_host_ports(target, open_ports)
        logger.info(f"Completed service detection on {target}")
        return {
            "target": target,
            "services": result,
            "count": len(result)
        }


# Module registration
def init_module():
    return ServiceDetector()

# Example (for dev/testing):
# detector = ServiceDetector()
# result = detector.execute("example.com", [22, 80, 443, 3306])
# print(json.dumps(result, indent=2))
