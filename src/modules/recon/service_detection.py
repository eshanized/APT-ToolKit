"""
Service Detection Module for APT Toolkit

Features:
- Protocol-agnostic service identification
- Banner grabbing and fingerprinting
- Port scanning integration
- Service version detection
- CPE matching for vulnerability correlation
"""

import json
from pathlib import Path
import socket
import asyncio
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
import re
import ssl
from concurrent.futures import ThreadPoolExecutor
from src.core.engine import ScanModule, ScanTarget
from src.utils.logger import get_logger
from src.utils.network import NetworkHelpers
from src.utils.config import config
from src.utils.threading_utils import net_pool, scan_pool

logger = get_logger(__name__)

@dataclass
class Service:
    """Identified service container"""
    port: int
    protocol: str
    service_name: str
    version: Optional[str] = None
    banner: Optional[str] = None
    cpe: Optional[str] = None
    extra_info: Optional[Dict[str, str]] = None

class ServiceDetector(ScanModule):
    """Network service detection and fingerprinting module"""
    
    def __init__(self):
        super().__init__()
        self.module_name = "service_detector"
        self._signatures = self._load_signatures()
        self._timeout = config.network.service_timeout
        self._max_workers = config.network.max_service_workers
        self._session = self._create_ssl_context()

    def _load_signatures(self) -> List[Dict]:
        """Load service fingerprint signatures"""
        try:
            sig_path = Path(config.data_dir) / "service_signatures.json"
            with open(sig_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load service signatures: {str(e)}")
            return []

    def _create_ssl_context(self) -> ssl.SSLContext:
        """Create configured SSL context"""
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.options |= ssl.OP_NO_SSLv2
        ctx.options |= ssl.OP_NO_SSLv3
        return ctx

    async def _probe_port(self, target: str, port: int) -> Optional[Service]:
        """Conduct service probing on a single port"""
        try:
            # Try TCP first
            service = await self._check_tcp_service(target, port)
            if service:
                return service

            # Fall back to UDP if no TCP service found
            return await self._check_udp_service(target, port)
        except Exception as e:
            logger.debug(f"Service probe failed on {target}:{port}: {str(e)}")
            return None

    async def _check_tcp_service(self, target: str, port: int) -> Optional[Service]:
        """Detect TCP-based services"""
        try:
            # Establish connection with timeout
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target, port),
                timeout=self._timeout
            )

            try:
                # Send protocol-specific probes
                banner = await self._get_banner(reader, writer, port)
                if not banner:
                    return None

                # Fingerprint the service
                service = self._fingerprint_service(port, 'tcp', banner)
                service.banner = banner[:1024]  # Truncate large banners
                return service
            finally:
                writer.close()
                await writer.wait_closed()
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return None
        except Exception as e:
            logger.warning(f"TCP service check failed on {target}:{port}: {str(e)}")
            return None

    async def _check_udp_service(self, target: str, port: int) -> Optional[Service]:
        """Detect UDP-based services"""
        try:
            loop = asyncio.get_running_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self._timeout)

            try:
                # UDP requires protocol-specific probes
                probe = self._get_udp_probe(port)
                if not probe:
                    return None

                await loop.sock_connect(sock, (target, port))
                await loop.sock_sendall(sock, probe)
                data = await loop.sock_recv(sock, 1024)

                if data:
                    service = self._fingerprint_service(port, 'udp', data.decode('utf-8', errors='ignore'))
                    service.banner = data[:1024].decode('utf-8', errors='ignore')
                    return service
            finally:
                sock.close()
        except socket.timeout:
            return None
        except Exception as e:
            logger.debug(f"UDP service check failed on {target}:{port}: {str(e)}")
            return None

    def _get_udp_probe(self, port: int) -> Optional[bytes]:
        """Get protocol-specific UDP probe"""
        common_udp_ports = {
            53: b"\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",  # DNS
            161: b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x71\xb4\xb5\x68\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",  # SNMP
            123: b"\x1a\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"  # NTP
        }
        return common_udp_ports.get(port)

    async def _get_banner(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, port: int) -> Optional[str]:
        """Retrieve service banner with protocol-specific probes"""
        try:
            # Common ports with specific probes
            if port == 80:  # HTTP
                writer.write(b"GET / HTTP/1.0\r\n\r\n")
                await writer.drain()
                return (await reader.read(1024)).decode('utf-8', errors='ignore')

            elif port == 443:  # HTTPS
                ssl_reader, ssl_writer = await asyncio.wait_for(
                    self._upgrade_to_ssl(reader, writer),
                    timeout=self._timeout
                )
                try:
                    ssl_writer.write(b"GET / HTTP/1.0\r\n\r\n")
                    await ssl_writer.drain()
                    return (await ssl_reader.read(1024)).decode('utf-8', errors='ignore')
                finally:
                    ssl_writer.close()
                    await ssl_writer.wait_closed()

            elif port == 21:  # FTP
                return (await reader.readuntil(b"\n")).decode('utf-8', errors='ignore')

            elif port == 22:  # SSH
                return (await reader.readuntil(b"\n")).decode('utf-8', errors='ignore')

            # Generic banner grab
            await asyncio.sleep(0.5)  # Wait for initial banner
            if reader._buffer:  # Check if data is already buffered
                return (await reader.read(1024)).decode('utf-8', errors='ignore')
        except Exception as e:
            logger.debug(f"Banner grab failed on port {port}: {str(e)}")
        return None

    async def _upgrade_to_ssl(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Upgrade connection to SSL/TLS"""
        return await asyncio.wait_for(
            asyncio.wrap_ssl_stream(
                reader,
                writer,
                server_hostname='',
                ssl_context=self._session
            ),
            timeout=self._timeout
        )

    def _fingerprint_service(self, port: int, protocol: str, banner: str) -> Service:
        """Identify service from banner using signature database"""
        # Initial service guess from port
        service_name = self._port_to_service(port, protocol)
        version = None
        cpe = None

        # Match against known signatures
        for sig in self._signatures:
            if re.search(sig['pattern'], banner, re.IGNORECASE):
                service_name = sig.get('service', service_name)
                version = sig.get('version')
                cpe = sig.get('cpe')
                break

        return Service(
            port=port,
            protocol=protocol,
            service_name=service_name,
            version=version,
            cpe=cpe
        )

    def _port_to_service(self, port: int, protocol: str) -> str:
        """Get common service name from port"""
        common_services = {
            (20, 'tcp'): 'ftp-data',
            (21, 'tcp'): 'ftp',
            (22, 'tcp'): 'ssh',
            (23, 'tcp'): 'telnet',
            (25, 'tcp'): 'smtp',
            (53, 'tcp'): 'dns',
            (53, 'udp'): 'dns',
            (80, 'tcp'): 'http',
            (110, 'tcp'): 'pop3',
            (143, 'tcp'): 'imap',
            (443, 'tcp'): 'https',
            (465, 'tcp'): 'smtps',
            (993, 'tcp'): 'imaps',
            (995, 'tcp'): 'pop3s',
            (3306, 'tcp'): 'mysql',
            (3389, 'tcp'): 'rdp',
            (5432, 'tcp'): 'postgresql'
        }
        return common_services.get((port, protocol), 'unknown')

    async def detect_services(self, target: str, ports: List[int]) -> Dict[str, List[Service]]:
        """Main service detection method"""
        if not NetworkHelpers.validate_ip(target) and not NetworkHelpers.validate_hostname(target):
            logger.error(f"Invalid target: {target}")
            return {'error': 'Invalid target'}

        logger.info(f"Starting service detection on {target} for {len(ports)} ports")

        # Create detection tasks
        tasks = [self._probe_port(target, port) for port in ports]
        results = await asyncio.gather(*tasks)

        # Process results
        discovered = [s for s in results if s]
        logger.info(f"Discovered {len(discovered)} services on {target}")

        return {
            'target': target,
            'services': discovered,
            'stats': {
                'scanned_ports': len(ports),
                'open_ports': len(discovered),
                'tcp_services': sum(1 for s in discovered if s.protocol == 'tcp'),
                'udp_services': sum(1 for s in discovered if s.protocol == 'udp')
            }
        }

    def execute(self, target: ScanTarget) -> Dict[str, Any]:
        """Synchronous wrapper for async detection"""
        ports = target.ports or self._get_default_ports()
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(
                self.detect_services(target.host, ports)
            )
            loop.close()
            return result
        except Exception as e:
            loop.close()
            logger.error(f"Service detection failed: {str(e)}")
            return {'error': str(e)}

    def _get_default_ports(self) -> List[int]:
        """Get commonly targeted ports"""
        return [
            21, 22, 23, 25, 53, 80, 110, 143, 
            443, 445, 465, 993, 995, 3306, 3389, 
            5432, 5900, 8080, 8443
        ]

# Module registration
def init_module():
    return ServiceDetector()

# Example usage:
# detector = ServiceDetector()
# results = detector.execute(ScanTarget(host="example.com", ports=[80, 443, 22]))