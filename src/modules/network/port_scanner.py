"""
Advanced Port Scanner Module for APT Toolkit

Features:
- SYN and Connect scanning techniques
- Adaptive rate limiting
- Service fingerprinting integration
- Comprehensive result reporting
- CIDR range and hostlist support
"""

import socket
import asyncio
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from dataclasses import dataclass
import ipaddress
from concurrent.futures import ThreadPoolExecutor
import random
import time
from src.core.engine import ScanModule, ScanTarget
from src.utils.logger import get_logger
from src.utils.network import NetworkHelpers
from src.utils.config import config
from src.utils.threading_utils import scan_pool, net_pool
from src.core.event_system import event_system

logger = get_logger(__name__)

@dataclass
class PortScanResult:
    """Container for port scan results"""
    target: str
    port: int
    protocol: str
    status: str  # open|filtered|closed|error
    service: Optional[str] = None
    latency: Optional[float] = None
    banner: Optional[str] = None

class PortScanner(ScanModule):
    """High-performance network port scanner"""
    
    def __init__(self):
        super().__init__()
        self.module_name = "port_scanner"
        self._timeout = config.network.port_scan_timeout
        self._max_retries = config.network.port_scan_retries
        self._rate_limit = asyncio.Semaphore(config.network.max_scan_rate)
        self._scanned_ports = set()
        
        # Initialize raw socket for SYN scans (requires root)
        self._syn_socket = None
        if config.scan.privileged_mode:
            try:
                self._syn_socket = socket.socket(
                    socket.AF_INET, 
                    socket.SOCK_RAW, 
                    socket.IPPROTO_TCP
                )
                self._syn_socket.settimeout(self._timeout)
            except PermissionError:
                logger.warning("SYN scan requires root privileges. Falling back to CONNECT scan")
            except Exception as e:
                logger.error(f"Failed to initialize SYN socket: {str(e)}")

    def _resolve_targets(self, target_spec: Union[str, List[str]]) -> List[str]:
        """Resolve target specification into individual IPs"""
        targets = []
        
        if isinstance(target_spec, str):
            target_spec = [target_spec]
            
        for target in target_spec:
            try:
                # Handle CIDR ranges
                if '/' in target:
                    targets.extend(str(ip) for ip in ipaddress.IPv4Network(target, strict=False))
                # Handle hostlists
                elif '-' in target:
                    start, end = target.split('-')
                    start_ip = ipaddress.IPv4Address(start)
                    end_ip = ipaddress.IPv4Address(end)
                    targets.extend(str(ipaddress.IPv4Address(i)) 
                                 for i in range(int(start_ip), int(end_ip) + 1))
                # Handle single hosts
                else:
                    if NetworkHelpers.validate_ip(target):
                        targets.append(target)
                    else:
                        resolved = NetworkHelpers.resolve_hostname(target)
                        if resolved:
                            targets.append(resolved)
            except Exception as e:
                logger.warning(f"Failed to resolve target {target}: {str(e)}")
                
        return list(set(targets))  # Deduplicate

    def _generate_port_list(self, port_spec: Optional[Union[int, List[int], str]] = None) -> List[int]:
        """Generate list of ports to scan"""
        if port_spec is None:
            return list(range(1, 1025))  # Default well-known ports
            
        if isinstance(port_spec, int):
            return [port_spec]
            
        if isinstance(port_spec, list):
            return port_spec
            
        if isinstance(port_spec, str):
            # Handle port ranges (e.g., "20-25")
            if '-' in port_spec:
                start, end = map(int, port_spec.split('-'))
                return list(range(start, end + 1))
            # Handle comma-separated ports (e.g., "80,443,8080")
            elif ',' in port_spec:
                return [int(p) for p in port_spec.split(',')]
            # Handle service names (e.g., "http")
            else:
                try:
                    return [socket.getservbyname(port_spec)]
                except socket.error:
                    logger.warning(f"Unknown service name: {port_spec}")
                    
        return []

    async def _syn_scan(self, target: str, port: int) -> bool:
        """Perform TCP SYN scan (requires root)"""
        if not self._syn_socket:
            return False
            
        try:
            # Craft TCP SYN packet
            packet = self._craft_syn_packet(target, port)
            
            async with self._rate_limit:
                # Send packet and wait for response
                self._syn_socket.sendto(packet, (target, 0))
                start_time = time.time()
                
                while time.time() - start_time < self._timeout:
                    try:
                        data, _ = self._syn_socket.recvfrom(1024)
                        if self._is_syn_ack(data, port):
                            return True
                    except socket.timeout:
                        break
                        
        except Exception as e:
            logger.debug(f"SYN scan failed for {target}:{port}: {str(e)}")
            
        return False

    def _craft_syn_packet(self, target: str, port: int) -> bytes:
        """Craft raw TCP SYN packet"""
        src_port = random.randint(1025, 65535)
        seq_num = random.randint(0, 4294967295)
        
        # TCP header (without IP header for simplicity)
        tcp_header = (
            src_port.to_bytes(2, 'big') +         # Source Port
            port.to_bytes(2, 'big') +             # Destination Port
            seq_num.to_bytes(4, 'big') +          # Sequence Number
            (0).to_bytes(4, 'big') +              # Acknowledgement Number
            (0x5002).to_bytes(2, 'big') +         # Header Length + SYN Flag
            (0xffff).to_bytes(2, 'big') +         # Window Size
            (0).to_bytes(2, 'big') +              # Checksum (0 for now)
            (0).to_bytes(2, 'big')                # Urgent Pointer
        )
        
        # Calculate checksum (pseudo-header + TCP header)
        pseudo_header = (
            socket.inet_aton(target) +
            socket.inet_aton('0.0.0.0') +
            (socket.IPPROTO_TCP).to_bytes(1, 'big') +
            len(tcp_header).to_bytes(2, 'big')
        )
        
        checksum = NetworkHelpers.calculate_checksum(pseudo_header + tcp_header)
        tcp_header = tcp_header[:16] + checksum.to_bytes(2, 'big') + tcp_header[18:]
        
        return tcp_header

    def _is_syn_ack(self, packet: bytes, port: int) -> bool:
        """Check if packet is SYN-ACK response"""
        try:
            # Parse TCP header (assuming IPv4)
            tcp_header = packet[20:]  # Skip IP header
            dest_port = int.from_bytes(tcp_header[2:4], 'big')
            flags = int.from_bytes(tcp_header[13:14], 'big')
            return dest_port == port and (flags & 0x12) == 0x12  # SYN-ACK
        except:
            return False

    async def _connect_scan(self, target: str, port: int) -> Tuple[bool, float]:
        """Perform TCP connect scan"""
        try:
            async with self._rate_limit:
                start_time = time.time()
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port),
                    timeout=self._timeout
                )
                latency = time.time() - start_time
                writer.close()
                await writer.wait_closed()
                return (True, latency)
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
            return (False, None)
        except Exception as e:
            logger.debug(f"Connect scan failed for {target}:{port}: {str(e)}")
            return (False, None)

    async def _scan_port(self, target: str, port: int) -> PortScanResult:
        """Scan a single port with retries"""
        result = PortScanResult(
            target=target,
            port=port,
            protocol="tcp",
            status="closed"
        )
        
        for attempt in range(self._max_retries + 1):
            try:
                # Try SYN scan first if available
                if self._syn_socket:
                    is_open = await self._syn_scan(target, port)
                    if is_open:
                        result.status = "open"
                        break
                
                # Fall back to connect scan
                is_open, latency = await self._connect_scan(target, port)
                if is_open:
                    result.status = "open"
                    result.latency = latency
                    break
                    
            except Exception as e:
                logger.debug(f"Port scan attempt {attempt} failed for {target}:{port}: {str(e)}")
                if attempt == self._max_retries:
                    result.status = "error"
        
        return result

    async def scan_target(self, target: str, ports: List[int]) -> List[PortScanResult]:
        """Scan multiple ports on a single target"""
        if not NetworkHelpers.validate_ip(target):
            logger.error(f"Invalid target IP: {target}")
            return []
            
        # Randomize port order for stealth
        randomized_ports = random.sample(ports, len(ports))
        results = []
        
        logger.info(f"Scanning {len(ports)} ports on {target}")
        
        # Create scanning tasks
        tasks = [self._scan_port(target, port) for port in randomized_ports]
        
        # Process results as they complete
        for future in asyncio.as_completed(tasks):
            result = await future
            results.append(result)
            
            # Emit progress event
            event_system.emit(
                "port_scan_progress",
                target=target,
                scanned=len(results),
                total=len(ports),
                open_ports=sum(1 for r in results if r.status == "open")
            )
        
        return results

    async def scan_multiple_targets(self, targets: List[str], ports: List[int]) -> Dict[str, List[PortScanResult]]:
        """Scan multiple targets with the same port list"""
        results = {}
        
        # Create scanning tasks per target
        tasks = {
            asyncio.create_task(self.scan_target(target, ports)): target
            for target in targets
        }
        
        # Process results as they complete
        for future in asyncio.as_completed(tasks):
            target = tasks[future]
            try:
                results[target] = await future
            except Exception as e:
                logger.error(f"Target scan failed for {target}: {str(e)}")
                results[target] = []
        
        return results

    def execute(self, target: ScanTarget) -> Dict[str, Any]:
        """Main scanning interface"""
        try:
            # Resolve target specification
            targets = self._resolve_targets(target.host)
            if not targets:
                return {'error': 'No valid targets specified'}
                
            # Generate port list
            ports = self._generate_port_list(target.ports)
            if not ports:
                return {'error': 'No valid ports specified'}
                
            # Run async scan
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            try:
                start_time = time.time()
                results = loop.run_until_complete(
                    self.scan_multiple_targets(targets, ports)
                )
                duration = time.time() - start_time
                
                # Process results
                open_ports = {
                    host: [r for r in res if r.status == "open"]
                    for host, res in results.items()
                }
                
                return {
                    'target': target.host,
                    'results': results,
                    'stats': {
                        'scanned_hosts': len(targets),
                        'scanned_ports': len(ports),
                        'open_ports': sum(len(v) for v in open_ports.values()),
                        'duration': duration
                    }
                }
            finally:
                loop.close()
                
        except Exception as e:
            logger.error(f"Port scan failed: {str(e)}")
            return {'error': str(e)}

    def shutdown(self) -> None:
        """Cleanup resources"""
        if self._syn_socket:
            self._syn_socket.close()
        logger.info("Port scanner shutdown complete")

# Module registration
def init_module():
    return PortScanner()

# Example usage:
# scanner = PortScanner()
# target = ScanTarget(host="example.com", ports=[80, 443, 22, 3389])
# results = scanner.execute(target)