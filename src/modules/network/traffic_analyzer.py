"""
Traffic Analyzer Module for APT Toolkit

Features:
- Packet capture and analysis
- Protocol decoding (HTTP, DNS, etc.)
- Traffic statistics
- Anomaly detection
- Thread-safe operation
- Configurable capture duration
"""

import time
import threading
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from enum import Enum, auto
import dpkt  # For packet parsing
import socket

from src.core.engine import ScanModule, ScanTarget, ScanResult, ScanStatus
from src.utils.logger import get_logger
from src.utils.network import NetworkHelpers
from src.utils.config import config
from src.core.event_system import event_system, Event

logger = get_logger(__name__)

class ProtocolType(Enum):
    """Network protocol types"""
    HTTP = auto()
    HTTPS = auto()
    DNS = auto()
    TCP = auto()
    UDP = auto()
    ICMP = auto()
    OTHER = auto()

class TrafficStats:
    """Traffic statistics container"""
    
    def __init__(self):
        self.packet_count = 0
        self.byte_count = 0
        self.protocols = defaultdict(int)
        self.sources = defaultdict(int)
        self.destinations = defaultdict(int)
        self.anomalies = []

class TrafficAnalyzer(ScanModule):
    """Network traffic analysis module"""
    
    def __init__(self):
        super().__init__()
        self.module_name = "traffic_analyzer"
        self.capture_duration = config.network.traffic_capture_duration
        self.max_threads = config.network.traffic_threads
        self._stop_event = threading.Event()
        self._capture_thread = None
        
    def initialize(self) -> None:
        """Initialize analyzer resources"""
        logger.info(f"Initialized {self.module_name} with {self.max_threads} threads")
        
    def cleanup(self) -> None:
        """Cleanup analyzer resources"""
        self._stop_capture()
        logger.info(f"Cleaned up {self.module_name}")
        
    def validate_target(self, target: ScanTarget) -> bool:
        """Validate target is appropriate for traffic analysis"""
        if not target.host:
            return False
        return NetworkHelpers.validate_ip_or_domain(target.host)
        
    def _capture_traffic(self, interface: str, duration: float) -> List[Any]:
        """Capture network traffic on specified interface"""
        packets = []
        start_time = time.time()
        
        try:
            # Note: Actual packet capture would use pcap or similar
            # This is a simplified implementation
            while not self._stop_event.is_set() and (time.time() - start_time) < duration:
                # Simulate packet capture
                time.sleep(0.1)
                # In real implementation, would capture actual packets here
                
        except Exception as e:
            logger.error(f"Traffic capture failed: {str(e)}")
            
        return packets
        
    def _analyze_packet(self, packet: Any) -> Dict[str, Any]:
        """Analyze a single network packet"""
        result = {
            "protocol": ProtocolType.OTHER.name,
            "src_ip": "",
            "dst_ip": "",
            "src_port": 0,
            "dst_port": 0,
            "size": 0,
            "anomaly": False,
            "timestamp": time.time()
        }
        
        try:
            # Parse packet using dpkt
            eth = dpkt.ethernet.Ethernet(packet)
            if isinstance(eth.data, dpkt.ip.IP):
                ip = eth.data
                result["src_ip"] = socket.inet_ntoa(ip.src)
                result["dst_ip"] = socket.inet_ntoa(ip.dst)
                result["size"] = ip.len
                
                if isinstance(ip.data, dpkt.tcp.TCP):
                    result["protocol"] = ProtocolType.TCP.name
                    tcp = ip.data
                    result["src_port"] = tcp.sport
                    result["dst_port"] = tcp.dport
                    
                    # Check for HTTP
                    if tcp.dport == 80 or tcp.sport == 80:
                        try:
                            http = dpkt.http.Request(tcp.data)
                            result["protocol"] = ProtocolType.HTTP.name
                        except:
                            pass
                            
                elif isinstance(ip.data, dpkt.udp.UDP):
                    result["protocol"] = ProtocolType.UDP.name
                    udp = ip.data
                    result["src_port"] = udp.sport
                    result["dst_port"] = udp.dport
                    
                    # Check for DNS
                    if udp.dport == 53 or udp.sport == 53:
                        try:
                            dns = dpkt.dns.DNS(udp.data)
                            result["protocol"] = ProtocolType.DNS.name
                        except:
                            pass
                            
                # Add anomaly detection here
                result["anomaly"] = self._detect_anomaly(result)
                
        except Exception as e:
            logger.debug(f"Packet analysis error: {str(e)}")
            
        return result
        
    def _detect_anomaly(self, packet_info: Dict[str, Any]) -> bool:
        """Detect anomalies in packet"""
        # Example simple anomaly detection
        if packet_info["size"] > 1500:  # Jumbo frames
            return True
        if packet_info["dst_port"] in [22, 3389] and packet_info["protocol"] != ProtocolType.TCP.name:
            return True
        return False
        
    def _analyze_traffic(self, packets: List[Any]) -> TrafficStats:
        """Analyze captured traffic"""
        stats = TrafficStats()
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            futures = [executor.submit(self._analyze_packet, pkt) for pkt in packets]
            
            for future in as_completed(futures):
                try:
                    result = future.result()
                    stats.packet_count += 1
                    stats.byte_count += result["size"]
                    stats.protocols[result["protocol"]] += 1
                    stats.sources[result["src_ip"]] += 1
                    stats.destinations[result["dst_ip"]] += 1
                    
                    if result["anomaly"]:
                        stats.anomalies.append(result)
                        
                except Exception as e:
                    logger.error(f"Traffic analysis failed: {str(e)}")
                    
        return stats
        
    def _stop_capture(self) -> None:
        """Stop ongoing traffic capture"""
        self._stop_event.set()
        if self._capture_thread and self._capture_thread.is_alive():
            self._capture_thread.join(timeout=5.0)
            
    def execute(self, target: ScanTarget) -> ScanResult:
        """
        Execute traffic analysis against target
        
        Args:
            target: ScanTarget specifying host and interface
            
        Returns:
            ScanResult with traffic analysis results
        """
        if not self.validate_target(target):
            logger.error(f"Invalid scan target: {target.host}")
            return ScanResult(
                target=target,
                data={"error": "Invalid target"},
                status=ScanStatus.FAILED
            )
            
        interface = target.metadata.get("interface", "eth0")
        duration = target.metadata.get("duration", self.capture_duration)
        
        logger.info(
            f"Starting traffic analysis on {interface} for {duration} seconds "
            f"(target: {target.host})"
        )
        
        try:
            # Start capture
            self._stop_event.clear()
            self._capture_thread = threading.Thread(
                target=self._capture_traffic,
                args=(interface, duration),
                daemon=True
            )
            self._capture_thread.start()
            
            # Wait for capture to complete
            self._capture_thread.join()
            
            # Analyze captured traffic
            packets = []  # In real implementation, would use captured packets
            stats = self._analyze_traffic(packets)
            
            return ScanResult(
                target=target,
                data={
                    "stats": {
                        "packet_count": stats.packet_count,
                        "byte_count": stats.byte_count,
                        "protocols": dict(stats.protocols),
                        "top_sources": dict(sorted(stats.sources.items(), key=lambda x: x[1], reverse=True)[:5]),
                        "top_destinations": dict(sorted(stats.destinations.items(), key=lambda x: x[1], reverse=True)[:5]),
                        "anomaly_count": len(stats.anomalies)
                    },
                    "anomalies": stats.anomalies[:100]  # Limit number of returned anomalies
                },
                status=ScanStatus.COMPLETED
            )
            
        except Exception as e:
            logger.error(f"Traffic analysis failed on {target.host}: {str(e)}", exc_info=True)
            return ScanResult(
                target=target,
                data={"error": str(e)},
                status=ScanStatus.FAILED
            )

# Module registration
def init_module():
    return TrafficAnalyzer()

# Example usage:
# analyzer = TrafficAnalyzer()
# target = ScanTarget(host="example.com", metadata={"interface": "eth0", "duration": 60})
# result = analyzer.execute(target)
# print(json.dumps(result.data, indent=2))