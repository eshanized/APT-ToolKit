"""
Network Traffic Analyzer Module for APT Toolkit

Features:
- Packet capture and analysis
- Protocol decoding
- Anomaly detection
- Flow analysis
- Threat intelligence integration
"""

import json
import re
import socket
import asyncio
from typing import Dict, List, Optional, Tuple, Union, Any
from dataclasses import dataclass, field
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
import dpkt
from src.core.engine import ScanModule, ScanTarget
from src.utils.logger import get_logger
from src.utils.config import config
from src.utils.threading_utils import net_pool
from src.core.event_system import event_system

logger = get_logger(__name__)

@dataclass
class TrafficFlow:
    """Network flow statistics container"""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None

@dataclass
class ProtocolStats:
    """Protocol-level statistics"""
    protocol: str
    total_bytes: int = 0
    total_packets: int = 0
    flows: int = 0

@dataclass
class TrafficAlert:
    """Security alert container"""
    severity: str  # info|warning|critical
    category: str  # scanning|dos|exfiltration|etc.
    description: str
    evidence: Dict[str, Any]
    timestamp: float = field(default_factory=time.time)

class TrafficAnalyzer(ScanModule):
    """Network traffic analysis engine"""
    
    def __init__(self):
        super().__init__()
        self.module_name = "traffic_analyzer"
        self._active = False
        self._socket = None
        self._flows: Dict[Tuple, TrafficFlow] = {}
        self._protocol_stats: Dict[str, ProtocolStats] = {}
        self._alerts: List[TrafficAlert] = []
        self._packet_count = 0
        self._signatures = self._load_signatures()
        
        # Initialize protocol decoders
        self._decoders = {
            dpkt.ethernet.ETH_TYPE_IP: self._process_ip_packet,
            dpkt.ethernet.ETH_TYPE_ARP: self._process_arp_packet
        }

    def _load_signatures(self) -> Dict:
        """Load threat signatures from file"""
        try:
            sig_path = Path(config.data_dir) / "traffic_signatures.json"
            with open(sig_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load traffic signatures: {str(e)}")
            return {}

    async def start_capture(self, interface: str = "eth0", filter: str = "") -> bool:
        """Start live traffic capture"""
        if self._active:
            logger.warning("Capture already running")
            return False

        try:
            # Create raw socket
            self._socket = socket.socket(
                socket.AF_PACKET,
                socket.SOCK_RAW,
                socket.htons(0x0003)
            )
            self._socket.settimeout(1)
            self._socket.bind((interface, 0))
            
            self._active = True
            asyncio.create_task(self._capture_loop())
            logger.info(f"Started traffic capture on {interface}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to start capture: {str(e)}")
            self._socket = None
            return False

    async def _capture_loop(self) -> None:
        """Main packet capture loop"""
        while self._active:
            try:
                raw_packet = self._socket.recv(65535)
                if raw_packet:
                    await net_pool.submit(
                        self._process_packet,
                        raw_packet
                    )
            except socket.timeout:
                continue
            except Exception as e:
                logger.error(f"Packet capture error: {str(e)}")
                time.sleep(1)

    async def _process_packet(self, raw_packet: bytes) -> None:
        """Process individual network packet"""
        try:
            self._packet_count += 1
            
            # Decode Ethernet frame
            eth = dpkt.ethernet.Ethernet(raw_packet)
            
            # Process based on protocol
            decoder = self._decoders.get(eth.type)
            if decoder:
                decoder(eth)
                
            # Periodic analysis
            if self._packet_count % 1000 == 0:
                self._analyze_traffic()
                
        except Exception as e:
            logger.debug(f"Packet processing failed: {str(e)}")

    def _process_ip_packet(self, eth: dpkt.ethernet.Ethernet) -> None:
        """Process IP packet"""
        ip = eth.data
        protocol = ip.p
        
        # Update protocol stats
        proto_name = self._protocol_to_name(protocol)
        if proto_name not in self._protocol_stats:
            self._protocol_stats[proto_name] = ProtocolStats(proto_name)
        self._protocol_stats[proto_name].total_packets += 1
        self._protocol_stats[proto_name].total_bytes += len(ip)
        
        # Handle TCP/UDP
        if protocol in (dpkt.ip.IP_PROTO_TCP, dpkt.ip.IP_PROTO_UDP):
            transport = ip.data
            flow_key = (
                socket.inet_ntoa(ip.src),
                socket.inet_ntoa(ip.dst),
                transport.sport,
                transport.dport,
                "tcp" if protocol == dpkt.ip.IP_PROTO_TCP else "udp"
            )
            
            # Update flow stats
            if flow_key not in self._flows:
                self._flows[flow_key] = TrafficFlow(*flow_key)
                self._protocol_stats[proto_name].flows += 1
                
            flow = self._flows[flow_key]
            flow.packets_sent += 1
            flow.bytes_sent += len(transport.data)
            flow.end_time = time.time()
            
            # Check for threats
            self._detect_threats(flow, transport.data)
            
    def _process_arp_packet(self, eth: dpkt.ethernet.Ethernet) -> None:
        """Process ARP packet"""
        arp = eth.data
        self._protocol_stats["arp"].total_packets += 1
        
        # Detect ARP spoofing
        if arp.op == dpkt.arp.ARP_OP_REPLY:
            self._check_arp_spoofing(arp)

    def _protocol_to_name(self, protocol: int) -> str:
        """Convert protocol number to name"""
        protocols = {
            dpkt.ip.IP_PROTO_TCP: "tcp",
            dpkt.ip.IP_PROTO_UDP: "udp",
            dpkt.ip.IP_PROTO_ICMP: "icmp",
            dpkt.arp.ARP_OP_REQUEST: "arp_request",
            dpkt.arp.ARP_OP_REPLY: "arp_reply"
        }
        return protocols.get(protocol, f"proto_{protocol}")

    def _detect_threats(self, flow: TrafficFlow, payload: bytes) -> None:
        """Analyze traffic for malicious patterns"""
        # Port scanning detection
        if flow.packets_sent > 100 and flow.dst_port > flow.src_port:
            self._create_alert(
                "warning",
                "scanning",
                f"Possible port scanning from {flow.src_ip}",
                {
                    "src_ip": flow.src_ip,
                    "port_range": f"{flow.src_port}-{flow.dst_port}",
                    "packets": flow.packets_sent
                }
            )
        
        # Data exfiltration detection
        if len(payload) > 1024 and flow.protocol == "tcp":
            self._create_alert(
                "critical",
                "exfiltration",
                f"Large data transfer from {flow.src_ip}",
                {
                    "src_ip": flow.src_ip,
                    "bytes": len(payload),
                    "protocol": flow.protocol
                }
            )
        
        # Signature-based detection
        for sig in self._signatures.get("network", []):
            if re.search(sig["pattern"], str(payload), re.IGNORECASE):
                self._create_alert(
                    sig["severity"],
                    sig["category"],
                    sig["description"],
                    {
                        "src_ip": flow.src_ip,
                        "dst_ip": flow.dst_ip,
                        "signature": sig["name"]
                    }
                )

    def _check_arp_spoofing(self, arp: dpkt.arp.ARP) -> None:
        """Detect ARP spoofing attempts"""
        # Implement ARP cache verification logic
        # This is a placeholder for actual ARP spoofing detection
        pass

    def _create_alert(self, severity: str, category: str, description: str, evidence: Dict) -> None:
        """Record a security alert"""
        alert = TrafficAlert(severity, category, description, evidence)
        self._alerts.append(alert)
        event_system.emit(
            "traffic_alert",
            severity=severity,
            category=category,
            description=description,
            evidence=evidence
        )
        logger.warning(f"Traffic alert: {description}")

    def _analyze_traffic(self) -> None:
        """Periodic traffic analysis"""
        # Detect DDoS patterns
        total_pps = sum(ps.total_packets for ps in self._protocol_stats.values())
        if total_pps > 10000:  # 10k packets/sec threshold
            self._create_alert(
                "critical",
                "dos",
                "Possible DDoS attack detected",
                {
                    "packets_per_second": total_pps,
                    "top_protocols": sorted(
                        self._protocol_stats.items(),
                        key=lambda x: x[1].total_packets,
                        reverse=True
                    )[:3]
                }
            )
        
        # Detect unusual protocols
        for proto, stats in self._protocol_stats.items():
            if proto not in ["tcp", "udp", "icmp", "arp"] and stats.total_packets > 100:
                self._create_alert(
                    "warning",
                    "unusual_protocol",
                    f"Unusual protocol activity: {proto}",
                    {
                        "protocol": proto,
                        "packets": stats.total_packets,
                        "bytes": stats.total_bytes
                    }
                )

    async def stop_capture(self) -> Dict[str, Any]:
        """Stop traffic capture and return results"""
        self._active = False
        if self._socket:
            self._socket.close()
            self._socket = None
            
        # Final analysis
        self._analyze_traffic()
        
        return {
            "duration": time.time() - min(
                (f.start_time for f in self._flows.values()),
                default=time.time()
            ),
            "total_packets": self._packet_count,
            "flows": len(self._flows),
            "protocols": self._protocol_stats,
            "alerts": self._alerts
        }

    def execute(self, target: ScanTarget) -> Dict[str, Any]:
        """Execute traffic analysis (interface for scan engine)"""
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # Start capture with default interface
            loop.run_until_complete(self.start_capture())
            
            # Run for configured duration
            time.sleep(config.traffic.capture_duration)
            
            # Stop and get results
            results = loop.run_until_complete(self.stop_capture())
            loop.close()
            
            return {
                "target": target.host,
                "results": results
            }
        except Exception as e:
            logger.error(f"Traffic analysis failed: {str(e)}")
            return {"error": str(e)}

    def shutdown(self) -> None:
        """Cleanup resources"""
        if self._active:
            asyncio.run(self.stop_capture())
        logger.info("Traffic analyzer shutdown complete")

# Module registration
def init_module():
    return TrafficAnalyzer()

# Example usage:
# analyzer = TrafficAnalyzer()
# results = analyzer.execute(ScanTarget(host="eth0"))
# analyzer.shutdown()