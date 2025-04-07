"""
Result Processor for APT Toolkit

Features:
- Normalized result handling
- Vulnerability correlation
- Risk scoring
- Report generation hooks
- Data persistence
"""

import json
import logging
from typing import Any, Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
import threading
from concurrent.futures import ThreadPoolExecutor
import hashlib
from datetime import datetime
from src.utils.config import config
from src.utils.logger import get_logger
from src.utils.file_utils import FileUtils
from src.core.event_system import event_system, Event, EventPriority
from src.utils.helpers import DataHelpers, ErrorHelpers

logger = get_logger(__name__)

class Severity(Enum):
    """Vulnerability severity levels"""
    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFO = auto()

@dataclass
class Vulnerability:
    """Standardized vulnerability representation"""
    id: str
    name: str
    description: str
    severity: Severity
    cvss_score: Optional[float] = None
    cve: Optional[str] = None
    references: List[str] = field(default_factory=list)
    evidence: Optional[Dict[str, Any]] = None
    timestamp: float = field(default_factory=lambda: datetime.now().timestamp())

@dataclass
class ScanResult:
    """Processed scan result container"""
    target: str
    module: str
    vulnerabilities: List[Vulnerability]
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=lambda: datetime.now().timestamp())

class ResultProcessor:
    """Centralized result processing engine"""
    
    def __init__(self):
        self._lock = threading.RLock()
        self._executor = ThreadPoolExecutor(
            max_workers=config.core.result_threads,
            thread_name_prefix="apt_result_"
        )
        self._results: Dict[str, ScanResult] = {}
        self._vulnerabilities: Dict[str, Vulnerability] = {}
        self._correlation_cache: Dict[str, List[str]] = {}
        
        # Setup results directory
        self._results_dir = Path(config.core.results_dir)
        self._results_dir.mkdir(parents=True, exist_ok=True)
        
        # Register event handlers
        event_system.register("scan_result", self._handle_raw_result, priority=EventPriority.HIGH)
        event_system.register("generate_report", self._generate_reports)
        
    def _handle_raw_result(self, event: Event, raw_result: Dict[str, Any]) -> None:
        """Process incoming raw scan results"""
        try:
            self._executor.submit(
                self._process_result,
                raw_result
            ).add_done_callback(
                lambda f: logger.debug("Result processing completed") if not f.exception() else None
            )
        except Exception as e:
            logger.error(f"Failed to submit result for processing: {str(e)}")

    @ErrorHelpers.retry(max_attempts=3, delay=1.0)
    def _process_result(self, raw_result: Dict[str, Any]) -> None:
        """Normalize and process a scan result"""
        try:
            # Validate basic result structure
            if not all(k in raw_result for k in ['target', 'module', 'data']):
                raise ValueError("Invalid result format - missing required fields")
                
            target = raw_result['target']
            module = raw_result['module']
            result_id = f"{target}_{module}_{hashlib.md5(json.dumps(raw_result).encode()).hexdigest()}"
            
            # Normalize vulnerabilities
            vulnerabilities = []
            for vuln in raw_result.get('vulnerabilities', []):
                try:
                    normalized = self._normalize_vulnerability(vuln)
                    vulnerabilities.append(normalized)
                    
                    # Store vulnerability in global registry
                    with self._lock:
                        self._vulnerabilities[normalized.id] = normalized
                        
                except Exception as e:
                    logger.warning(f"Failed to normalize vulnerability: {str(e)}")
                    continue
                    
            # Create scan result
            scan_result = ScanResult(
                target=target,
                module=module,
                vulnerabilities=vulnerabilities,
                metadata=raw_result.get('metadata', {})
            )
            
            # Store result
            with self._lock:
                self._results[result_id] = scan_result
                
            # Correlate vulnerabilities
            self._correlate_vulnerabilities(scan_result)
            
            # Persist to disk
            self._persist_result(result_id, scan_result)
            
            logger.info(f"Processed result from {module} for {target} ({len(vulnerabilities)} vulns)")
            
        except Exception as e:
            logger.error(f"Result processing failed: {str(e)}", exc_info=True)
            raise

    def _normalize_vulnerability(self, vuln: Dict[str, Any]) -> Vulnerability:
        """Convert raw vulnerability to standardized format"""
        # Validate required fields
        if not all(k in vuln for k in ['id', 'name', 'severity']):
            raise ValueError("Vulnerability missing required fields")
            
        # Convert severity
        try:
            severity = Severity[vuln['severity'].upper()]
        except KeyError:
            severity = Severity.INFO
            
        # Create normalized vulnerability
        return Vulnerability(
            id=vuln['id'],
            name=vuln['name'],
            description=vuln.get('description', ''),
            severity=severity,
            cvss_score=float(vuln['cvss']) if 'cvss' in vuln else None,
            cve=vuln.get('cve'),
            references=vuln.get('references', []),
            evidence=vuln.get('evidence')
        )

    def _correlate_vulnerabilities(self, result: ScanResult) -> None:
        """Find relationships between vulnerabilities"""
        with self._lock:
            for vuln in result.vulnerabilities:
                # Simple correlation by CVE
                if vuln.cve:
                    if vuln.cve not in self._correlation_cache:
                        self._correlation_cache[vuln.cve] = []
                    self._correlation_cache[vuln.cve].append(vuln.id)
                    
                # More advanced correlation could be added here
                # (e.g., by service, port, vulnerability type, etc.)

    def _persist_result(self, result_id: str, result: ScanResult) -> None:
        """Save result to persistent storage"""
        try:
            filename = f"result_{result_id}.json"
            filepath = self._results_dir / filename
            
            # Convert to serializable format
            result_dict = {
                'target': result.target,
                'module': result.module,
                'timestamp': result.timestamp,
                'vulnerabilities': [
                    {
                        'id': v.id,
                        'name': v.name,
                        'description': v.description,
                        'severity': v.severity.name,
                        'cvss_score': v.cvss_score,
                        'cve': v.cve,
                        'references': v.references,
                        'evidence': v.evidence
                    }
                    for v in result.vulnerabilities
                ],
                'metadata': result.metadata
            }
            
            # Atomic write
            FileUtils.atomic_write(
                filepath,
                json.dumps(result_dict, indent=2),
                chmod=0o600
            )
            
        except Exception as e:
            logger.error(f"Failed to persist result {result_id}: {str(e)}")

    def get_results(self, filter_args: Optional[Dict[str, Any]] = None) -> List[ScanResult]:
        """
        Retrieve processed scan results with optional filtering
        
        Args:
            filter_args: Dictionary of filter criteria:
                - target: str
                - module: str
                - min_severity: Severity
                - cve: str
                - time_range: (start, end) timestamps
                
        Returns:
            List of matching ScanResult objects
        """
        filter_args = filter_args or {}
        results = []
        
        with self._lock:
            for result in self._results.values():
                # Apply filters
                if 'target' in filter_args and result.target != filter_args['target']:
                    continue
                    
                if 'module' in filter_args and result.module != filter_args['module']:
                    continue
                    
                if 'min_severity' in filter_args:
                    result_vulns = [
                        v for v in result.vulnerabilities
                        if v.severity.value <= filter_args['min_severity'].value
                    ]
                    if not result_vulns:
                        continue
                        
                if 'cve' in filter_args:
                    has_cve = any(
                        v.cve == filter_args['cve']
                        for v in result.vulnerabilities
                    )
                    if not has_cve:
                        continue
                        
                if 'time_range' in filter_args:
                    start, end = filter_args['time_range']
                    if not (start <= result.timestamp <= end):
                        continue
                        
                results.append(result)
                
        return results

    def get_vulnerability(self, vuln_id: str) -> Optional[Vulnerability]:
        """Get vulnerability by ID"""
        with self._lock:
            return self._vulnerabilities.get(vuln_id)

    def get_correlated_vulnerabilities(self, vuln_id: str) -> List[Vulnerability]:
        """Get vulnerabilities correlated to the specified vulnerability"""
        correlations = []
        with self._lock:
            # Find all correlation keys that include this vulnerability
            for key, vuln_ids in self._correlation_cache.items():
                if vuln_id in vuln_ids:
                    for related_id in vuln_ids:
                        if related_id != vuln_id and related_id in self._vulnerabilities:
                            correlations.append(self._vulnerabilities[related_id])
                            
        return correlations

    def _generate_reports(self, event: Event, report_type: str = "summary") -> Dict[str, Any]:
        """Generate reports based on collected results"""
        try:
            with self._lock:
                all_results = list(self._results.values())
                
            if report_type == "summary":
                return self._generate_summary_report(all_results)
            elif report_type == "detailed":
                return self._generate_detailed_report(all_results)
            else:
                raise ValueError(f"Unknown report type: {report_type}")
                
        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}", exc_info=True)
            raise

    def _generate_summary_report(self, results: List[ScanResult]) -> Dict[str, Any]:
        """Generate summary statistics report"""
        stats = {
            'total_targets': len({r.target for r in results}),
            'total_vulnerabilities': 0,
            'by_severity': {s.name: 0 for s in Severity},
            'by_module': {},
            'critical_vulnerabilities': []
        }
        
        for result in results:
            # Update module stats
            if result.module not in stats['by_module']:
                stats['by_module'][result.module] = 0
            stats['by_module'][result.module] += len(result.vulnerabilities)
            
            # Update severity stats
            for vuln in result.vulnerabilities:
                stats['by_severity'][vuln.severity.name] += 1
                stats['total_vulnerabilities'] += 1
                
                # Track critical vulnerabilities
                if vuln.severity == Severity.CRITICAL:
                    stats['critical_vulnerabilities'].append({
                        'id': vuln.id,
                        'name': vuln.name,
                        'target': result.target,
                        'module': result.module,
                        'cve': vuln.cve
                    })
                    
        return stats

    def _generate_detailed_report(self, results: List[ScanResult]) -> Dict[str, Any]:
        """Generate detailed vulnerability report"""
        report = {
            'generated_at': datetime.now().timestamp(),
            'results': []
        }
        
        for result in results:
            result_entry = {
                'target': result.target,
                'module': result.module,
                'timestamp': result.timestamp,
                'vulnerabilities': []
            }
            
            for vuln in result.vulnerabilities:
                result_entry['vulnerabilities'].append({
                    'id': vuln.id,
                    'name': vuln.name,
                    'severity': vuln.severity.name,
                    'cvss_score': vuln.cvss_score,
                    'cve': vuln.cve,
                    'description': vuln.description
                })
                
            report['results'].append(result_entry)
            
        return report

    def shutdown(self) -> None:
        """Cleanup processor resources"""
        self._executor.shutdown(wait=True)
        logger.info("Result processor shutdown complete")

# Global result processor instance
result_processor = ResultProcessor()

# Example usage:
# result = {
#     'target': 'example.com',
#     'module': 'web_scanner',
#     'data': {...},
#     'vulnerabilities': [
#         {
#             'id': 'xss_123',
#             'name': 'Cross-Site Scripting',
#             'severity': 'HIGH',
#             'description': 'Found XSS vulnerability in /contact form',
#             'cve': 'CVE-2023-1234'
#         }
#     ]
# }
# event_system.emit('scan_result', raw_result=result)
# 
# # Get results later
# critical_vulns = result_processor.get_results({
#     'min_severity': Severity.HIGH
# })