"""
Scan Manager - Core Orchestration Engine for APT Toolkit

Features:
- Stateful scan job management
- Thread-safe operation queue
- Progress tracking and reporting
- Graceful error recovery
- Resource optimization
"""

import heapq
import threading
import time
import uuid
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from pathlib import Path

from src.utils.config import config
from src.utils.logger import get_logger
from src.utils.helpers import ErrorHelpers, DataHelpers
from src.core.event_system import event_system, Event, EventPriority
from src.core.engine import ScanEngine, ScanStatus, ScanTarget
from src.core.result_processor import result_processor

logger = get_logger(__name__)

class ScanPhase(Enum):
    """Lifecycle phases for scan jobs"""
    INITIALIZATION = auto()
    RECONNAISSANCE = auto()
    DISCOVERY = auto()
    VULNERABILITY_ASSESSMENT = auto()
    EXPLOITATION = auto()
    POST_EXPLOITATION = auto()
    REPORTING = auto()
    COMPLETED = auto()
    FAILED = auto()

@dataclass(order=True)
class ScanProfile:
    """Scan configuration template"""
    name: str
    description: str
    modules: List[str] = field(default_factory=list)
    intensity: str = "normal"  # light|normal|aggressive
    timeout: int = 3600  # seconds
    credentials: Dict[str, str] = field(default_factory=dict)
    target_filters: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ScanJob:
    """Active scan job container"""
    id: str
    profile: ScanProfile
    targets: List[ScanTarget]
    status: ScanStatus = ScanStatus.PENDING
    phase: ScanPhase = ScanPhase.INITIALIZATION
    progress: float = 0.0
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    _cancel_event: threading.Event = field(default_factory=threading.Event, init=False)

class ScanManager:
    """Centralized scan orchestration controller"""
    
    def __init__(self):
        self._engine = ScanEngine()
        self._jobs: Dict[str, ScanJob] = {}
        self._job_queue: List[Tuple[int, str]] = []
        self._lock = threading.RLock()
        self._executor = ThreadPoolExecutor(
            max_workers=config.core.max_concurrent_scans,
            thread_name_prefix="apt_scan_manager_"
        )
        
        # Initialize event handlers
        event_system.register("scan_start", self._on_scan_start, priority=EventPriority.HIGH)
        event_system.register("scan_progress", self._on_scan_progress)
        event_system.register("scan_complete", self._on_scan_complete)
        
        # Start queue processor thread
        self._processor_thread = threading.Thread(
            target=self._process_job_queue,
            name="ScanQueueProcessor",
            daemon=True
        )
        self._processor_thread.start()

    def create_scan(self, profile: ScanProfile, targets: List[Union[str, ScanTarget]]) -> str:
        """
        Create and enqueue a new scan job
        
        Args:
            profile: Scan configuration profile
            targets: List of target hosts or ScanTarget objects
            
        Returns:
            str: Generated job ID
        """
        # Normalize targets
        normalized_targets = []
        for target in targets:
            if isinstance(target, str):
                normalized_targets.append(ScanTarget(host=target))
            else:
                normalized_targets.append(target)
                
        # Create job
        job_id = f"scan_{uuid.uuid4().hex[:8]}"
        job = ScanJob(
            id=job_id,
            profile=profile,
            targets=normalized_targets
        )
        
        # Add to priority queue (lower priority value = higher priority)
        with self._lock:
            self._jobs[job_id] = job
            heapq.heappush(self._job_queue, (profile.timeout, job_id))
            
        logger.info(
            f"Created scan job {job_id} with {len(targets)} targets "
            f"(profile: {profile.name}, timeout: {profile.timeout}s)"
        )
        return job_id

    def _process_job_queue(self) -> None:
        """Background job processing loop"""
        while True:
            try:
                _, job_id = self._get_next_job()
                
                with self._lock:
                    job = self._jobs.get(job_id)
                    if not job:
                        continue
                        
                    job.status = ScanStatus.RUNNING
                    job.started_at = time.time()
                    
                # Execute in thread pool
                self._executor.submit(
                    self._execute_scan_job,
                    job
                ).add_done_callback(
                    lambda f, jid=job_id: self._finalize_job(jid, f)
                )
                
            except Exception as e:
                logger.error(f"Job queue processing error: {str(e)}", exc_info=True)
                time.sleep(1)

    def _get_next_job(self) -> Tuple[int, str]:
        """Thread-safe job queue access with priority handling"""
        with self._lock:
            while not self._job_queue:
                time.sleep(0.5)
            return heapq.heappop(self._job_queue)

    def _execute_scan_job(self, job: ScanJob) -> None:
        """Execute a scan job through all phases"""
        try:
            event_system.emit(
                "scan_start",
                job_id=job.id,
                profile=job.profile.name,
                target_count=len(job.targets)
            )
            
            # Phase 1: Reconnaissance
            if not job._cancel_event.is_set():
                self._run_scan_phase(
                    job,
                    ScanPhase.RECONNAISSANCE,
                    [m for m in job.profile.modules if m.startswith("recon_")]
                )
                
            # Phase 2: Service Discovery
            if not job._cancel_event.is_set():
                self._run_scan_phase(
                    job,
                    ScanPhase.DISCOVERY,
                    [m for m in job.profile.modules if m.startswith("discovery_")]
                )
                
            # Phase 3: Vulnerability Assessment
            if not job._cancel_event.is_set():
                self._run_scan_phase(
                    job,
                    ScanPhase.VULNERABILITY_ASSESSMENT,
                    [m for m in job.profile.modules if m.startswith("vuln_")]
                )
                
            # Phase 4: Controlled Exploitation
            if not job._cancel_event.is_set() and job.profile.intensity == "aggressive":
                self._run_scan_phase(
                    job,
                    ScanPhase.EXPLOITATION,
                    [m for m in job.profile.modules if m.startswith("exploit_")]
                )
                
            # Finalize
            job.phase = ScanPhase.COMPLETED
            job.progress = 100.0
            job.completed_at = time.time()
            
            event_system.emit(
                "scan_complete",
                job_id=job.id,
                duration=job.completed_at - job.started_at
            )
            
        except Exception as e:
            logger.error(f"Scan job {job.id} failed: {str(e)}", exc_info=True)
            job.phase = ScanPhase.FAILED
            job.completed_at = time.time()
            event_system.emit(
                "scan_failed",
                job_id=job.id,
                error=str(e),
                phase=job.phase.name
            )

    def _run_scan_phase(
        self,
        job: ScanJob,
        phase: ScanPhase,
        modules: List[str]
    ) -> None:
        """Execute a single scan phase with multiple modules"""
        if not modules or job._cancel_event.is_set():
            return
            
        job.phase = phase
        logger.info(f"Starting {phase.name} for job {job.id}")
        
        # Calculate phase weight (progress contribution)
        phase_weights = {
            ScanPhase.RECONNAISSANCE: 0.2,
            ScanPhase.DISCOVERY: 0.3,
            ScanPhase.VULNERABILITY_ASSESSMENT: 0.4,
            ScanPhase.EXPLOITATION: 0.1
        }
        
        for i, module in enumerate(modules):
            if job._cancel_event.is_set():
                break
                
            try:
                # Execute module scan
                results = self._engine.execute_scan(
                    targets=job.targets,
                    module_names=[module]
                )
                
                # Process results
                for module_name, scan_results in results.items():
                    for result in scan_results:
                        event_system.emit(
                            "scan_result",
                            raw_result={
                                'job_id': job.id,
                                'target': result.target.host,
                                'module': module_name,
                                'data': result.data,
                                'vulnerabilities': [
                                    {
                                        'id': vuln.id,
                                        'name': vuln.name,
                                        'severity': vuln.severity.name,
                                        'evidence': vuln.evidence
                                    }
                                    for vuln in result.vulnerabilities
                                ]
                            }
                        )
                
                # Update progress
                job.progress += phase_weights.get(phase, 0) / len(modules)
                event_system.emit(
                    "scan_progress",
                    job_id=job.id,
                    progress=job.progress,
                    phase=phase.name
                )
                
            except Exception as e:
                logger.error(f"Module {module} failed in job {job.id}: {str(e)}")
                if phase == ScanPhase.RECONNAISSANCE:
                    raise  # Critical phase failure

    def _finalize_job(self, job_id: str, future: Future) -> None:
        """Cleanup completed job resources"""
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
                
            if future.exception():
                job.status = ScanStatus.FAILED
                job.phase = ScanPhase.FAILED
            else:
                job.status = ScanStatus.COMPLETED
                
            job.completed_at = time.time()
            logger.info(
                f"Job {job_id} completed with status {job.status.name} "
                f"in {job.completed_at - job.started_at:.2f}s"
            )

    def get_job_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve current job status"""
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return None
                
            return {
                'id': job.id,
                'profile': job.profile.name,
                'status': job.status.name,
                'phase': job.phase.name,
                'progress': job.progress,
                'targets': [t.host for t in job.targets],
                'created_at': job.created_at,
                'started_at': job.started_at,
                'completed_at': job.completed_at,
                'duration': (job.completed_at or time.time()) - (job.started_at or time.time())
            }

    def list_jobs(self, filter_status: Optional[ScanStatus] = None) -> List[Dict[str, Any]]:
        """List all jobs with optional status filter"""
        with self._lock:
            return [
                self.get_job_status(job_id)
                for job_id in self._jobs
                if not filter_status or self._jobs[job_id].status == filter_status
            ]

    def cancel_job(self, job_id: str) -> bool:
        """Cancel a running scan job"""
        with self._lock:
            job = self._jobs.get(job_id)
            if not job or job.status not in (ScanStatus.PENDING, ScanStatus.RUNNING):
                return False
                
            job._cancel_event.set()
            job.status = ScanStatus.CANCELLED
            job.completed_at = time.time()
            
            # Notify engine to stop active scans
            self._engine.stop()
            
            logger.info(f"Cancelled job {job_id}")
            return True

    def shutdown(self) -> None:
        """Graceful shutdown of all scan operations"""
        with self._lock:
            # Cancel all active jobs
            for job_id in list(self._jobs.keys()):
                self.cancel_job(job_id)
                
            # Shutdown executors
            self._executor.shutdown(wait=False)
            self._engine.shutdown()
            
        logger.info("Scan manager shutdown complete")

    # Event handlers
    def _on_scan_start(self, event: Event, job_id: str, **kwargs) -> None:
        logger.info(f"Scan job {job_id} started")

    def _on_scan_progress(self, event: Event, job_id: str, progress: float, **kwargs) -> None:
        logger.debug(f"Job {job_id} progress: {progress:.1f}%")

    def _on_scan_complete(self, event: Event, job_id: str, **kwargs) -> None:
        logger.info(f"Scan job {job_id} completed successfully")

# Global scan manager instance
scan_manager = ScanManager()