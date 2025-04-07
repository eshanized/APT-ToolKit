"""
Core Scanning Engine for APT Toolkit

Features:
- Modular scan pipeline architecture
- Thread-safe operation management
- Progress tracking and reporting
- Resource management
- Plugin integration
"""

import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from concurrent.futures import ThreadPoolExecutor, Future, as_completed
from queue import PriorityQueue
from enum import Enum, auto
from dataclasses import dataclass
import signal
from src.utils.logger import get_logger
from src.utils.config import config
from src.core.event_system import EventPriority, event_system, Event
from src.utils.helpers import DataHelpers, ErrorHelpers

logger = get_logger(__name__)

class ScanStatus(Enum):
    """Scan lifecycle states"""
    PENDING = auto()
    RUNNING = auto()
    PAUSED = auto()
    COMPLETED = auto()
    FAILED = auto()
    CANCELLED = auto()

@dataclass
class ScanTarget:
    """Target specification for scans"""
    host: str
    ports: Optional[List[int]] = None
    protocol: str = "tcp"

@dataclass
class ScanResult:
    """Base scan result container"""
    target: ScanTarget
    data: Dict[str, Any]
    status: ScanStatus
    timestamp: float = time.time()

class ScanModule:
    """Base class for all scan modules"""
    
    def __init__(self):
        self.module_name = self.__class__.__name__
        self._interrupt = threading.Event()
        
    def initialize(self) -> None:
        """Initialize module resources"""
        pass
        
    def cleanup(self) -> None:
        """Cleanup module resources"""
        pass
        
    def validate_target(self, target: ScanTarget) -> bool:
        """Validate target is appropriate for this module"""
        return True
        
    def execute(self, target: ScanTarget) -> ScanResult:
        """Execute scan against target"""
        raise NotImplementedError
        
    def interrupt(self) -> None:
        """Request scan interruption"""
        self._interrupt.set()

class ScanEngine:
    """Core scanning engine with thread pool management"""
    
    def __init__(self):
        self.status = ScanStatus.PENDING
        self._executor = ThreadPoolExecutor(
            max_workers=config.core.max_threads,
            thread_name_prefix="apt_scan_worker"
        )
        self._lock = threading.RLock()
        self._interrupt = threading.Event()
        self._current_tasks: Dict[str, Future] = {}
        self._modules: Dict[str, ScanModule] = {}
        self._progress = {
            'total': 0,
            'completed': 0,
            'failed': 0
        }
        
        # Register signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, self._handle_signal)
        signal.signal(signal.SIGTERM, self._handle_signal)
        
    def _handle_signal(self, signum, frame) -> None:
        """Handle system signals for graceful shutdown"""
        logger.info(f"Received signal {signum}, initiating shutdown...")
        self.stop()

    def register_module(self, module: ScanModule) -> bool:
        """Register a scan module with the engine"""
        with self._lock:
            if module.module_name in self._modules:
                logger.warning(f"Module {module.module_name} already registered")
                return False
                
            module.initialize()
            self._modules[module.module_name] = module
            logger.info(f"Registered module: {module.module_name}")
            return True

    def unregister_module(self, module_name: str) -> bool:
        """Unregister a scan module"""
        with self._lock:
            module = self._modules.pop(module_name, None)
            if module:
                module.cleanup()
                logger.info(f"Unregistered module: {module_name}")
                return True
            return False

    @ErrorHelpers.retry(max_attempts=3, delay=1.0)
    def execute_scan(
        self,
        targets: List[ScanTarget],
        module_names: Optional[List[str]] = None
    ) -> Dict[str, List[ScanResult]]:
        """
        Execute scan against multiple targets
        
        Args:
            targets: List of scan targets
            module_names: Optional list of modules to use (all if None)
            
        Returns:
            Dictionary of {module_name: [ScanResult]}
        """
        with self._lock:
            if self.status == ScanStatus.RUNNING:
                raise RuntimeError("Scan already in progress")
                
            self.status = ScanStatus.RUNNING
            self._interrupt.clear()
            self._progress = {
                'total': len(targets) * len(module_names if module_names else self._modules),
                'completed': 0,
                'failed': 0
            }
            
        # Determine which modules to use
        modules_to_run = [
            m for name, m in self._modules.items()
            if not module_names or name in module_names
        ]
        
        if not modules_to_run:
            raise ValueError("No valid scan modules selected")
            
        # Prepare results structure
        results = {m.module_name: [] for m in modules_to_run}
        futures = []
        
        try:
            # Submit all scan tasks
            for target in targets:
                if self._interrupt.is_set():
                    break
                    
                for module in modules_to_run:
                    if not module.validate_target(target):
                        continue
                        
                    future = self._executor.submit(
                        self._execute_module_scan,
                        module,
                        target
                    )
                    future.add_done_callback(self._handle_scan_completion)
                    futures.append(future)
                    with self._lock:
                        self._current_tasks[f"{module.module_name}_{target.host}"] = future
            
            # Wait for completion
            for future in as_completed(futures):
                if self._interrupt.is_set():
                    break
                    
                try:
                    module_name, result = future.result()
                    results[module_name].append(result)
                except Exception as e:
                    logger.error(f"Scan task failed: {str(e)}", exc_info=True)
                    with self._lock:
                        self._progress['failed'] += 1
            
            # Update final status
            with self._lock:
                if self._interrupt.is_set():
                    self.status = ScanStatus.CANCELLED
                    logger.warning("Scan interrupted by user")
                else:
                    self.status = ScanStatus.COMPLETED
                    logger.info("Scan completed successfully")
            
            return results
            
        finally:
            # Cleanup any remaining tasks
            with self._lock:
                for future in futures:
                    if not future.done():
                        future.cancel()
                self._current_tasks.clear()

    def _execute_module_scan(
        self,
        module: ScanModule,
        target: ScanTarget
    ) -> Tuple[str, ScanResult]:
        """Execute a single module scan and handle results"""
        try:
            if self._interrupt.is_set() or module._interrupt.is_set():
                return (module.module_name, ScanResult(
                    target=target,
                    data={},
                    status=ScanStatus.CANCELLED
                ))
                
            # Emit pre-scan event
            pre_event = Event("pre_scan")
            event_system.emit(
                "pre_scan",
                event=pre_event,
                module=module.module_name,
                target=target
            ).result()
            
            if pre_event.cancelled:
                return (module.module_name, ScanResult(
                    target=target,
                    data={'reason': 'cancelled_by_handler'},
                    status=ScanStatus.CANCELLED
                ))
                
            # Execute scan
            result = module.execute(target)
            
            # Emit post-scan event
            post_event = Event("post_scan")
            event_system.emit(
                "post_scan",
                event=post_event,
                module=module.module_name,
                target=target,
                result=result
            ).result()
            
            return (module.module_name, result)
            
        except Exception as e:
            logger.error(
                f"Module {module.module_name} failed on {target.host}: {str(e)}",
                exc_info=True
            )
            return (module.module_name, ScanResult(
                target=target,
                data={'error': str(e)},
                status=ScanStatus.FAILED
            ))

    def _handle_scan_completion(self, future: Future) -> None:
        """Update progress when a scan task completes"""
        with self._lock:
            self._progress['completed'] += 1
            
        # Calculate progress percentage
        progress = (self._progress['completed'] / max(1, self._progress['total'])) * 100
        event_system.emit(
            "scan_progress",
            progress=progress,
            completed=self._progress['completed'],
            total=self._progress['total'],
            failed=self._progress['failed']
        )

    def pause(self) -> None:
        """Pause current scan operations"""
        with self._lock:
            if self.status == ScanStatus.RUNNING:
                self.status = ScanStatus.PAUSED
                for module in self._modules.values():
                    module.interrupt()
                logger.info("Scan paused")

    def resume(self) -> None:
        """Resume paused scan operations"""
        with self._lock:
            if self.status == ScanStatus.PAUSED:
                self.status = ScanStatus.RUNNING
                for module in self._modules.values():
                    module._interrupt.clear()
                logger.info("Scan resumed")

    def stop(self) -> None:
        """Stop all scan operations"""
        with self._lock:
            if self.status in (ScanStatus.RUNNING, ScanStatus.PAUSED):
                self.status = ScanStatus.CANCELLED
                self._interrupt.set()
                for module in self._modules.values():
                    module.interrupt()
                    
                # Cancel all pending tasks
                for task_id, future in self._current_tasks.items():
                    if not future.done():
                        future.cancel()
                self._current_tasks.clear()
                
                logger.info("Scan stopped")

    def get_progress(self) -> Dict[str, int]:
        """Get current scan progress"""
        with self._lock:
            return self._progress.copy()

    def get_status(self) -> ScanStatus:
        """Get current engine status"""
        with self._lock:
            return self.status

    def shutdown(self) -> None:
        """Cleanup engine resources"""
        self.stop()
        with self._lock:
            for module in self._modules.values():
                module.cleanup()
            self._modules.clear()
            self._executor.shutdown(wait=False)
            logger.info("Scan engine shutdown complete")

# Global engine instance
scan_engine = ScanEngine()

@event_system.register("pre_scan", priority=EventPriority.HIGHEST)
def validate_scan_target(event: Event, module: str, target: ScanTarget) -> None:
    """Global pre-scan validation"""
    if not DataHelpers.validate_ip(target.host) and not DataHelpers.validate_hostname(target.host):
        event.cancel()
        logger.warning(f"Invalid scan target: {target.host}")

@event_system.register("post_scan", priority=EventPriority.LOWEST)
def log_scan_result(event: Event, module: str, target: ScanTarget, result: ScanResult) -> None:
    """Log all scan results"""
    if result.status == ScanStatus.FAILED:
        logger.error(
            f"Scan failed on {target.host} with {module}: {result.data.get('error', 'Unknown error')}"
        )
    elif result.status == ScanStatus.COMPLETED:
        logger.info(
            f"Scan completed on {target.host} with {module}. Results: {len(result.data)} items"
        )