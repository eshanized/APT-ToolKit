"""
Advanced Queue Dispatcher for APT Toolkit

Features:
- Priority-based task queue
- Thread-safe operation
- Task deduplication
- Automatic retry mechanism
- Progress tracking
- Graceful shutdown
"""

import heapq
import threading
import time
from typing import (
    Any,
    Callable,
    Dict,
    Generic,
    List,
    Optional,
    Set,
    Tuple,
    TypeVar,
    Union,
)
from concurrent.futures import Future, ThreadPoolExecutor
from enum import IntEnum
from dataclasses import dataclass, field
from src.utils.logger import get_logger
from src.utils.config import config
from src.utils.helpers import ErrorHelpers
from src.core.event_system import event_system, Event, EventPriority

logger = get_logger(__name__)

T = TypeVar("T")

class Priority(IntEnum):
    """Task priority levels"""
    CRITICAL = 0
    HIGH = 1
    NORMAL = 2
    LOW = 3

@dataclass(order=True)
class QueueItem(Generic[T]):
    """Item in the priority queue"""
    priority: Priority
    timestamp: float = field(compare=False)
    task_id: str = field(compare=False)
    task: Callable[[], T] = field(compare=False)
    retries: int = field(default=0, compare=False)
    future: Optional[Future] = field(default=None, compare=False)

class QueueDispatcher:
    """Thread-safe priority task dispatcher"""

    def __init__(self):
        self._queue: List[QueueItem] = []
        self._lock = threading.RLock()
        self._cv = threading.Condition(self._lock)
        self._active_tasks: Set[str] = set()
        self._task_counter = 0
        self._shutdown = False
        self._executor = ThreadPoolExecutor(
            max_workers=config.core.max_dispatcher_threads,
            thread_name_prefix="apt_dispatcher_"
        )
        
        # Start dispatcher thread
        self._dispatcher_thread = threading.Thread(
            target=self._dispatch_loop,
            name="QueueDispatcher",
            daemon=True
        )
        self._dispatcher_thread.start()

    def submit(
        self,
        task: Callable[[], T],
        task_id: Optional[str] = None,
        priority: Priority = Priority.NORMAL,
        retries: int = 0
    ) -> Future:
        """
        Submit a task to the queue
        
        Args:
            task: Callable to execute
            task_id: Optional unique task identifier
            priority: Task priority
            retries: Number of retry attempts
            
        Returns:
            Future: Result future for the task
            
        Raises:
            RuntimeError: If dispatcher is shutting down
        """
        with self._lock:
            if self._shutdown:
                raise RuntimeError("Dispatcher is shutting down")
                
            if not task_id:
                self._task_counter += 1
                task_id = f"task_{self._task_counter}"
                
            # Check for duplicate tasks
            if task_id in self._active_tasks:
                for item in self._queue:
                    if item.task_id == task_id:
                        logger.debug(f"Duplicate task {task_id} detected")
                        return item.future or Future()
            
            future = Future()
            heapq.heappush(
                self._queue,
                QueueItem(
                    priority=priority,
                    timestamp=time.time(),
                    task_id=task_id,
                    task=task,
                    retries=retries,
                    future=future
                )
            )
            self._active_tasks.add(task_id)
            self._cv.notify()
            
            logger.debug(f"Submitted task {task_id} at {priority.name} priority")
            return future

    def _dispatch_loop(self) -> None:
        """Main dispatch processing loop"""
        while True:
            with self._lock:
                while not (self._queue or self._shutdown):
                    self._cv.wait()
                    
                if self._shutdown and not self._queue:
                    logger.info("Dispatcher shutdown complete")
                    return
                    
                item = heapq.heappop(self._queue)
                self._active_tasks.remove(item.task_id)
                
            try:
                # Execute the task
                result = item.task()
                
                # Set result on future
                if item.future and not item.future.done():
                    item.future.set_result(result)
                    
                logger.debug(f"Completed task {item.task_id}")
                
            except Exception as e:
                logger.warning(f"Task {item.task_id} failed: {str(e)}")
                
                # Handle retries
                if item.retries > 0:
                    with self._lock:
                        heapq.heappush(
                            self._queue,
                            QueueItem(
                                priority=item.priority,
                                timestamp=time.time(),
                                task_id=item.task_id,
                                task=item.task,
                                retries=item.retries - 1,
                                future=item.future
                            )
                        )
                        self._active_tasks.add(item.task_id)
                        logger.debug(f"Retrying task {item.task_id}, attempts left: {item.retries}")
                elif item.future and not item.future.done():
                    item.future.set_exception(e)

    def shutdown(self, wait: bool = True) -> None:
        """
        Shutdown the dispatcher
        
        Args:
            wait: Whether to wait for queue to drain
        """
        with self._lock:
            if self._shutdown:
                return
                
            self._shutdown = True
            self._cv.notify_all()
            
        logger.info("Initiating dispatcher shutdown...")
        
        if wait:
            # Wait for queue to drain
            while True:
                with self._lock:
                    if not self._queue:
                        break
                time.sleep(0.1)
                
            # Wait for dispatcher thread
            self._dispatcher_thread.join(timeout=5.0)
            
        # Shutdown executor
        self._executor.shutdown(wait=wait)
        
        logger.info("Dispatcher resources released")

    def get_queue_size(self) -> Tuple[int, Dict[Priority, int]]:
        """
        Get current queue status
        
        Returns:
            Tuple of (total_tasks, {priority: count})
        """
        with self._lock:
            counts = {p: 0 for p in Priority}
            for item in self._queue:
                counts[item.priority] += 1
            return (len(self._queue), counts)

    def cancel_task(self, task_id: str) -> bool:
        """
        Cancel a pending task
        
        Args:
            task_id: ID of task to cancel
            
        Returns:
            bool: True if task was cancelled, False if not found
        """
        with self._lock:
            for i, item in enumerate(self._queue):
                if item.task_id == task_id:
                    if item.future and not item.future.done():
                        item.future.cancel()
                    self._queue.pop(i)
                    heapq.heapify(self._queue)
                    self._active_tasks.remove(task_id)
                    logger.info(f"Cancelled task {task_id}")
                    return True
            return False

# Global dispatcher instance
dispatcher = QueueDispatcher()

@event_system.register("shutdown", priority=EventPriority.HIGHEST)
def handle_shutdown(event: Event) -> None:
    """Handle application shutdown"""
    dispatcher.shutdown()

# Example usage:
# future = dispatcher.submit(
#     lambda: scan_target(target),
#     task_id=f"scan_{target.host}",
#     priority=Priority.HIGH,
#     retries=2
# )
# result = future.result()  # Blocks until completion