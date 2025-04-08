"""
Advanced Threading Utilities for APT Toolkit

Features:
- Thread-safe primitives
- Synchronization helpers
- Thread pool management
- Deadlock prevention
- Performance monitoring
"""

import queue
import threading
import time
from typing import Any, Callable, Dict, Optional, TypeVar, Generic
from concurrent.futures import ThreadPoolExecutor, Future
from dataclasses import dataclass, field
from queue import Queue, Empty
import contextlib
from src.utils.logger import get_logger
from src.utils.config import config

logger = get_logger(__name__)

T = TypeVar('T')

class AtomicInteger:
    """Thread-safe integer with atomic operations"""
    def __init__(self, value: int = 0):
        self._value = value
        self._lock = threading.RLock()

    def inc(self) -> int:
        """Atomic increment"""
        with self._lock:
            self._value += 1
            return self._value

    def dec(self) -> int:
        """Atomic decrement"""
        with self._lock:
            self._value -= 1
            return self._value

    @property
    def value(self) -> int:
        """Current value"""
        with self._lock:
            return self._value

    @value.setter
    def value(self, v: int):
        """Set value"""
        with self._lock:
            self._value = v

class TimedLock:
    """Lock with timeout and deadlock detection"""
    def __init__(self, timeout: float = 10.0):
        self._lock = threading.RLock()
        self.timeout = timeout
        self._owner: Optional[int] = None

    def acquire(self, blocking: bool = True) -> bool:
        """Acquire lock with timeout"""
        start = time.time()
        while True:
            acquired = self._lock.acquire(blocking=False)
            if acquired:
                self._owner = threading.get_ident()
                return True
            elif not blocking:
                return False
            elif time.time() - start > self.timeout:
                logger.warning(
                    f"Potential deadlock detected in thread {threading.get_ident()}. "
                    f"Current owner: {self._owner}"
                )
                return False
            time.sleep(0.01)

    def release(self) -> None:
        """Release lock"""
        self._owner = None
        self._lock.release()

    @contextlib.contextmanager
    def locked(self) -> Any:
        """Context manager for lock acquisition"""
        acquired = self.acquire()
        try:
            yield acquired
        finally:
            if acquired:
                self.release()

class ThreadPool:
    """Managed thread pool with task queue monitoring"""
    def __init__(self, name: str, max_workers: Optional[int] = None):
        self.name = name
        self.max_workers = max_workers or config.core.max_threads
        self._executor = ThreadPoolExecutor(
            max_workers=self.max_workers,
            thread_name_prefix=f"apt_{name}_"
        )
        self._pending = AtomicInteger()
        self._completed = AtomicInteger()
        self._active = AtomicInteger()

    def submit(self, fn: Callable[..., T], *args, **kwargs) -> Future[T]:
        """Submit task to thread pool"""
        self._pending.inc()
        
        def wrapped_fn():
            self._pending.dec()
            self._active.inc()
            try:
                result = fn(*args, **kwargs)
                self._completed.inc()
                return result
            except Exception as e:
                logger.error(f"Task failed in {self.name} pool: {str(e)}")
                raise
            finally:
                self._active.dec()

        return self._executor.submit(wrapped_fn)

    def shutdown(self, wait: bool = True) -> None:
        """Shutdown thread pool"""
        self._executor.shutdown(wait=wait)

    @property
    def stats(self) -> Dict[str, int]:
        """Current pool statistics"""
        return {
            'pending': self._pending.value,
            'active': self._active.value,
            'completed': self._completed.value,
            'max_workers': self.max_workers
        }

@dataclass
class Debouncer:
    """Debounce rapid function calls"""
    interval: float  # seconds
    _last_called: float = field(default_factory=lambda: -1, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    def debounce(self, fn: Callable) -> Callable:
        """Decorator to debounce function calls"""
        def wrapped(*args, **kwargs):
            with self._lock:
                now = time.time()
                if now - self._last_called >= self.interval:
                    self._last_called = now
                    return fn(*args, **kwargs)
        return wrapped

class BoundedQueue:
    """Thread-safe bounded queue with backpressure"""
    def __init__(self, maxsize: int = 0):
        self.queue = Queue(maxsize=maxsize)
        self._dropped = AtomicInteger()

    def put(self, item: Any, block: bool = True, timeout: Optional[float] = None) -> bool:
        """Add item to queue with backpressure handling"""
        try:
            self.queue.put(item, block=block, timeout=timeout)
            return True
        except queue.Full:
            self._dropped.inc()
            logger.warning(f"Queue full, dropped item (total: {self._dropped.value})")
            return False

    def get(self, block: bool = True, timeout: Optional[float] = None) -> Any:
        """Get item from queue"""
        return self.queue.get(block=block, timeout=timeout)

    @property
    def dropped_count(self) -> int:
        """Number of dropped items"""
        return self._dropped.value

def synchronized(lock: threading.Lock) -> Callable:
    """Decorator for thread-safe method execution"""
    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            with lock:
                return func(*args, **kwargs)
        return wrapper
    return decorator

def run_in_thread(name: Optional[str] = None, daemon: bool = True) -> Callable:
    """Decorator to execute function in background thread"""
    def decorator(func: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            thread = threading.Thread(
                target=func,
                args=args,
                kwargs=kwargs,
                name=name or func.__name__,
                daemon=daemon
            )
            thread.start()
            return thread
        return wrapper
    return decorator

# Global thread pools
scan_pool = ThreadPool("scan_worker")
io_pool = ThreadPool("io_worker", max_workers=4)
net_pool = ThreadPool("net_worker", max_workers=8)

def shutdown_thread_pools() -> None:
    """Cleanup all thread pools"""
    scan_pool.shutdown()
    io_pool.shutdown()
    net_pool.shutdown()
    logger.info("All thread pools shutdown")

# Example usage:
# @run_in_thread("background_task")
# def long_running_task():
#     pass
#
# atomic = AtomicInteger(5)
# atomic.inc()
#
# with TimedLock().locked():
#     # critical section
#     pass
#
# debounce = Debouncer(0.5)
# @debounce.debounce
# def handle_input():
#     pass