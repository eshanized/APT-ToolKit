"""
Advanced Event System for APT Toolkit

Features:
- Type-safe event handling
- Async/sync event support
- Priority-based execution
- Event cancellation
- Thread-safe operations
"""

import asyncio
import inspect
import logging
from typing import (
    Any,
    Callable,
    Dict,
    List,
    Optional,
    Set,
    Tuple,
    TypeVar,
    Union,
    Coroutine,
)
from dataclasses import dataclass
from enum import Enum, auto
from functools import partial, wraps
import threading
from concurrent.futures import Future
from src.utils.logger import get_logger

logger = get_logger(__name__)

T = TypeVar("T")
EventCallback = Union[
    Callable[..., Optional[T]],
    Callable[..., Coroutine[Any, Any, Optional[T]]],
]

class EventPriority(Enum):
    """Execution priority for event handlers"""
    HIGHEST = auto()
    HIGH = auto()
    NORMAL = auto()
    LOW = auto()
    LOWEST = auto()

class EventCancelled(Exception):
    """Exception raised when an event is cancelled"""
    pass

@dataclass
class Event:
    """Base event class"""
    name: str
    cancelled: bool = False

    def cancel(self) -> None:
        """Cancel this event"""
        self.cancelled = True
        logger.debug(f"Event '{self.name}' cancelled")

@dataclass
class HandlerRegistration:
    """Registered event handler details"""
    callback: EventCallback
    priority: EventPriority
    is_async: bool

class EventSystem:
    """Thread-safe event dispatch system"""

    def __init__(self):
        self._handlers: Dict[str, List[HandlerRegistration]] = {}
        self._lock = threading.RLock()
        self._loop = asyncio.get_event_loop()

    def register(
        self,
        event_name: str,
        callback: Optional[EventCallback] = None,
        priority: EventPriority = EventPriority.NORMAL,
    ) -> Callable:
        """
        Decorator or method to register event handlers
        
        Args:
            event_name: Name of event to handle
            callback: Optional direct callback registration
            priority: Handler execution priority
            
        Returns:
            Decorator if no callback provided, otherwise None
        """
        if callback is None:
            return partial(self.register, event_name, priority=priority)

        is_async = inspect.iscoroutinefunction(callback)

        with self._lock:
            if event_name not in self._handlers:
                self._handlers[event_name] = []

            registration = HandlerRegistration(callback, priority, is_async)
            self._handlers[event_name].append(registration)
            # Keep handlers sorted by priority (highest first)
            self._handlers[event_name].sort(
                key=lambda h: h.priority.value, reverse=True
            )

        logger.debug(
            f"Registered {'async' if is_async else 'sync'} handler for "
            f"event '{event_name}' at {priority.name} priority"
        )
        return callback

    def unregister(self, event_name: str, callback: EventCallback) -> bool:
        """
        Unregister an event handler
        
        Args:
            event_name: Name of event
            callback: Callback to remove
            
        Returns:
            bool: True if handler was removed, False if not found
        """
        with self._lock:
            if event_name not in self._handlers:
                return False

            before_count = len(self._handlers[event_name])
            self._handlers[event_name] = [
                h for h in self._handlers[event_name] if h.callback != callback
            ]
            removed = before_count != len(self._handlers[event_name])

            if removed:
                logger.debug(f"Unregistered handler for event '{event_name}'")
            else:
                logger.debug(
                    f"Handler not found for event '{event_name}' during unregister"
                )

            return removed

    def emit(
        self, event_name: str, event: Optional[Event] = None, **kwargs
    ) -> Future:
        """
        Emit an event to be processed by handlers
        
        Args:
            event_name: Name of event to emit
            event: Optional Event instance
            **kwargs: Additional event arguments
            
        Returns:
            Future: Result future that completes when all handlers finish
        """
        if event is None:
            event = Event(event_name)

        future = Future()

        def execute_handlers():
            try:
                if event.cancelled:
                    raise EventCancelled(f"Event '{event_name}' was cancelled")

                handlers = self._get_handlers(event_name)
                if not handlers:
                    future.set_result(None)
                    return

                if any(h.is_async for h in handlers):
                    asyncio.run_coroutine_threadsafe(
                        self._execute_async_handlers(event, handlers, **kwargs),
                        self._loop,
                    ).add_done_callback(
                        lambda f: future.set_result(f.result())
                    )
                else:
                    result = self._execute_sync_handlers(event, handlers, **kwargs)
                    future.set_result(result)
            except Exception as e:
                future.set_exception(e)

        # Execute in a thread to prevent blocking
        threading.Thread(target=execute_handlers, daemon=True).start()
        return future

    async def emit_async(
        self, event_name: str, event: Optional[Event] = None, **kwargs
    ) -> Any:
        """
        Async variant of emit that awaits all handlers
        
        Args:
            event_name: Name of event to emit
            event: Optional Event instance
            **kwargs: Additional event arguments
            
        Returns:
            Any: Result from last handler
        """
        if event is None:
            event = Event(event_name)

        if event.cancelled:
            raise EventCancelled(f"Event '{event_name}' was cancelled")

        handlers = self._get_handlers(event_name)
        if not handlers:
            return None

        if any(h.is_async for h in handlers):
            return await self._execute_async_handlers(event, handlers, **kwargs)
        return self._execute_sync_handlers(event, handlers, **kwargs)

    def _get_handlers(self, event_name: str) -> List[HandlerRegistration]:
        """Get handlers for an event in thread-safe manner"""
        with self._lock:
            return self._handlers.get(event_name, []).copy()

    def _execute_sync_handlers(
        self, event: Event, handlers: List[HandlerRegistration], **kwargs
    ) -> Any:
        """Execute synchronous event handlers"""
        result = None
        for handler in handlers:
            if event.cancelled:
                raise EventCancelled(f"Event '{event.name}' was cancelled")

            if handler.is_async:
                continue  # Async handlers handled separately

            try:
                current_result = handler.callback(event, **kwargs)
                if current_result is not None:
                    result = current_result
            except Exception as e:
                logger.error(
                    f"Error in sync handler for event '{event.name}': {str(e)}",
                    exc_info=True,
                )
                if not isinstance(e, EventCancelled):
                    raise

        return result

    async def _execute_async_handlers(
        self, event: Event, handlers: List[HandlerRegistration], **kwargs
    ) -> Any:
        """Execute asynchronous event handlers"""
        result = None
        for handler in handlers:
            if event.cancelled:
                raise EventCancelled(f"Event '{event.name}' was cancelled")

            try:
                if handler.is_async:
                    current_result = await handler.callback(event, **kwargs)
                else:
                    current_result = handler.callback(event, **kwargs)

                if current_result is not None:
                    result = current_result
            except Exception as e:
                logger.error(
                    f"Error in {'async' if handler.is_async else 'sync'} "
                    f"handler for event '{event.name}': {str(e)}",
                    exc_info=True,
                )
                if not isinstance(e, EventCancelled):
                    raise

        return result

    def has_handlers(self, event_name: str) -> bool:
        """Check if any handlers are registered for an event"""
        with self._lock:
            return event_name in self._handlers and bool(self._handlers[event_name])

# Global event system instance
event_system = EventSystem()

# Convenience decorators
def on_event(
    event_name: str, priority: EventPriority = EventPriority.NORMAL
) -> Callable:
    """Decorator to register event handlers"""
    return event_system.register(event_name, priority=priority)

def async_on_event(
    event_name: str, priority: EventPriority = EventPriority.NORMAL
) -> Callable:
    """Decorator to register async event handlers"""
    def decorator(coro: Callable[..., Coroutine]) -> Callable:
        @wraps(coro)
        async def wrapper(*args, **kwargs):
            return await coro(*args, **kwargs)
        
        event_system.register(event_name, wrapper, priority)
        return wrapper
    return decorator