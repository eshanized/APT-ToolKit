"""
Advanced logging utility for APT Toolkit with security controls

Features:
- Sensitive data redaction
- Audit trail integration
- Thread-safe operations
- Structured logging support
- Runtime log level adjustment
"""

import logging
import logging.config
import re
from pathlib import Path
from typing import Dict, Optional, Union
import json
import threading
from functools import wraps
from src.utils.config import config

# Sensitive data patterns
SENSITIVE_PATTERNS = [
    r'(?i)password=([^&\s]+)',
    r'(?i)api_?key=([^&\s]+)',
    r'(?i)token=([^&\s]+)',
    r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',  # Credit cards
    r'\b\d{3}[- ]?\d{2}[- ]?\d{4}\b'  # SSNs
]

class SensitiveDataFilter(logging.Filter):
    """Filter to redact sensitive information from logs"""
    def __init__(self):
        super().__init__()
        self._patterns = [re.compile(p) for p in SENSITIVE_PATTERNS]

    def filter(self, record: logging.LogRecord) -> bool:
        """Redact sensitive data from log messages"""
        if isinstance(record.msg, str):
            record.msg = self._redact_sensitive(record.msg)
        if isinstance(record.args, (dict, str)):
            record.args = self._redact_sensitive(record.args)
        return True

    def _redact_sensitive(self, data: Union[str, Dict]) -> Union[str, Dict]:
        """Apply redaction to strings or dicts"""
        if isinstance(data, str):
            for pattern in self._patterns:
                data = pattern.sub(r'\1[REDACTED]', data)
        elif isinstance(data, dict):
            return {k: self._redact_sensitive(v) for k, v in data.items()}
        return data

class StructuredFormatter(logging.Formatter):
    """JSON formatter for structured logging"""
    def format(self, record: logging.LogRecord) -> str:
        """Convert log record to JSON string"""
        log_data = {
            'timestamp': self.formatTime(record),
            'level': record.levelname,
            'logger': record.name,
            'process': record.process,
            'thread': record.thread,
            'message': record.getMessage(),
        }
        if hasattr(record, 'data'):
            log_data.update(record.data)
        return json.dumps(log_data)

class ThreadContextFilter(logging.Filter):
    """Add thread context information to logs"""
    def __init__(self):
        super().__init__()
        self.local = threading.local()

    def filter(self, record: logging.LogRecord) -> bool:
        """Add thread context to log records"""
        record.thread_name = getattr(self.local, 'name', 'main')
        record.task_id = getattr(self.local, 'task_id', None)
        return True

def setup_logging(config_path: Optional[Path] = None) -> None:
    """
    Initialize logging configuration with security controls
    
    Args:
        config_path: Path to logging config file
    """
    try:
        logging_config = str(config_path or Path(__file__).parent.parent / 'config' / 'logging.conf')
        logging.config.fileConfig(
            logging_config,
            disable_existing_loggers=False,
            defaults={'log_level': config.logging.level}
        )
        
        # Apply security filters to all handlers
        sensitive_filter = SensitiveDataFilter()
        for handler in logging.root.handlers:
            handler.addFilter(sensitive_filter)
            handler.addFilter(ThreadContextFilter())
            
        # Special audit logger setup
        audit_logger = logging.getLogger('apt_audit')
        audit_logger.propagate = False
        audit_logger.setLevel(logging.INFO)
        
    except Exception as e:
        logging.basicConfig(level=logging.WARNING)
        logging.warning(f"Failed to load logging config: {str(e)}")

def log_operation(logger_name: str = 'apt_audit'):
    """
    Decorator for logging function entry/exit with timing
    
    Args:
        logger_name: Name of logger to use
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            logger = logging.getLogger(logger_name)
            logger.info(
                "Operation started",
                extra={'data': {
                    'operation': func.__name__,
                    'args': args,
                    'kwargs': kwargs
                }}
            )
            
            try:
                result = func(*args, **kwargs)
                logger.info(
                    "Operation completed",
                    extra={'data': {
                        'operation': func.__name__,
                        'status': 'success'
                    }}
                )
                return result
            except Exception as e:
                logger.error(
                    "Operation failed",
                    extra={'data': {
                        'operation': func.__name__,
                        'error': str(e),
                        'status': 'failed'
                    }},
                    exc_info=True
                )
                raise
        return wrapper
    return decorator

def get_logger(name: str, structured: bool = False) -> logging.Logger:
    """
    Get configured logger instance with security controls
    
    Args:
        name: Logger name
        structured: Enable JSON formatting
    """
    logger = logging.getLogger(name)
    
    if structured and not any(
        isinstance(h, logging.StreamHandler) and 
        isinstance(h.formatter, StructuredFormatter)
        for h in logger.handlers
    ):
        handler = logging.StreamHandler()
        handler.setFormatter(StructuredFormatter())
        logger.addHandler(handler)
    
    return logger

# Initialize logging on import
setup_logging()

# Example usage:
# logger = get_logger(__name__)
# logger.info("Message", extra={'data': {'key': 'value'}})