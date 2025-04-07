"""
Core utility functions for APT Toolkit

Features:
- Network operations with security controls
- Data validation and sanitization
- Cryptographic helpers
- Thread/concurrency utilities
- Error handling patterns
"""

import ipaddress
import json
import logging
import socket
import re
import hashlib
from typing import Optional, Union, List, Dict, Any, Callable
from functools import wraps
from concurrent.futures import Future
import threading
import time
import random
import string
from urllib.parse import urlparse
from pathlib import Path
import inspect
import ssl
import certifi
from src.utils.config import config
from src.utils.logger import get_logger

logger = get_logger(__name__)

# Constants
MAX_PORT = 65535
DEFAULT_USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) APT-Toolkit/1.0"
SAFE_FILENAME_CHARS = "-_.() %s%s" % (string.ascii_letters, string.digits)

class NetworkHelpers:
    """Network-related utility functions"""
    
    @staticmethod
    def is_valid_ip(target: str) -> bool:
        """Validate IPv4/IPv6 address with security controls"""
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False

    @staticmethod
    def resolve_hostname(hostname: str, timeout: float = 3.0) -> Optional[str]:
        """Securely resolve hostname to IP address"""
        try:
            with socket.create_connection((hostname, 80), timeout=timeout) as conn:
                return conn.getpeername()[0]
        except (socket.gaierror, socket.timeout, ConnectionRefusedError):
            return None

    @staticmethod
    def get_ssl_cert(hostname: str, port: int = 443) -> Optional[Dict[str, Any]]:
        """Retrieve SSL certificate info with validation"""
        try:
            context = ssl.create_default_context(cafile=certifi.where())
            with socket.create_connection((hostname, port)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serialNumber': cert['serialNumber'],
                        'notBefore': cert['notBefore'],
                        'notAfter': cert['notAfter'],
                        'extensions': cert.get('extensions', [])
                    }
        except (ssl.SSLError, socket.error) as e:
            logger.warning(f"SSL cert fetch failed for {hostname}:{port} - {str(e)}")
            return None

class DataHelpers:
    """Data manipulation and validation utilities"""
    
    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize strings to be safe filenames"""
        cleaned = ''.join(c for c in filename if c in SAFE_FILENAME_CHARS)
        return cleaned.strip().replace(' ', '_')[:255]

    @staticmethod
    def generate_random_string(length: int = 8) -> str:
        """Generate cryptographically random string"""
        return ''.join(random.SystemRandom().choice(
            string.ascii_letters + string.digits
        ) for _ in range(length))

    @staticmethod
    def is_valid_json(data: str) -> bool:
        """Validate JSON data safely"""
        try:
            json.loads(data)
            return True
        except (json.JSONDecodeError, TypeError):
            return False

    @staticmethod
    def deep_merge(dict1: Dict, dict2: Dict) -> Dict:
        """Recursively merge two dictionaries"""
        result = dict1.copy()
        for key, value in dict2.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = DataHelpers.deep_merge(result[key], value)
            else:
                result[key] = value
        return result

class SecurityHelpers:
    """Security-focused utility functions"""
    
    @staticmethod
    def hash_data(data: str, algorithm: str = 'sha256') -> str:
        """Generate secure hash of data"""
        if algorithm not in hashlib.algorithms_available:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")
        hasher = hashlib.new(algorithm)
        hasher.update(data.encode('utf-8'))
        return hasher.hexdigest()

    @staticmethod
    def validate_url(url: str) -> bool:
        """Validate URL with security constraints"""
        try:
            result = urlparse(url)
            if not all([result.scheme, result.netloc]):
                return False
            return result.scheme in ('http', 'https')
        except ValueError:
            return False

    @staticmethod
    def is_malicious_input(input_str: str) -> bool:
        """Check for common injection patterns"""
        patterns = [
            r'<script.*?>.*?</script>',
            r'[\s]*(union|select|insert|update|delete|drop|alter)[\s]+',
            r'(\|\||&&)[\s]*\w+\(.*\)',
            r'\.\./\.\./'  # Path traversal
        ]
        return any(re.search(p, input_str, re.IGNORECASE) for p in patterns)

class ConcurrencyHelpers:
    """Thread and concurrency utilities"""
    
    @staticmethod
    def run_in_thread(func: Callable) -> Future:
        """Execute function in thread pool"""
        executor = config.core.thread_pool_executor
        return executor.submit(func)

    @staticmethod
    def synchronized(lock: threading.Lock):
        """Thread synchronization decorator"""
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                with lock:
                    return func(*args, **kwargs)
            return wrapper
        return decorator

    @staticmethod
    def timeout(timeout_sec: float):
        """Function timeout decorator"""
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                result = None
                exception = None
                
                def target():
                    nonlocal result, exception
                    try:
                        result = func(*args, **kwargs)
                    except Exception as e:
                        exception = e
                
                thread = threading.Thread(target=target)
                thread.daemon = True
                thread.start()
                thread.join(timeout_sec)
                
                if thread.is_alive():
                    thread.join()  # Cleanup
                    raise TimeoutError(f"Function {func.__name__} timed out after {timeout_sec} seconds")
                if exception:
                    raise exception
                return result
            return wrapper
        return decorator

class ErrorHelpers:
    """Error handling utilities"""
    
    @staticmethod
    def retry(max_attempts: int = 3, delay: float = 1.0, 
              exceptions: tuple = (Exception,)):
        """Retry decorator for unreliable operations"""
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                last_exception = None
                for attempt in range(1, max_attempts + 1):
                    try:
                        return func(*args, **kwargs)
                    except exceptions as e:
                        last_exception = e
                        if attempt < max_attempts:
                            time.sleep(delay * attempt)
                        logger.warning(f"Attempt {attempt} failed: {str(e)}")
                raise last_exception
            return wrapper
        return decorator

    @staticmethod
    def suppress_errors(logger: logging.Logger = None):
        """Suppress and log errors decorator"""
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    if logger:
                        logger.debug(f"Suppressed error in {func.__name__}: {str(e)}")
                    return None
            return wrapper
        return decorator

# Utility function exports
sanitize_filename = DataHelpers.sanitize_filename
is_valid_ip = NetworkHelpers.is_valid_ip
hash_data = SecurityHelpers.hash_data
run_in_thread = ConcurrencyHelpers.run_in_thread
retry = ErrorHelpers.retry