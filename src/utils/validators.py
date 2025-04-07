"""
Advanced validation utilities for APT Toolkit

Features:
- Input sanitization and validation
- Protocol-specific validators
- Security-focused checks
- Network resource validation
- Data format verification
"""

import re
import ipaddress
import socket
import urllib.parse
from typing import Any, Dict, Optional, Tuple, Union
from datetime import datetime
import dns.resolver
import idna
from src.utils.config import config
from src.utils.logger import get_logger
from src.utils.helpers import DataHelpers

logger = get_logger(__name__)

class ValidationError(Exception):
    """Base validation error with contextual information"""
    def __init__(self, message: str, field: str = None, value: Any = None):
        self.message = message
        self.field = field
        self.value = value
        super().__init__(message)

class InputValidators:
    """Core input validation and sanitization"""
    
    @staticmethod
    def validate_str(
        value: Any,
        min_len: int = 1,
        max_len: int = 255,
        regex: Optional[str] = None,
        field_name: str = None
    ) -> str:
        """
        Validate and sanitize string input
        
        Args:
            value: Input value to validate
            min_len: Minimum length requirement
            max_len: Maximum length allowed
            regex: Optional regex pattern to match
            field_name: Field name for error messages
            
        Returns:
            Sanitized string value
            
        Raises:
            ValidationError: If validation fails
        """
        if not isinstance(value, str):
            raise ValidationError(
                f"Expected string, got {type(value).__name__}",
                field_name,
                value
            )
            
        stripped = value.strip()
        if len(stripped) < min_len:
            raise ValidationError(
                f"Must be at least {min_len} characters",
                field_name,
                value
            )
            
        if len(stripped) > max_len:
            raise ValidationError(
                f"Exceeds maximum length of {max_len} characters",
                field_name,
                value
            )
            
        if regex and not re.fullmatch(regex, stripped):
            raise ValidationError(
                f"Does not match required pattern: {regex}",
                field_name,
                value
            )
            
        return DataHelpers.sanitize_filename(stripped)

    @staticmethod
    def validate_int(
        value: Any,
        min_val: Optional[int] = None,
        max_val: Optional[int] = None,
        field_name: str = None
    ) -> int:
        """
        Validate integer input with range checking
        
        Args:
            value: Input value to validate
            min_val: Minimum allowed value
            max_val: Maximum allowed value
            field_name: Field name for error messages
            
        Returns:
            Validated integer
            
        Raises:
            ValidationError: If validation fails
        """
        try:
            num = int(value)
        except (ValueError, TypeError):
            raise ValidationError(
                "Invalid integer value",
                field_name,
                value
            )
            
        if min_val is not None and num < min_val:
            raise ValidationError(
                f"Must be at least {min_val}",
                field_name,
                value
            )
            
        if max_val is not None and num > max_val:
            raise ValidationError(
                f"Must be at most {max_val}",
                field_name,
                value
            )
            
        return num

    @staticmethod
    def validate_bool(value: Any, field_name: str = None) -> bool:
        """
        Validate boolean input
        
        Args:
            value: Input value to validate
            field_name: Field name for error messages
            
        Returns:
            Validated boolean
            
        Raises:
            ValidationError: If validation fails
        """
        if isinstance(value, bool):
            return value
            
        if isinstance(value, str):
            lower_val = value.lower()
            if lower_val in ('true', '1', 'yes', 'y'):
                return True
            if lower_val in ('false', '0', 'no', 'n'):
                return False
                
        raise ValidationError(
            "Invalid boolean value",
            field_name,
            value
        )

class NetworkValidators:
    """Network-related validation utilities"""
    
    @staticmethod
    def validate_ip(
        address: str,
        allow_private: bool = False,
        field_name: str = None
    ) -> str:
        """
        Validate IP address with security controls
        
        Args:
            address: IP address to validate
            allow_private: Whether to allow private/reserved IPs
            field_name: Field name for error messages
            
        Returns:
            Normalized IP address string
            
        Raises:
            ValidationError: If validation fails
        """
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            raise ValidationError(
                "Invalid IP address format",
                field_name,
                address
            )
            
        if not allow_private and ip.is_private:
            raise ValidationError(
                "Private IP addresses not allowed",
                field_name,
                address
            )
            
        if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            raise ValidationError(
                "Special-use IP addresses not allowed",
                field_name,
                address
            )
            
        return str(ip)

    @staticmethod
    def validate_hostname(
        hostname: str,
        resolve_dns: bool = False,
        field_name: str = None
    ) -> str:
        """
        Validate hostname with optional DNS resolution
        
        Args:
            hostname: Hostname to validate
            resolve_dns: Whether to verify DNS resolution
            field_name: Field name for error messages
            
        Returns:
            Normalized hostname
            
        Raises:
            ValidationError: If validation fails
        """
        try:
            # IDNA encoding for internationalized domains
            encoded = idna.encode(hostname).decode('ascii')
        except idna.IDNAError:
            raise ValidationError(
                "Invalid hostname format",
                field_name,
                hostname
            )
            
        if not re.match(
            r'^([a-z0-9]+(-[a-z0-9]+)*\.)+[a-z]{2,}$',
            encoded,
            re.IGNORECASE
        ):
            raise ValidationError(
                "Invalid hostname format",
                field_name,
                hostname
            )
            
        if resolve_dns:
            try:
                socket.getaddrinfo(encoded, None)
            except socket.gaierror:
                raise ValidationError(
                    "Hostname does not resolve",
                    field_name,
                    hostname
                )
                
        return encoded

    @staticmethod
    def validate_port(
        port: Any,
        allow_privileged: bool = False,
        field_name: str = None
    ) -> int:
        """
        Validate network port number
        
        Args:
            port: Port number to validate
            allow_privileged: Allow privileged ports (<1024)
            field_name: Field name for error messages
            
        Returns:
            Validated port number
            
        Raises:
            ValidationError: If validation fails
        """
        try:
            port_num = InputValidators.validate_int(
                port,
                min_val=1,
                max_val=65535,
                field_name=field_name
            )
        except ValidationError as e:
            raise ValidationError(
                "Invalid port number",
                field_name,
                port
            ) from e
            
        if not allow_privileged and port_num < 1024:
            raise ValidationError(
                "Privileged ports require explicit permission",
                field_name,
                port
            )
            
        return port_num

class SecurityValidators:
    """Security-focused validation checks"""
    
    @staticmethod
    def validate_no_injection(value: str, field_name: str = None) -> str:
        """
        Validate input contains no injection patterns
        
        Args:
            value: Input to check
            field_name: Field name for error messages
            
        Returns:
            Sanitized value if safe
            
        Raises:
            ValidationError: If injection patterns detected
        """
        patterns = [
            r'[\s]*(union|select|insert|update|delete|drop|alter)[\s]+',
            r'<script.*?>.*?</script>',
            r'(\|\||&&)\s*\w+\(.*\)',
            r'\.\./\.\./',
            r'[\x00-\x1f\x7f-\x9f]'
        ]
        
        sanitized = value.strip()
        for pattern in patterns:
            if re.search(pattern, sanitized, re.IGNORECASE):
                raise ValidationError(
                    "Potential injection pattern detected",
                    field_name,
                    value
                )
                
        return sanitized

    @staticmethod
    def validate_password_strength(
        password: str,
        min_length: int = 12,
        field_name: str = None
    ) -> str:
        """
        Validate password meets strength requirements
        
        Args:
            password: Password to validate
            min_length: Minimum required length
            field_name: Field name for error messages
            
        Returns:
            Validated password
            
        Raises:
            ValidationError: If password is weak
        """
        if len(password) < min_length:
            raise ValidationError(
                f"Password must be at least {min_length} characters",
                field_name,
                None  # Don't echo passwords in errors
            )
            
        checks = {
            'uppercase': r'[A-Z]',
            'lowercase': r'[a-z]',
            'digit': r'[0-9]',
            'special': r'[^A-Za-z0-9]'
        }
        
        missing = []
        for name, pattern in checks.items():
            if not re.search(pattern, password):
                missing.append(name)
                
        if missing:
            raise ValidationError(
                f"Password missing required characters: {', '.join(missing)}",
                field_name,
                None
            )
            
        return password

    @staticmethod
    def validate_api_key(
        key: str,
        expected_prefix: Optional[str] = None,
        expected_length: Optional[int] = None,
        field_name: str = None
    ) -> str:
        """
        Validate API key format
        
        Args:
            key: API key to validate
            expected_prefix: Expected key prefix (e.g., 'sk_live_')
            expected_length: Expected key length
            field_name: Field name for error messages
            
        Returns:
            Validated key
            
        Raises:
            ValidationError: If key is invalid
        """
        sanitized = key.strip()
        if not sanitized:
            raise ValidationError(
                "API key cannot be empty",
                field_name,
                None
            )
            
        if expected_prefix and not sanitized.startswith(expected_prefix):
            raise ValidationError(
                f"API key must start with {expected_prefix}",
                field_name,
                None
            )
            
        if expected_length and len(sanitized) != expected_length:
            raise ValidationError(
                f"API key must be {expected_length} characters",
                field_name,
                None
            )
            
        return sanitized

class ProtocolValidators:
    """Protocol-specific validation utilities"""
    
    @staticmethod
    def validate_url(
        url: str,
        allowed_schemes: Tuple[str, ...] = ('http', 'https'),
        field_name: str = None
    ) -> urllib.parse.ParseResult:
        """
        Validate URL with security constraints
        
        Args:
            url: URL to validate
            allowed_schemes: Tuple of allowed schemes
            field_name: Field name for error messages
            
        Returns:
            Parsed URL components
            
        Raises:
            ValidationError: If URL is invalid
        """
        try:
            result = urllib.parse.urlparse(url)
            if not all([result.scheme, result.netloc]):
                raise ValidationError(
                    "Invalid URL format",
                    field_name,
                    url
                )
                
            if result.scheme not in allowed_schemes:
                raise ValidationError(
                    f"URL scheme must be one of: {', '.join(allowed_schemes)}",
                    field_name,
                    url
                )
                
            # Validate hostname component
            NetworkValidators.validate_hostname(result.hostname, field_name=field_name)
            
            return result
        except ValueError as e:
            raise ValidationError(
                f"Invalid URL: {str(e)}",
                field_name,
                url
            ) from e

    @staticmethod
    def validate_email(
        email: str,
        verify_dns: bool = False,
        field_name: str = None
    ) -> str:
        """
        Validate email address format with optional DNS verification
        
        Args:
            email: Email address to validate
            verify_dns: Whether to verify MX records exist
            field_name: Field name for error messages
            
        Returns:
            Normalized email address
            
        Raises:
            ValidationError: If email is invalid
        """
        try:
            local_part, domain = email.rsplit('@', 1)
        except ValueError:
            raise ValidationError(
                "Invalid email format",
                field_name,
                email
            )
            
        # Validate local part
        if not re.match(r'^[a-z0-9.!#$%&\'*+/=?^_`{|}~-]+$', local_part, re.IGNORECASE):
            raise ValidationError(
                "Invalid email local part",
                field_name,
                email
            )
            
        # Validate domain
        try:
            norm_domain = NetworkValidators.validate_hostname(domain, field_name=field_name)
        except ValidationError as e:
            raise ValidationError(
                "Invalid email domain",
                field_name,
                email
            ) from e
            
        if verify_dns:
            try:
                dns.resolver.resolve(norm_domain, 'MX')
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
                raise ValidationError(
                    "Email domain has no MX records",
                    field_name,
                    email
                )
                
        return f"{local_part}@{norm_domain}"

# Common validator exports
validate_str = InputValidators.validate_str
validate_int = InputValidators.validate_int
validate_ip = NetworkValidators.validate_ip
validate_hostname = NetworkValidators.validate_hostname
validate_url = ProtocolValidators.validate_url
validate_email = ProtocolValidators.validate_email
validate_no_injection = SecurityValidators.validate_no_injection