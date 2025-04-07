"""
Configuration loader and validator for APT Toolkit

Handles:
- YAML configuration loading
- Environment variable overrides
- Runtime validation
- Sensitive value encryption
"""

import os
import logging
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
import yaml
from pydantic import BaseModel, ValidationError, validator, Field
from cryptography.fernet import Fernet
import dotenv

# Initialize logging
logger = logging.getLogger(__name__)

class SecurityConfig(BaseModel):
    """Security-related configuration model"""
    encryption_key: str = Field(..., min_length=32)
    api_keys: Dict[str, str]
    credential_storage: str = Field(..., regex="^(vault|aws_secrets|file)$")
    
    @validator('encryption_key')
    def validate_encryption_key(cls, v):
        if v == "CHANGE_ME_IN_PRODUCTION":
            raise ValueError("Default encryption key must be changed in production")
        return v

class CoreConfig(BaseModel):
    """Core system configuration"""
    max_threads: int = Field(..., gt=0, le=100)
    max_processes: int = Field(..., gt=0, le=10)
    task_timeout: int = Field(..., gt=0)
    unsafe_operations: bool = False

class NetworkConfig(BaseModel):
    """Network scanning configuration"""
    default_ports: str
    scan_speed: str = Field(..., regex="^T[0-5]$")
    proxy_enabled: bool = False
    proxy_http: Optional[str]
    proxy_https: Optional[str]

class AppConfig(BaseModel):
    """Main application configuration model"""
    core: CoreConfig
    security: SecurityConfig
    network: NetworkConfig
    # Additional models can be added here

class ConfigLoader:
    """Secure configuration loader with validation"""
    
    def __init__(self):
        self.base_dir = Path(__file__).resolve().parent.parent
        self.config_path = self.base_dir / "config" / "default.yaml"
        self._config = None
        self._fernet = None
        
    def load(self) -> AppConfig:
        """Load and validate configuration"""
        try:
            # Load environment variables first
            dotenv.load_dotenv(self.base_dir / ".env")
            
            # Read YAML config
            raw_config = self._read_config_file()
            
            # Apply environment overrides
            self._apply_env_overrides(raw_config)
            
            # Validate configuration
            self._config = AppConfig(**raw_config)
            
            # Initialize encryption
            self._init_encryption()
            
            return self._config
            
        except (yaml.YAMLError, ValidationError) as e:
            logger.critical(f"Configuration error: {str(e)}")
            raise RuntimeError("Invalid configuration") from e

    def _read_config_file(self) -> Dict[str, Any]:
        """Read and parse YAML configuration"""
        with open(self.config_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) or {}

    def _apply_env_overrides(self, config: Dict[str, Any]):
        """Override config values from environment variables"""
        if 'security' in config:
            for key in ['shodan', 'virustotal']:
                env_key = f"APT_{key.upper()}_KEY"
                if env_key in os.environ:
                    config['security']['api_keys'][key] = os.environ[env_key]

    def _init_encryption(self):
        """Initialize encryption handler"""
        if self._config.security.encryption_key:
            key = self._config.security.encryption_key.encode()
            self._fernet = Fernet(Fernet.generate_key() if key == b"CHANGE_ME_IN_PRODUCTION" else key)

    def encrypt_value(self, value: str) -> str:
        """Encrypt sensitive values"""
        if not self._fernet:
            raise RuntimeError("Encryption not initialized")
        return self._fernet.encrypt(value.encode()).decode()

    def decrypt_value(self, encrypted: str) -> str:
        """Decrypt sensitive values"""
        if not self._fernet:
            raise RuntimeError("Encryption not initialized")
        return self._fernet.decrypt(encrypted.encode()).decode()

    @property
    def config(self) -> AppConfig:
        """Get validated configuration"""
        if not self._config:
            raise RuntimeError("Configuration not loaded")
        return self._config

# Global configuration instance
_config_loader = ConfigLoader()
config = _config_loader.config

def init_config() -> AppConfig:
    """Initialize and return the application configuration"""
    return _config_loader.load()

def get_encryption_handler() -> Tuple[callable, callable]:
    """Get encryption/decryption functions"""
    return _config_loader.encrypt_value, _config_loader.decrypt_value

if __name__ == "__main__":
    # Test configuration loading
    try:
        cfg = init_config()
        print("Configuration loaded successfully")
        print(f"Core threads: {cfg.core.max_threads}")
    except Exception as e:
        print(f"Configuration error: {str(e)}")
        exit(1)