"""
Version and package metadata for APT Toolkit

Follows Semantic Versioning (https://semver.org/)
"""

__title__ = "apt-toolkit"
__description__ = "Automated Penetration Testing Toolkit"
__author__ = "Eshan Roy"
__license__ = "GPL-3.0"
__copyright__ = "Copyright 2025, Eshan Roy"

# Version tuple (major, minor, patch)
VERSION_INFO = (1, 0, 0)

# String version
__version__ = '.'.join(map(str, VERSION_INFO))

# Version suffix for pre-releases (alpha/beta/rc)
VERSION_SUFFIX = ""

# Full version string
__full_version__ = __version__ + VERSION_SUFFIX

# Package dependencies (core requirements)
__dependencies__ = [
    'PyQt6>=6.4.0',
    'python-nmap>=0.7.1',
    'requests>=2.28.0'
]

def get_version() -> str:
    """Get the full version string with suffix (if any)"""
    return __full_version__

def check_compatibility(required_version: str) -> bool:
    """
    Check if current version meets required version
    Args:
        required_version: Version string to compare against (e.g., "1.2.0")
    Returns:
        bool: True if current version >= required version
    """
    current = tuple(map(int, __version__.split('.')))
    required = tuple(map(int, required_version.split('.')))
    return current >= required

if __name__ == "__main__":
    print(f"{__title__} v{get_version()}")
    print(f"License: {__license__}")
    print(f"Author: {__author__}")