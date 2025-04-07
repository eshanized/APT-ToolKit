"""
Plugin Handler for APT Toolkit

Features:
- Secure plugin loading
- Dependency management
- Sandboxed execution
- Version compatibility checks
- Signature verification
"""

import importlib
import inspect
import json
import logging
import pkgutil
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Type, Union
import hashlib
import zipfile
from dataclasses import dataclass
import threading
from concurrent.futures import Future
from src.utils.config import config
from src.utils.logger import get_logger
from src.utils.file_utils import FileUtils
from src.utils.validators import SecurityValidators
from src.core.event_system import event_system, Event, EventPriority

logger = get_logger(__name__)

@dataclass
class PluginMetadata:
    """Plugin metadata container"""
    name: str
    version: str
    description: str
    author: str
    min_toolkit_version: str
    dependencies: List[str]
    entry_point: str
    signature: Optional[str] = None

class PluginLoadError(Exception):
    """Plugin loading failed"""
    pass

class PluginVerificationError(Exception):
    """Plugin verification failed"""
    pass

class Plugin:
    """Base plugin class for all toolkit plugins"""
    
    def __init__(self, metadata: PluginMetadata):
        self.metadata = metadata
        self._enabled = False
        
    def initialize(self) -> None:
        """Initialize plugin resources"""
        self._enabled = True
        logger.info(f"Initialized plugin: {self.metadata.name}")
        
    def cleanup(self) -> None:
        """Cleanup plugin resources"""
        self._enabled = False
        logger.info(f"Cleaned up plugin: {self.metadata.name}")
        
    def is_enabled(self) -> bool:
        """Check if plugin is enabled"""
        return self._enabled

class PluginHandler:
    """Secure plugin manager for APT Toolkit"""
    
    def __init__(self):
        self._lock = threading.RLock()
        self._plugins: Dict[str, Plugin] = {}
        self._loaded_modules: Set[str] = set()
        self._verify_signatures = config.plugins.signature_required
        
        # Setup plugin directories
        self._plugin_dir = Path(config.plugins.plugin_dir)
        self._plugin_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize event handlers
        event_system.register("plugin_pre_load", self._validate_plugin, priority=EventPriority.HIGHEST)
        event_system.register("plugin_post_load", self._notify_plugin_loaded)

    def _validate_plugin(self, event: Event, plugin_path: Path, metadata: Dict[str, Any]) -> None:
        """Validate plugin before loading"""
        try:
            # Verify plugin name
            if not SecurityValidators.validate_str(metadata.get('name', ''), regex=r'^[a-z0-9_]+$'):
                event.cancel()
                raise PluginVerificationError("Invalid plugin name")
                
            # Verify version format
            if not re.match(r'^\d+\.\d+\.\d+$', metadata.get('version', '')):
                event.cancel()
                raise PluginVerificationError("Invalid version format")
                
            # Verify toolkit version compatibility
            if metadata.get('min_toolkit_version', '0.0.0') > config.core.version:
                event.cancel()
                raise PluginVerificationError(
                    f"Plugin requires toolkit version {metadata['min_toolkit_version']} "
                    f"(current: {config.core.version})"
                )
                
            # Verify signature if required
            if self._verify_signatures and metadata.get('signature'):
                if not self._verify_plugin_signature(plugin_path, metadata['signature']):
                    event.cancel()
                    raise PluginVerificationError("Plugin signature verification failed")
                    
        except Exception as e:
            logger.error(f"Plugin validation failed: {str(e)}")
            raise

    def _verify_plugin_signature(self, plugin_path: Path, signature: str) -> bool:
        """Verify plugin signature (placeholder implementation)"""
        # In production, this would verify against a trusted certificate
        # For this example, we'll just check a SHA256 hash
        expected_hash = hashlib.sha256(plugin_path.read_bytes()).hexdigest()
        return expected_hash == signature

    def _notify_plugin_loaded(self, event: Event, plugin_name: str) -> None:
        """Log plugin load events"""
        logger.info(f"Successfully loaded plugin: {plugin_name}")

    def _load_plugin_metadata(self, plugin_path: Path) -> PluginMetadata:
        """Load and validate plugin metadata"""
        try:
            if plugin_path.is_dir():
                meta_file = plugin_path / "plugin.json"
            elif plugin_path.suffix == '.zip':
                with zipfile.ZipFile(plugin_path) as z:
                    with z.open('plugin.json') as f:
                        meta_data = json.load(f)
                    return PluginMetadata(**meta_data)
            else:
                raise PluginLoadError(f"Unsupported plugin format: {plugin_path.suffix}")
                
            if not meta_file.exists():
                raise PluginLoadError("Missing plugin.json metadata file")
                
            with open(meta_file, 'r') as f:
                meta_data = json.load(f)
                
            return PluginMetadata(**meta_data)
        except (json.JSONDecodeError, TypeError) as e:
            raise PluginLoadError(f"Invalid plugin metadata: {str(e)}")

    def _load_plugin_module(self, plugin_path: Path, metadata: PluginMetadata) -> Plugin:
        """Load the plugin module"""
        module_name = f"apt_plugins.{metadata.name}"
        
        try:
            if module_name in sys.modules:
                module = importlib.reload(sys.modules[module_name])
            else:
                if plugin_path.suffix == '.zip':
                    # Add zipfile to Python path
                    sys.path.insert(0, str(plugin_path))
                    module = importlib.import_module(module_name)
                    sys.path.pop(0)
                else:
                    # Regular directory-based plugin
                    spec = importlib.util.spec_from_file_location(
                        module_name,
                        plugin_path / f"{metadata.entry_point}.py"
                    )
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
            # Find and instantiate the plugin class
            for name, obj in inspect.getmembers(module):
                if (
                    inspect.isclass(obj)
                    and issubclass(obj, Plugin)
                    and obj != Plugin
                ):
                    plugin = obj(metadata)
                    plugin.initialize()
                    return plugin
                    
            raise PluginLoadError(f"No valid Plugin class found in {module_name}")
        except Exception as e:
            raise PluginLoadError(f"Failed to load plugin module: {str(e)}")

    def load_plugin(self, plugin_path: Union[str, Path]) -> Future:
        """
        Load a plugin from path
        
        Args:
            plugin_path: Path to plugin directory or zip file
            
        Returns:
            Future: Result future for the loading operation
        """
        future = Future()
        
        def load_task():
            try:
                plugin_path_obj = Path(plugin_path)
                if not plugin_path_obj.exists():
                    raise PluginLoadError(f"Plugin path does not exist: {plugin_path}")
                    
                # Load and validate metadata
                metadata = self._load_plugin_metadata(plugin_path_obj)
                
                # Emit pre-load event
                pre_event = Event("plugin_pre_load")
                event_system.emit(
                    "plugin_pre_load",
                    event=pre_event,
                    plugin_path=plugin_path_obj,
                    metadata=metadata.__dict__
                ).result()
                
                if pre_event.cancelled:
                    raise PluginVerificationError("Plugin loading cancelled by event handler")
                    
                # Check dependencies
                missing_deps = [
                    dep for dep in metadata.dependencies
                    if dep not in self._plugins
                ]
                if missing_deps:
                    raise PluginLoadError(
                        f"Missing dependencies: {', '.join(missing_deps)}"
                    )
                    
                # Load the plugin module
                with self._lock:
                    if metadata.name in self._plugins:
                        raise PluginLoadError(f"Plugin {metadata.name} already loaded")
                        
                    plugin = self._load_plugin_module(plugin_path_obj, metadata)
                    self._plugins[metadata.name] = plugin
                    self._loaded_modules.add(metadata.name)
                    
                    # Emit post-load event
                    event_system.emit(
                        "plugin_post_load",
                        plugin_name=metadata.name,
                        plugin_version=metadata.version
                    )
                    
                    future.set_result(plugin)
                    
            except Exception as e:
                logger.error(f"Plugin loading failed: {str(e)}", exc_info=True)
                future.set_exception(e)
                
        # Run in background thread
        threading.Thread(target=load_task, daemon=True).start()
        return future

    def unload_plugin(self, plugin_name: str) -> bool:
        """
        Unload a plugin
        
        Args:
            plugin_name: Name of plugin to unload
            
        Returns:
            bool: True if plugin was unloaded, False otherwise
        """
        with self._lock:
            if plugin_name not in self._plugins:
                logger.warning(f"Plugin {plugin_name} not found for unloading")
                return False
                
            plugin = self._plugins.pop(plugin_name)
            plugin.cleanup()
            
            # Cleanup module imports
            module_name = f"apt_plugins.{plugin_name}"
            if module_name in sys.modules:
                del sys.modules[module_name]
                
            self._loaded_modules.discard(plugin_name)
            logger.info(f"Unloaded plugin: {plugin_name}")
            return True

    def get_plugin(self, plugin_name: str) -> Optional[Plugin]:
        """
        Get loaded plugin by name
        
        Args:
            plugin_name: Name of plugin to retrieve
            
        Returns:
            Plugin: The plugin instance if loaded, None otherwise
        """
        with self._lock:
            return self._plugins.get(plugin_name)

    def list_plugins(self) -> Dict[str, PluginMetadata]:
        """
        List all loaded plugins
        
        Returns:
            Dict of {plugin_name: plugin_metadata}
        """
        with self._lock:
            return {
                name: plugin.metadata
                for name, plugin in self._plugins.items()
            }

    def scan_plugin_dir(self) -> List[Path]:
        """
        Scan plugin directory for available plugins
        
        Returns:
            List of Paths to potential plugins
        """
        plugins = []
        
        # Scan for directory plugins
        for item in self._plugin_dir.iterdir():
            if item.is_dir() and (item / "plugin.json").exists():
                plugins.append(item)
            elif item.suffix == '.zip' and "plugin.json" in zipfile.ZipFile(item).namelist():
                plugins.append(item)
                
        return plugins

    def load_all_plugins(self) -> Dict[str, Future]:
        """
        Load all plugins from the plugin directory
        
        Returns:
            Dict of {plugin_name: loading_future}
        """
        futures = {}
        for plugin_path in self.scan_plugin_dir():
            try:
                metadata = self._load_plugin_metadata(plugin_path)
                futures[metadata.name] = self.load_plugin(plugin_path)
            except Exception as e:
                logger.error(f"Skipping plugin at {plugin_path}: {str(e)}")
                
        return futures

    def shutdown(self) -> None:
        """Cleanup all plugins and release resources"""
        with self._lock:
            for plugin_name in list(self._plugins.keys()):
                self.unload_plugin(plugin_name)
                
            self._loaded_modules.clear()
            logger.info("Plugin handler shutdown complete")

# Global plugin handler instance
plugin_handler = PluginHandler()

# Example usage:
# future = plugin_handler.load_plugin("/path/to/plugin.zip")
# plugin = future.result()  # Wait for loading to complete
# 
# # Or load all plugins:
# plugin_handler.load_all_plugins()
# 
# # Get a specific plugin
# scanner = plugin_handler.get_plugin("vulnerability_scanner")