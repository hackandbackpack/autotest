"""Base plugin interface and registry for AutoTest framework."""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Dict, Type, Optional, Any, List, Tuple, Union
from pathlib import Path
import logging
import sys
import os
import subprocess

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath((__file__ if "__file__" in globals() else ".")))))
from core.utils import ToolChecker
from core.tool_executor import ToolExecutor

logger = logging.getLogger(__name__)


class PluginType(Enum):
    """Plugin type enumeration."""
    SERVICE = "service"
    TOOL = "tool"
    REPORT = "report"
    EXPLOIT = "exploit"


class Plugin(ABC):
    """Base abstract class for all AutoTest plugins."""
    
    def __init__(self):
        """Initialize plugin with basic attributes."""
        self.name = self.__class__.__name__
        self.version = "1.0.0"
        self.author = "AutoTest Framework"
        self.description = "Base plugin"
        self.type = PluginType.SERVICE
        self.required_tools = []  # List of required external tools
        self.skip_tool_check = False  # Can be set to skip tool checks
        self.output_manager = None  # Will be set by framework after instantiation
        
    @abstractmethod
    def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute the plugin functionality.
        
        Args:
            target: Target host or network
            **kwargs: Additional plugin-specific arguments
            
        Returns:
            Dictionary containing execution results
        """
        pass
    
    @abstractmethod
    def validate_params(self, **kwargs) -> bool:
        """Validate plugin parameters before execution.
        
        Args:
            **kwargs: Plugin-specific parameters to validate
            
        Returns:
            True if parameters are valid, False otherwise
        """
        pass
    
    def get_info(self) -> Dict[str, str]:
        """Get plugin information.
        
        Returns:
            Dictionary containing plugin metadata
        """
        return {
            "name": self.name,
            "version": self.version,
            "author": self.author,
            "description": self.description,
            "type": self.type.value
        }
    
    def get_required_params(self) -> List[str]:
        """Get list of required parameters for the plugin.
        
        Returns:
            List of required parameter names
        """
        return []
    
    def get_optional_params(self) -> Dict[str, Any]:
        """Get optional parameters with their default values.
        
        Returns:
            Dictionary of optional parameters and defaults
        """
        return {}
    
    def cleanup(self) -> None:
        """
        Cleanup any temporary files or resources created by the plugin.
        
        This method is called after plugin execution to ensure proper cleanup.
        Override this method in plugin implementations to add custom cleanup logic.
        """
        if hasattr(self, '_temp_files'):
            for temp_file in getattr(self, '_temp_files', []):
                try:
                    if isinstance(temp_file, (str, Path)):
                        temp_path = Path(temp_file)
                        if temp_path.exists():
                            temp_path.unlink()
                except Exception as e:
                    logger.debug(f"Error cleaning up temporary file {temp_file}: {e}")
            self._temp_files = []
    
    def _register_temp_file(self, file_path: Union[str, Path]) -> None:
        """
        Register a temporary file for automatic cleanup.
        
        Args:
            file_path: Path to temporary file
        """
        if not hasattr(self, '_temp_files'):
            self._temp_files = []
        self._temp_files.append(file_path)
    
    def check_required_tools(self, skip_check: bool = False) -> Tuple[bool, Dict[str, Dict[str, Any]]]:
        """Check if required tools are available.
        
        Args:
            skip_check: If True, skip the tool check
            
        Returns:
            Tuple of (all_available, tool_status_dict)
        """
        if skip_check or self.skip_tool_check or not self.required_tools:
            return True, {}
        
        tool_status = ToolChecker.check_required_tools(self.required_tools, skip_check)
        all_available = all(status["available"] for status in tool_status.values())
        
        return all_available, tool_status
    
    def get_missing_tools(self) -> List[Dict[str, str]]:
        """Get list of missing tools with installation instructions.
        
        Returns:
            List of dictionaries with tool name and install command
        """
        _, tool_status = self.check_required_tools()
        missing_tools = []
        
        for tool_name, status in tool_status.items():
            if not status["available"]:
                missing_tools.append({
                    "name": tool_name,
                    "install_command": status["install_command"]
                })
        
        return missing_tools
    
    def execute_tool(self, cmd: List[str], timeout: int = 300, 
                    output_manager=None, service: str = None) -> subprocess.CompletedProcess:
        """
        Execute a tool command using ToolExecutor with standard logging.
        
        Args:
            cmd: Command to execute as a list
            timeout: Timeout in seconds
            output_manager: OutputManager instance for logging
            service: Service name for categorized logging
            
        Returns:
            CompletedProcess object with results
        """
        import subprocess
        import time
        
        tool_name = cmd[0] if cmd else "unknown"
        target = cmd[-1] if len(cmd) > 1 else "unknown"
        start_time = time.time()
        
        try:
            # Use ToolExecutor if we have one, otherwise fall back to subprocess
            if hasattr(self, 'tool_executor') and self.tool_executor:
                result = self.tool_executor.execute_command(cmd, timeout=timeout)
            else:
                logger.info(f"Executing command: {' '.join(cmd)}")
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            
            execution_time = time.time() - start_time
            
            # Log to output manager if provided
            if output_manager and hasattr(output_manager, 'log_tool_execution'):
                output_manager.log_tool_execution(
                    tool_name=tool_name,
                    target=target,
                    command=' '.join(cmd),
                    output=result.stdout + result.stderr,
                    service=service,
                    execution_time=execution_time
                )
            
            return result
            
        except subprocess.TimeoutExpired:
            logger.error(f"Tool {tool_name} timed out after {timeout} seconds")
            raise
        except Exception as e:
            logger.error(f"Error executing {tool_name}: {e}")
            raise
    
    def can_handle(self, service: str, port: int) -> bool:
        """Check if this plugin can handle the given service/port.
        
        Args:
            service: Service name detected
            port: Port number
            
        Returns:
            True if plugin should run for this service/port
        """
        # Default implementation - override in subclasses
        return False


class PluginRegistry:
    """Registry for managing and accessing plugins."""
    
    _instance = None
    _plugins: Dict[str, Type[Plugin]] = {}
    
    def __new__(cls):
        """Singleton pattern implementation."""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    @classmethod
    def register(cls, plugin_class: Type[Plugin], name: Optional[str] = None):
        """Register a plugin class.
        
        Args:
            plugin_class: Plugin class to register
            name: Optional custom name for the plugin
        """
        plugin_name = name or plugin_class.__name__.lower()
        cls._plugins[plugin_name] = plugin_class
        # Plugin registration logged at debug level
        logger.debug(f"Registered plugin: {plugin_name}")
    
    @classmethod
    def get_plugin(cls, name: str) -> Optional[Type[Plugin]]:
        """Get a plugin class by name.
        
        Args:
            name: Plugin name
            
        Returns:
            Plugin class or None if not found
        """
        return cls._plugins.get(name.lower())
    
    @classmethod
    def list_plugins(cls, plugin_type: Optional[PluginType] = None) -> List[str]:
        """List all registered plugins.
        
        Args:
            plugin_type: Optional filter by plugin type
            
        Returns:
            List of plugin names
        """
        if plugin_type is None:
            return list(cls._plugins.keys())
        
        filtered = []
        for name, plugin_class in cls._plugins.items():
            instance = plugin_class()
            if instance.type == plugin_type:
                filtered.append(name)
        return filtered
    
    @classmethod
    def create_plugin(cls, name: str, **kwargs) -> Optional[Plugin]:
        """Create a plugin instance by name.
        
        Args:
            name: Plugin name
            **kwargs: Arguments to pass to plugin constructor
            
        Returns:
            Plugin instance or None if not found
        """
        plugin_class = cls.get_plugin(name)
        if plugin_class:
            try:
                return plugin_class(**kwargs)
            except Exception as e:
                logger.error(f"Failed to create plugin {name}: {e}")
        return None
    
    @classmethod
    def clear(cls):
        """Clear all registered plugins."""
        cls._plugins.clear()


def plugin(name: Optional[str] = None):
    """Decorator for registering plugins.
    
    Args:
        name: Optional custom name for the plugin
        
    Returns:
        Decorator function
    """
    def decorator(plugin_class: Type[Plugin]):
        PluginRegistry.register(plugin_class, name)
        return plugin_class
    return decorator