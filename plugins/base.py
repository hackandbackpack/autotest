"""Base plugin interface and registry for AutoTest framework."""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Dict, Type, Optional, Any, List
import logging

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
        logger.info(f"Registered plugin: {plugin_name}")
    
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