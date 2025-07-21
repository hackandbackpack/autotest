"""
Configuration management for AutoTest framework.
"""

import os
import json
from typing import Dict, Any, Optional
from pathlib import Path
from .exceptions import ConfigurationError


class Config:
    """
    Configuration manager for AutoTest.
    
    Handles loading, validation, and access to configuration settings.
    """
    
    # Default configuration values
    DEFAULTS = {
        # General settings
        "output_dir": "output",
        "log_level": "INFO",
        "max_threads": 10,
        "timeout": 30,
        
        # Discovery settings
        "discovery": {
            "ping_timeout": 1,
            "port_scan_timeout": 1,
            "default_ports": "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080",
            "fast_scan_ports": "22,80,443,445,3389,8080",
            "max_concurrent_hosts": 100,
            "max_concurrent_ports": 1000
        },
        
        # Tool settings
        "tools": {
            "nmap": {
                "enabled": True,
                "path": "nmap",
                "default_args": "-sV -sC",
                "timeout_multiplier": 2
            },
            "nikto": {
                "enabled": True,
                "path": "nikto",
                "default_args": "-h",
                "timeout_multiplier": 3
            },
            "dirb": {
                "enabled": True,
                "path": "dirb",
                "wordlist": "/usr/share/wordlists/dirb/common.txt",
                "timeout_multiplier": 3
            },
            "sqlmap": {
                "enabled": True,
                "path": "sqlmap",
                "default_args": "--batch --random-agent",
                "timeout_multiplier": 4
            },
            "hydra": {
                "enabled": True,
                "path": "hydra",
                "default_args": "-V",
                "timeout_multiplier": 3
            }
        },
        
        # Output settings
        "output": {
            "format": "json",
            "pretty_print": True,
            "include_timestamps": True,
            "save_raw_output": False,
            "compress": False
        },
        
        # Security settings
        "security": {
            "verify_ssl": True,
            "follow_redirects": True,
            "max_redirects": 10,
            "user_agent": "AutoTest/1.0"
        },
        
        # Performance settings
        "performance": {
            "chunk_size": 1024,
            "buffer_size": 8192,
            "max_retries": 3,
            "retry_delay": 1
        }
    }
    
    def __init__(self, config_file: Optional[str] = None):
        """
        Initialize configuration.
        
        Args:
            config_file: Path to configuration file (optional)
        """
        self._config = self.DEFAULTS.copy()
        self._config_file = config_file
        
        if config_file:
            self.load_from_file(config_file)
        
        # Load from environment variables
        self._load_from_env()
    
    def load_from_file(self, filepath: str) -> None:
        """
        Load configuration from a JSON file.
        
        Args:
            filepath: Path to configuration file
            
        Raises:
            ConfigurationError: If file cannot be loaded or parsed
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                user_config = json.load(f)
            
            # Merge with defaults
            self._merge_config(self._config, user_config)
            
        except FileNotFoundError:
            raise ConfigurationError(f"Configuration file not found: {filepath}")
        except json.JSONDecodeError as e:
            raise ConfigurationError(f"Invalid JSON in configuration file: {e}")
        except Exception as e:
            raise ConfigurationError(f"Error loading configuration: {e}")
    
    def _merge_config(self, base: Dict[str, Any], update: Dict[str, Any]) -> None:
        """
        Recursively merge configuration dictionaries.
        
        Args:
            base: Base configuration dictionary
            update: Update configuration dictionary
        """
        for key, value in update.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge_config(base[key], value)
            else:
                base[key] = value
    
    def _load_from_env(self) -> None:
        """Load configuration from environment variables."""
        # Map environment variables to configuration keys
        env_mapping = {
            "AUTOTEST_OUTPUT_DIR": "output_dir",
            "AUTOTEST_LOG_LEVEL": "log_level",
            "AUTOTEST_MAX_THREADS": ("max_threads", int),
            "AUTOTEST_TIMEOUT": ("timeout", int),
            "AUTOTEST_PING_TIMEOUT": ("discovery.ping_timeout", int),
            "AUTOTEST_PORT_SCAN_TIMEOUT": ("discovery.port_scan_timeout", int),
        }
        
        for env_var, config_key in env_mapping.items():
            value = os.environ.get(env_var)
            if value is not None:
                if isinstance(config_key, tuple):
                    config_key, converter = config_key
                    try:
                        value = converter(value)
                    except ValueError:
                        continue
                
                # Handle nested keys
                if '.' in config_key:
                    keys = config_key.split('.')
                    target = self._config
                    for key in keys[:-1]:
                        target = target.setdefault(key, {})
                    target[keys[-1]] = value
                else:
                    self._config[config_key] = value
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get a configuration value.
        
        Args:
            key: Configuration key (supports dot notation for nested keys)
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        keys = key.split('.')
        value = self._config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any) -> None:
        """
        Set a configuration value.
        
        Args:
            key: Configuration key (supports dot notation for nested keys)
            value: Value to set
        """
        keys = key.split('.')
        target = self._config
        
        for k in keys[:-1]:
            target = target.setdefault(k, {})
        
        target[keys[-1]] = value
    
    def save(self, filepath: Optional[str] = None) -> None:
        """
        Save configuration to a file.
        
        Args:
            filepath: Path to save configuration (uses loaded file if not specified)
            
        Raises:
            ConfigurationError: If save fails
        """
        save_path = filepath or self._config_file
        if not save_path:
            raise ConfigurationError("No filepath specified for saving configuration")
        
        try:
            # Ensure directory exists
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            
            with open(save_path, 'w', encoding='utf-8') as f:
                json.dump(self._config, f, indent=2, ensure_ascii=False)
                
        except Exception as e:
            raise ConfigurationError(f"Error saving configuration: {e}")
    
    def validate(self) -> None:
        """
        Validate configuration values.
        
        Raises:
            ConfigurationError: If configuration is invalid
        """
        # Validate required settings
        if self.get("max_threads", 0) < 1:
            raise ConfigurationError("max_threads must be at least 1")
        
        if self.get("timeout", 0) < 1:
            raise ConfigurationError("timeout must be at least 1 second")
        
        # Validate output directory
        output_dir = self.get("output_dir")
        if not output_dir:
            raise ConfigurationError("output_dir cannot be empty")
        
        # Validate log level
        valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.get("log_level") not in valid_log_levels:
            raise ConfigurationError(f"Invalid log_level. Must be one of: {valid_log_levels}")
        
        # Validate tool paths if enabled
        tools = self.get("tools", {})
        for tool_name, tool_config in tools.items():
            if tool_config.get("enabled", False):
                tool_path = tool_config.get("path")
                if not tool_path:
                    raise ConfigurationError(f"Path not specified for enabled tool: {tool_name}")
    
    def get_tool_config(self, tool_name: str) -> Dict[str, Any]:
        """
        Get configuration for a specific tool.
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            Tool configuration dictionary
        """
        return self.get(f"tools.{tool_name}", {})
    
    def is_tool_enabled(self, tool_name: str) -> bool:
        """
        Check if a tool is enabled.
        
        Args:
            tool_name: Name of the tool
            
        Returns:
            True if tool is enabled, False otherwise
        """
        return self.get(f"tools.{tool_name}.enabled", False)
    
    def get_output_path(self, filename: str) -> str:
        """
        Get full path for an output file.
        
        Args:
            filename: Name of the output file
            
        Returns:
            Full path to output file
        """
        output_dir = self.get("output_dir", "output")
        return os.path.join(output_dir, filename)
    
    def __repr__(self) -> str:
        """String representation of configuration."""
        return f"Config(file={self._config_file})"


# Global configuration instance
_config: Optional[Config] = None


def get_config() -> Config:
    """
    Get the global configuration instance.
    
    Returns:
        Global Config instance
    """
    global _config
    if _config is None:
        _config = Config()
    return _config


def set_config(config: Config) -> None:
    """
    Set the global configuration instance.
    
    Args:
        config: Config instance to set as global
    """
    global _config
    _config = config