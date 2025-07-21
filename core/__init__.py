"""
AutoTest Core Module

This module provides the core functionality for the AutoTest network penetration testing framework.
"""

from .exceptions import (
    AutoTestException,
    ConfigurationError,
    DiscoveryError,
    ValidationError,
    TaskError
)

from .utils import (
    validate_ip,
    validate_port,
    validate_cidr,
    parse_port_range,
    is_private_ip,
    get_timestamp,
    format_duration,
    sanitize_filename,
    create_directory,
    load_json_file,
    save_json_file
)

from .config import Config, get_config
from .input_parser import InputParser
from .discovery import Discovery
from .task_manager import TaskManager
from .output import OutputManager

__all__ = [
    # Exceptions
    'AutoTestException',
    'ConfigurationError',
    'DiscoveryError',
    'ValidationError',
    'TaskError',
    
    # Utilities
    'validate_ip',
    'validate_port',
    'validate_cidr',
    'parse_port_range',
    'is_private_ip',
    'get_timestamp',
    'format_duration',
    'sanitize_filename',
    'create_directory',
    'load_json_file',
    'save_json_file',
    
    # Core Classes
    'Config',
    'get_config',
    'InputParser',
    'Discovery',
    'TaskManager',
    'OutputManager'
]

__version__ = '1.0.0'