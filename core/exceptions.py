"""
Custom exceptions for AutoTest framework.
"""


class AutoTestException(Exception):
    """Base exception for all AutoTest errors."""
    pass


class ConfigurationError(AutoTestException):
    """Raised when there's an error in configuration."""
    pass


class DiscoveryError(AutoTestException):
    """Raised when there's an error during discovery operations."""
    pass


class ValidationError(AutoTestException):
    """Raised when input validation fails."""
    pass


class TaskError(AutoTestException):
    """Raised when there's an error in task execution."""
    pass


class NetworkError(AutoTestException):
    """Raised when there's a network-related error."""
    pass


class ToolError(AutoTestException):
    """Raised when there's an error with external tool execution."""
    pass


class OutputError(AutoTestException):
    """Raised when there's an error with output generation."""
    pass


class TimeoutError(AutoTestException):
    """Raised when an operation times out."""
    pass


class PermissionError(AutoTestException):
    """Raised when there's a permission-related error."""
    pass