"""Base plugin classes for AutoTest framework."""

from .netexec_base import NetExecPlugin
from .tool_mixin import ToolDetectionMixin

__all__ = ['NetExecPlugin', 'ToolDetectionMixin']