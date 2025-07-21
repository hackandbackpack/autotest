"""Service plugins for AutoTest framework."""

from .smb import SMBPlugin
from .rdp import RDPPlugin

__all__ = ['SMBPlugin', 'RDPPlugin']