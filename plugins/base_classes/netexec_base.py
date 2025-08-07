"""
Base class for NetExec-based plugins (SMB, RDP, etc.)
"""

import logging
import subprocess
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path

import sys
import os
# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from plugins.base import Plugin
from core.tool_executor import NetExecExecutor

logger = logging.getLogger(__name__)


class NetExecPlugin(Plugin):
    """
    Base class for plugins that use NetExec/CrackMapExec as their primary tool.
    Provides common functionality for tool detection, command building, and output parsing.
    """
    
    # Class-level cache for NetExec executor to avoid duplicate detection
    _netexec_executor = None
    
    def __init__(self, protocol: str, default_port: int):
        """
        Initialize NetExec plugin.
        
        Args:
            protocol: Protocol name (smb, rdp, etc.)
            default_port: Default port for the protocol
        """
        super().__init__()
        self.protocol = protocol
        self.default_port = default_port
        self.required_tools = ["netexec"]
        
        # Use cached NetExec executor or create new one
        if NetExecPlugin._netexec_executor is None:
            NetExecPlugin._netexec_executor = NetExecExecutor()
        
        self.netexec_executor = NetExecPlugin._netexec_executor
        self.netexec_path = self.netexec_executor.tool_path or "netexec"
    
    def check_required_tools(self, skip_check: bool = False) -> Tuple[bool, Dict[str, Dict[str, Any]]]:
        """Check if netexec is available using custom logic."""
        if skip_check or getattr(self, 'skip_tool_check', False):
            return True, {}
        
        if self.netexec_executor.is_available():
            return True, {"netexec": {"available": True, "path": self.netexec_path}}
        
        return False, {"netexec": {
            "available": False,
            "install_command": "pipx install netexec",
            "path": None
        }}
    
    def build_base_command(self, target: str, **kwargs) -> List[str]:
        """
        Build base NetExec command with common options.
        
        Args:
            target: Target host
            **kwargs: Additional parameters (port, username, password, etc.)
            
        Returns:
            Command as a list of strings
        """
        port = kwargs.get('port', self.default_port)
        additional_args = kwargs.get('additional_args', [])
        
        # Use the executor to build command
        cmd = self.netexec_executor.build_command(
            protocol=self.protocol,
            target=target,
            port=port if port != self.default_port else None,
            username=kwargs.get('username'),
            password=kwargs.get('password'),
            hash=kwargs.get('hash'),
            domain=kwargs.get('domain'),
            local_auth=kwargs.get('local_auth', False),
            additional_args=additional_args
        )
        
        return cmd
    
    def execute_netexec(self, cmd: List[str], timeout: int = 30, 
                       output_manager=None) -> subprocess.CompletedProcess:
        """
        Execute NetExec command with standard error handling and logging.
        
        Args:
            cmd: Command to execute
            timeout: Timeout in seconds
            output_manager: OutputManager for logging
            
        Returns:
            CompletedProcess object
        """
        try:
            result = self.netexec_executor.execute_command(cmd, timeout=timeout)
            
            # Log execution if output manager provided
            if output_manager:
                self.log_execution(cmd, result, output_manager)
            
            return result
            
        except subprocess.TimeoutExpired:
            logger.error(f"{self.protocol.upper()} scan timed out")
            raise
        except Exception as e:
            logger.error(f"{self.protocol.upper()} scan failed: {e}")
            raise
    
    def log_execution(self, cmd: List[str], result: subprocess.CompletedProcess, 
                     output_manager) -> None:
        """Log tool execution to output manager."""
        if hasattr(output_manager, 'log_tool_execution'):
            target = cmd[-1] if len(cmd) > 2 else "unknown"
            output_manager.log_tool_execution(
                tool_name="netexec",
                target=target,
                command=' '.join(cmd),
                output=result.stdout + result.stderr,
                service=self.protocol.upper()
            )
    
    def parse_connectivity_output(self, output: str) -> Dict[str, Any]:
        """
        Parse basic NetExec connectivity output.
        
        Args:
            output: NetExec output
            
        Returns:
            Parsed connectivity information
        """
        info = {
            "accessible": False,
            "hostname": None,
            "domain": None,
            "os": None,
            "signing": None
        }
        
        if not output:
            return info
        
        # Look for successful connection indicators
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # NetExec output typically has the format:
            # PROTOCOL IP:PORT HOSTNAME (domain\name) (signing:True/False) (SMBv1:True/False)
            if self.protocol.upper() in line and "(name:" in line:
                info["accessible"] = True
                
                # Extract hostname
                if "(name:" in line:
                    start = line.find("(name:") + 6
                    end = line.find(")", start)
                    if end > start:
                        info["hostname"] = line[start:end]
                
                # Extract domain
                if "(domain:" in line:
                    start = line.find("(domain:") + 8
                    end = line.find(")", start)
                    if end > start:
                        info["domain"] = line[start:end]
                
                # Extract signing info
                if "(signing:" in line:
                    if "signing:True" in line:
                        info["signing"] = "enabled"
                    elif "signing:False" in line:
                        info["signing"] = "disabled"
                
                # Extract OS info
                if "Windows" in line:
                    # Try to extract Windows version
                    import re
                    os_match = re.search(r'Windows\s+[\d.]+\s+\w+', line)
                    if os_match:
                        info["os"] = os_match.group()
        
        return info
    
    def create_finding(self, finding_type: str, severity: str, title: str,
                      description: str, **kwargs) -> Dict[str, Any]:
        """
        Create a standardized finding dictionary.
        
        Args:
            finding_type: Type identifier for the finding
            severity: Severity level (critical, high, medium, low, info)
            title: Human-readable title
            description: Detailed description
            **kwargs: Additional finding properties
            
        Returns:
            Standardized finding dictionary
        """
        finding = {
            'type': finding_type,
            'severity': severity,
            'title': title,
            'description': description,
            'service': self.protocol.upper()
        }
        
        # Add any additional properties
        finding.update(kwargs)
        
        return finding
    
    def check_authentication_success(self, output: str) -> bool:
        """
        Check if authentication was successful based on output.
        
        Args:
            output: NetExec output
            
        Returns:
            True if authentication succeeded
        """
        success_indicators = [
            "(Pwn3d!)",
            "STATUS_SUCCESS",
            "[+]",
            "Administrator"
        ]
        
        return any(indicator in output for indicator in success_indicators)