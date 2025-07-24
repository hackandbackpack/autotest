"""
Common tool execution functionality for AutoTest plugins.
"""

import subprocess
import logging
import shutil
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
import time

logger = logging.getLogger(__name__)


class ToolExecutor:
    """
    Base class for executing external tools with common functionality
    like timeout handling, output capture, and error management.
    """
    
    def __init__(self, tool_names: List[str], install_command: str = None):
        """
        Initialize ToolExecutor.
        
        Args:
            tool_names: List of possible command names for the tool
            install_command: Command to install the tool if not found
        """
        self.tool_names = tool_names
        self.install_command = install_command
        self.tool_path = None
        self._find_tool()
    
    def _find_tool(self) -> Optional[str]:
        """
        Find the tool in PATH by trying multiple command names.
        
        Returns:
            Path to the tool executable or None if not found
        """
        for cmd in self.tool_names:
            if shutil.which(cmd):
                self.tool_path = cmd
                logger.debug(f"Found tool '{cmd}' in PATH")
                return cmd
        
        logger.warning(f"Tool not found in PATH. Tried: {', '.join(self.tool_names)}")
        return None
    
    def is_available(self) -> bool:
        """Check if the tool is available."""
        return self.tool_path is not None
    
    def execute_command(
        self,
        cmd: List[str],
        timeout: int = 300,
        capture_output: bool = True,
        check: bool = False
    ) -> subprocess.CompletedProcess:
        """
        Execute a command with standard error handling.
        
        Args:
            cmd: Command to execute as a list
            timeout: Timeout in seconds
            capture_output: Whether to capture stdout/stderr
            check: Whether to raise exception on non-zero exit
            
        Returns:
            CompletedProcess object with results
            
        Raises:
            subprocess.TimeoutExpired: If command times out
            subprocess.CalledProcessError: If check=True and command fails
        """
        logger.info(f"Executing command: {' '.join(cmd)}")
        start_time = time.time()
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=capture_output,
                text=True,
                timeout=timeout,
                check=check
            )
            
            execution_time = time.time() - start_time
            logger.debug(f"Command completed in {execution_time:.2f} seconds with return code {result.returncode}")
            
            if result.stderr and result.returncode != 0:
                logger.warning(f"Command stderr: {result.stderr}")
            
            return result
            
        except subprocess.TimeoutExpired as e:
            logger.error(f"Command timed out after {timeout} seconds")
            raise
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed with return code {e.returncode}")
            if e.stderr:
                logger.error(f"Error output: {e.stderr}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error executing command: {e}")
            raise
    
    def get_version(self) -> Optional[str]:
        """
        Try to get the tool version.
        
        Returns:
            Version string or None if unable to determine
        """
        if not self.is_available():
            return None
        
        # Try common version flags
        version_flags = ['--version', '-v', '-V', 'version']
        
        for flag in version_flags:
            try:
                result = self.execute_command(
                    [self.tool_path, flag],
                    timeout=10,
                    capture_output=True
                )
                
                if result.returncode == 0 and result.stdout:
                    # Extract first line which usually contains version
                    return result.stdout.strip().split('\n')[0]
                    
            except:
                continue
        
        return None
    
    def check_output_contains(
        self,
        output: str,
        indicators: List[str],
        min_matches: int = 1
    ) -> bool:
        """
        Check if output contains enough indicators to confirm tool identity.
        
        Args:
            output: Output to check
            indicators: List of strings to look for
            min_matches: Minimum number of indicators that must be found
            
        Returns:
            True if enough indicators are found
        """
        output_lower = output.lower()
        matches = sum(1 for indicator in indicators if indicator.lower() in output_lower)
        return matches >= min_matches
    
    def get_install_instructions(self) -> str:
        """
        Get installation instructions for the tool.
        
        Returns:
            Installation instructions string
        """
        if self.install_command:
            return f"Install with: {self.install_command}"
        else:
            return f"Please install one of: {', '.join(self.tool_names)}"
    
    def parse_output_lines(
        self,
        output: str,
        skip_patterns: List[str] = None,
        stop_patterns: List[str] = None
    ) -> List[str]:
        """
        Parse output into lines with filtering.
        
        Args:
            output: Raw output string
            skip_patterns: Patterns to skip lines
            stop_patterns: Stop processing if these patterns are found
            
        Returns:
            List of processed lines
        """
        if not output:
            return []
        
        skip_patterns = skip_patterns or []
        stop_patterns = stop_patterns or []
        
        lines = []
        for line in output.splitlines():
            line = line.strip()
            
            # Check stop patterns
            if any(pattern in line for pattern in stop_patterns):
                break
            
            # Skip empty lines and patterns
            if not line:
                continue
            
            if any(pattern in line for pattern in skip_patterns):
                continue
            
            lines.append(line)
        
        return lines


class NetExecExecutor(ToolExecutor):
    """
    Specialized executor for NetExec/CrackMapExec tools with
    common detection and execution logic.
    """
    
    def __init__(self):
        """Initialize NetExec executor."""
        super().__init__(
            tool_names=['netexec', 'nxc'],
            install_command='pipx install netexec'
        )
    
    def _find_tool(self) -> Optional[str]:
        """
        Find NetExec with enhanced detection to avoid false positives.
        """
        for cmd in self.tool_names:
            try:
                # Run without arguments - netexec shows help/usage
                result = subprocess.run(
                    [cmd],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                
                # Check both stdout and stderr for netexec indicators
                combined_output = (result.stdout + result.stderr).lower()
                
                # Look for netexec-specific strings
                indicators = ["netexec", "nxc", "network execution tool", "smoothoperator", "neffisback"]
                found_indicators = sum(1 for ind in indicators if ind in combined_output)
                
                if found_indicators >= 2:
                    self.tool_path = cmd
                    logger.info(f"Found netexec as '{cmd}'")
                    return cmd
                    
            except (FileNotFoundError, subprocess.TimeoutExpired):
                continue
            except Exception as e:
                logger.debug(f"Error checking '{cmd}': {e}")
        
        logger.warning("netexec not found in PATH")
        return None
    
    def build_command(
        self,
        protocol: str,
        target: str,
        port: Optional[int] = None,
        username: Optional[str] = None,
        password: Optional[str] = None,
        hash: Optional[str] = None,
        domain: Optional[str] = None,
        local_auth: bool = False,
        additional_args: List[str] = None
    ) -> List[str]:
        """
        Build a NetExec command with common options.
        
        Args:
            protocol: Protocol to use (smb, rdp, etc.)
            target: Target host or network
            port: Port number (optional)
            username: Username for authentication
            password: Password for authentication
            hash: NTLM hash for authentication
            domain: Domain for authentication
            local_auth: Use local authentication
            additional_args: Additional command arguments
            
        Returns:
            Command as a list of strings
        """
        if not self.is_available():
            raise RuntimeError("NetExec is not available")
        
        cmd = [self.tool_path, protocol, target]
        
        # Add port if non-default
        if port:
            cmd.extend(['--port', str(port)])
        
        # Add authentication
        if username:
            cmd.extend(['-u', username])
            
            if password:
                cmd.extend(['-p', password])
            elif hash:
                cmd.extend(['-H', hash])
            
            if domain:
                cmd.extend(['-d', domain])
            
            if local_auth:
                cmd.append('--local-auth')
        
        # Add any additional arguments
        if additional_args:
            cmd.extend(additional_args)
        
        return cmd