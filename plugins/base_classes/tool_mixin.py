"""
Tool detection mixin for plugins that need to find external tools.
"""

import shutil
import subprocess
import logging
from typing import Optional, Dict, Any, Tuple, List
from pathlib import Path

logger = logging.getLogger(__name__)


class ToolDetectionMixin:
    """
    Mixin class that provides standardized tool detection functionality.
    
    Plugins should set:
        self.tool_name: Primary tool command name
        self.tool_alt_names: List of alternative command names (optional)
        self.install_command: Installation command for the tool
    """
    
    def _find_tool(self) -> Optional[str]:
        """
        Find tool executable in PATH.
        
        Returns:
            Path to tool executable or None if not found
        """
        # Check primary tool name
        if hasattr(self, 'tool_name') and shutil.which(self.tool_name):
            return self.tool_name
        
        # Check alternative names
        if hasattr(self, 'tool_alt_names'):
            for alt_name in self.tool_alt_names:
                if shutil.which(alt_name):
                    logger.info(f"Found {self.tool_name} as '{alt_name}'")
                    return alt_name
        
        # Tool not found
        tool_name = getattr(self, 'tool_name', 'unknown')
        logger.debug(f"{tool_name} not found in PATH")
        return None
    
    def check_required_tools(self, skip_check: bool = False) -> Tuple[bool, Dict[str, Dict[str, Any]]]:
        """
        Check if required tools are available.
        
        Args:
            skip_check: If True, skip the tool check
            
        Returns:
            Tuple of (all_available, tool_status_dict)
        """
        if skip_check or getattr(self, 'skip_tool_check', False):
            return True, {}
        
        # Use parent class check if no custom tool detection needed
        if not hasattr(self, 'tool_name'):
            return super().check_required_tools(skip_check)
        
        tool_path = self._find_tool()
        tool_name = getattr(self, 'tool_name', 'unknown')
        
        if tool_path:
            return True, {tool_name: {"available": True, "path": tool_path}}
        
        # Tool not found
        install_cmd = getattr(self, 'install_command', f"Please install {tool_name}")
        return False, {tool_name: {
            "available": False,
            "install_command": install_cmd,
            "path": None
        }}
    
    def execute_tool_command(self, cmd: List[str], timeout: int = 300,
                           check_output: bool = True) -> subprocess.CompletedProcess:
        """
        Execute a tool command with standard error handling.
        
        Args:
            cmd: Command to execute as a list
            timeout: Timeout in seconds
            check_output: Whether to capture output
            
        Returns:
            CompletedProcess object with results
        """
        logger.debug(f"Executing command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=check_output,
                text=True,
                timeout=timeout
            )
            
            if result.returncode != 0 and result.stderr:
                logger.warning(f"Command stderr: {result.stderr}")
            
            # Log to output manager if available
            if hasattr(self, 'output_manager') and self.output_manager:
                if hasattr(self.output_manager, 'log_tool_execution'):
                    tool_name = cmd[0] if cmd else "unknown"
                    target = cmd[-1] if len(cmd) > 1 else "unknown"
                    
                    self.output_manager.log_tool_execution(
                        tool_name=tool_name,
                        target=target,
                        command=' '.join(cmd),
                        output=result.stdout + result.stderr,
                        service=getattr(self, 'name', 'Unknown')
                    )
            
            return result
            
        except subprocess.TimeoutExpired:
            logger.error(f"Command timed out after {timeout} seconds")
            raise
        except Exception as e:
            logger.error(f"Command execution failed: {e}")
            raise