"""
SNMP service plugin for AutoTest using OneSixtyOne.
"""

import logging
import subprocess
from typing import Dict, Any, List, Optional
from pathlib import Path

from plugins.base import BasePlugin
from core.task_manager import Task
from core.output import OutputManager


class SNMPPlugin(BasePlugin):
    """Plugin for SNMP enumeration using OneSixtyOne."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the SNMP plugin."""
        super().__init__(config)
        self.name = "snmp"
        self.description = "SNMP enumeration using OneSixtyOne"
        self.author = "AutoTest Framework"
        self.version = "1.0.0"
        self.port = 161  # Default SNMP port
        
        # Tool configuration
        self.tool_name = "onesixtyone"
        self.required_tools = ["onesixtyone"]
        
        # Get wordlist from config or use default
        self.community_list = self.config.get('plugins.snmp.community_list', 
                                            '/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt')
    
    def validate_tools(self) -> bool:
        """Check if required tools are available."""
        import shutil
        return shutil.which(self.tool_name) is not None
    
    def can_handle_service(self, service_info: Dict[str, Any]) -> bool:
        """Check if this plugin can handle the detected service."""
        service = service_info.get('service', '').lower()
        port = service_info.get('port', 0)
        
        # Handle SNMP on standard port or if service is detected as SNMP
        return port == 161 or 'snmp' in service
    
    def execute_task(self, task: Task, output_manager: OutputManager) -> Dict[str, Any]:
        """Execute SNMP enumeration task."""
        try:
            logging.info(f"Starting SNMP enumeration on {task.target}:{task.port}")
            
            # Prepare output file
            output_file = output_manager.get_output_path(
                f"snmp_{task.target}_{task.port}.txt"
            )
            
            # Build OneSixtyOne command
            cmd = [
                self.tool_name,
                "-c", self.community_list,  # Community string file
                "-o", str(output_file),     # Output file
                task.target
            ]
            
            # Run OneSixtyOne
            logging.debug(f"Running command: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.get('plugins.snmp.timeout', 300)
            )
            
            # Parse results
            findings = self._parse_results(output_file, result.stdout)
            
            # Save raw output
            if result.stdout:
                raw_output = output_manager.get_output_path(
                    f"snmp_{task.target}_{task.port}_raw.txt"
                )
                output_manager.write_output(raw_output, result.stdout)
            
            return {
                'success': True,
                'findings': findings,
                'output_file': str(output_file),
                'command': ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            logging.error(f"SNMP scan timed out for {task.target}:{task.port}")
            return {
                'success': False,
                'error': 'Scan timed out',
                'findings': []
            }
        except Exception as e:
            logging.error(f"SNMP scan failed for {task.target}:{task.port}: {e}")
            return {
                'success': False,
                'error': str(e),
                'findings': []
            }
    
    def _parse_results(self, output_file: Path, stdout: str) -> List[Dict[str, Any]]:
        """Parse OneSixtyOne results."""
        findings = []
        
        # Parse stdout for successful community strings
        if stdout:
            for line in stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                    
                # OneSixtyOne format: IP [community] system description
                if '[' in line and ']' in line:
                    parts = line.split('[', 1)
                    if len(parts) == 2:
                        ip = parts[0].strip()
                        rest = parts[1]
                        if ']' in rest:
                            community = rest.split(']')[0]
                            description = rest.split(']', 1)[1].strip()
                            
                            findings.append({
                                'type': 'snmp_community',
                                'severity': 'high',
                                'title': f'SNMP Community String Found: {community}',
                                'description': f'Valid SNMP community string "{community}" found on {ip}',
                                'details': {
                                    'ip': ip,
                                    'community': community,
                                    'system_description': description
                                }
                            })
        
        # Also check output file if it exists
        if output_file.exists():
            try:
                with open(output_file, 'r') as f:
                    content = f.read()
                    # Parse file content if different from stdout
                    if content and content != stdout:
                        # Additional parsing logic if needed
                        pass
            except Exception as e:
                logging.error(f"Failed to read output file: {e}")
        
        return findings
    
    def get_config_template(self) -> Dict[str, Any]:
        """Return configuration template for this plugin."""
        return {
            'enabled': True,
            'timeout': 300,
            'community_list': '/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt',
            'threads': 10
        }