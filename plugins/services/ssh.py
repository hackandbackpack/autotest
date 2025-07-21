"""
SSH service plugin for AutoTest using SSH-Audit.
"""

import logging
import subprocess
import json
from typing import Dict, Any, List, Optional
from pathlib import Path

from plugins.base import BasePlugin
from core.task_manager import Task
from core.output import OutputManager


class SSHPlugin(BasePlugin):
    """Plugin for SSH configuration auditing using SSH-Audit."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the SSH plugin."""
        super().__init__(config)
        self.name = "ssh"
        self.description = "SSH configuration auditing using SSH-Audit"
        self.author = "AutoTest Framework"
        self.version = "1.0.0"
        self.port = 22  # Default SSH port
        
        # Tool configuration
        self.tool_name = "ssh-audit"
        self.required_tools = ["ssh-audit"]
    
    def validate_tools(self) -> bool:
        """Check if required tools are available."""
        import shutil
        return shutil.which(self.tool_name) is not None
    
    def can_handle_service(self, service_info: Dict[str, Any]) -> bool:
        """Check if this plugin can handle the detected service."""
        service = service_info.get('service', '').lower()
        port = service_info.get('port', 0)
        
        # Handle SSH on any port
        return 'ssh' in service or port == 22
    
    def execute_task(self, task: Task, output_manager: OutputManager) -> Dict[str, Any]:
        """Execute SSH audit task."""
        try:
            logging.info(f"Starting SSH audit on {task.target}:{task.port}")
            
            # Prepare output files
            json_output = output_manager.get_output_path(
                f"ssh_{task.target}_{task.port}.json"
            )
            txt_output = output_manager.get_output_path(
                f"ssh_{task.target}_{task.port}.txt"
            )
            
            # Build SSH-Audit command for JSON output
            cmd_json = [
                self.tool_name,
                "--json",
                "-p", str(task.port),
                task.target
            ]
            
            # Run SSH-Audit for JSON output
            logging.debug(f"Running command: {' '.join(cmd_json)}")
            result_json = subprocess.run(
                cmd_json,
                capture_output=True,
                text=True,
                timeout=self.config.get('plugins.ssh.timeout', 60)
            )
            
            # Save JSON output
            if result_json.stdout:
                output_manager.write_output(json_output, result_json.stdout)
            
            # Run SSH-Audit for text output
            cmd_txt = [
                self.tool_name,
                "-p", str(task.port),
                task.target
            ]
            
            result_txt = subprocess.run(
                cmd_txt,
                capture_output=True,
                text=True,
                timeout=self.config.get('plugins.ssh.timeout', 60)
            )
            
            # Save text output
            if result_txt.stdout:
                output_manager.write_output(txt_output, result_txt.stdout)
            
            # Parse results
            findings = self._parse_results(result_json.stdout, result_txt.stdout)
            
            return {
                'success': True,
                'findings': findings,
                'output_files': {
                    'json': str(json_output),
                    'text': str(txt_output)
                },
                'command': ' '.join(cmd_json)
            }
            
        except subprocess.TimeoutExpired:
            logging.error(f"SSH audit timed out for {task.target}:{task.port}")
            return {
                'success': False,
                'error': 'Scan timed out',
                'findings': []
            }
        except Exception as e:
            logging.error(f"SSH audit failed for {task.target}:{task.port}: {e}")
            return {
                'success': False,
                'error': str(e),
                'findings': []
            }
    
    def _parse_results(self, json_output: str, text_output: str) -> List[Dict[str, Any]]:
        """Parse SSH-Audit results."""
        findings = []
        
        try:
            # Parse JSON output
            if json_output:
                data = json.loads(json_output)
                
                # Check for banner
                if 'banner' in data and data['banner']:
                    findings.append({
                        'type': 'ssh_banner',
                        'severity': 'info',
                        'title': 'SSH Banner Detected',
                        'description': f"SSH Banner: {data['banner']['software']}",
                        'details': data['banner']
                    })
                
                # Check for weak algorithms
                if 'kex' in data:
                    for kex in data['kex']:
                        if 'warn' in kex or 'fail' in kex:
                            findings.append({
                                'type': 'weak_kex',
                                'severity': 'medium' if 'warn' in kex else 'high',
                                'title': f'Weak Key Exchange Algorithm: {kex["algorithm"]}',
                                'description': kex.get('warn', kex.get('fail', '')),
                                'details': kex
                            })
                
                # Check for weak host keys
                if 'keys' in data:
                    for key in data['keys']:
                        if 'warn' in key or 'fail' in key:
                            findings.append({
                                'type': 'weak_host_key',
                                'severity': 'medium' if 'warn' in key else 'high',
                                'title': f'Weak Host Key: {key["algorithm"]}',
                                'description': key.get('warn', key.get('fail', '')),
                                'details': key
                            })
                
                # Check for weak ciphers
                if 'enc' in data:
                    for enc in data['enc']:
                        if 'warn' in enc or 'fail' in enc:
                            findings.append({
                                'type': 'weak_cipher',
                                'severity': 'medium' if 'warn' in enc else 'high',
                                'title': f'Weak Cipher: {enc["algorithm"]}',
                                'description': enc.get('warn', enc.get('fail', '')),
                                'details': enc
                            })
                
                # Check for weak MACs
                if 'mac' in data:
                    for mac in data['mac']:
                        if 'warn' in mac or 'fail' in mac:
                            findings.append({
                                'type': 'weak_mac',
                                'severity': 'medium' if 'warn' in mac else 'high',
                                'title': f'Weak MAC Algorithm: {mac["algorithm"]}',
                                'description': mac.get('warn', mac.get('fail', '')),
                                'details': mac
                            })
                
        except json.JSONDecodeError as e:
            logging.error(f"Failed to parse JSON output: {e}")
            
            # Fallback to text parsing
            if text_output:
                lines = text_output.splitlines()
                for line in lines:
                    if '(fail)' in line.lower():
                        findings.append({
                            'type': 'ssh_issue',
                            'severity': 'high',
                            'title': 'SSH Configuration Issue',
                            'description': line.strip(),
                            'details': {'raw': line}
                        })
                    elif '(warn)' in line.lower():
                        findings.append({
                            'type': 'ssh_issue',
                            'severity': 'medium',
                            'title': 'SSH Configuration Warning',
                            'description': line.strip(),
                            'details': {'raw': line}
                        })
        
        return findings
    
    def get_config_template(self) -> Dict[str, Any]:
        """Return configuration template for this plugin."""
        return {
            'enabled': True,
            'timeout': 60
        }