"""
SSH service plugin for AutoTest using SSH-Audit.
"""

import logging
import subprocess
import json
import shutil
from typing import Dict, Any, List, Optional
from pathlib import Path

from ..base import Plugin, PluginType, plugin

logger = logging.getLogger(__name__)


@plugin(name="ssh")
class SSHPlugin(Plugin):
    """Plugin for SSH configuration auditing using SSH-Audit."""
    
    def __init__(self):
        """Initialize the SSH plugin."""
        super().__init__()
        self.name = "SSH Service Plugin"
        self.version = "1.0.0"
        self.description = "SSH configuration auditing using SSH-Audit"
        self.type = PluginType.SERVICE
        self.author = "AutoTest Framework"
        self.port = 22  # Default SSH port
        
        # Tool configuration
        self.tool_name = "ssh-audit"
        self.required_tools = ["ssh-audit"]
    
    def _find_tool(self) -> Optional[str]:
        """Find ssh-audit executable.
        
        Returns:
            Path to ssh-audit executable or None
        """
        if shutil.which(self.tool_name):
            return self.tool_name
        logger.warning("ssh-audit not found in PATH")
        return None
    
    def get_required_params(self) -> List[str]:
        """Get required parameters for SSH plugin.
        
        Returns:
            List of required parameter names
        """
        return ["target"]
    
    def get_optional_params(self) -> Dict[str, Any]:
        """Get optional parameters with their default values.
        
        Returns:
            Dictionary of optional parameters and defaults
        """
        return {
            "port": 22,
            "timeout": 60,
            "output_dir": "output/ssh"
        }
    
    def validate_params(self, **kwargs) -> bool:
        """Validate SSH plugin parameters.
        
        Args:
            **kwargs: Parameters to validate
            
        Returns:
            True if parameters are valid
        """
        if not kwargs.get("target"):
            logger.error("Target parameter is required")
            return False
        
        # Validate port
        port = kwargs.get("port", 22)
        if not isinstance(port, int) or port < 1 or port > 65535:
            logger.error(f"Invalid port: {port}")
            return False
        
        return True
    
    def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute SSH audit using ssh-audit.
        
        Args:
            target: Target host or network
            **kwargs: Additional parameters
            
        Returns:
            Dictionary containing test results
        """
        if not self.validate_params(target=target, **kwargs):
            return {"success": False, "error": "Invalid parameters"}
        
        # Find tool
        tool_path = self._find_tool()
        if not tool_path:
            return {
                "success": False,
                "error": "ssh-audit not found. Please install it first.",
                "install_command": "pip install ssh-audit"
            }
        
        results = {
            "success": True,
            "target": target,
            "service": "SSH",
            "findings": [],
            "errors": []
        }
        
        try:
            port = kwargs.get("port", 22)
            timeout = kwargs.get("timeout", 60)
            output_dir = Path(kwargs.get("output_dir", "output/ssh"))
            output_dir.mkdir(parents=True, exist_ok=True)
            
            logger.info(f"Starting SSH audit on {target}:{port}")
            
            # Prepare output files
            json_output = output_dir / f"ssh_{target}_{port}.json"
            txt_output = output_dir / f"ssh_{target}_{port}.txt"
            
            # Build SSH-Audit command for JSON output
            cmd_json = [
                tool_path,
                "--json",
                "-p", str(port),
                target
            ]
            
            # Run SSH-Audit for JSON output
            logger.debug(f"Running command: {' '.join(cmd_json)}")
            result_json = subprocess.run(
                cmd_json,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            # Save JSON output
            if result_json.stdout:
                with open(json_output, 'w') as f:
                    f.write(result_json.stdout)
                results["json_output"] = str(json_output)
            
            # Run SSH-Audit for text output
            cmd_txt = [
                tool_path,
                "-p", str(port),
                target
            ]
            
            result_txt = subprocess.run(
                cmd_txt,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            # Save text output
            if result_txt.stdout:
                with open(txt_output, 'w') as f:
                    f.write(result_txt.stdout)
                results["text_output"] = str(txt_output)
            
            # Parse results
            findings = self._parse_results(result_json.stdout, result_txt.stdout)
            results["findings"].extend(findings)
            results["command"] = ' '.join(cmd_json)
            
        except subprocess.TimeoutExpired:
            logger.error(f"SSH audit timed out for {target}:{port}")
            results["success"] = False
            results["errors"].append("Scan timed out")
        except Exception as e:
            logger.error(f"SSH audit failed for {target}:{port}: {e}")
            results["success"] = False
            results["errors"].append(str(e))
        
        return results
    
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
    
