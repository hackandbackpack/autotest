"""
SSH-Audit security assessment plugin for AutoTest.
"""

import logging
import subprocess
import shutil
import time
import json
from typing import Dict, Any, List, Tuple
from pathlib import Path

from ..base import Plugin, PluginType, plugin

logger = logging.getLogger(__name__)


@plugin(name="ssh_audit")
class SSHAuditPlugin(Plugin):
    """Plugin for SSH security assessment using ssh-audit."""
    
    def __init__(self):
        """Initialize the SSH-Audit plugin."""
        super().__init__()
        self.name = "SSH-Audit Security Scanner"
        self.version = "1.0.0"
        self.description = "SSH security configuration assessment using ssh-audit"
        self.type = PluginType.SERVICE
        self.author = "AutoTest Framework"
        
        self.required_tools = ["ssh-audit"]
        
        # SSH ports
        self.ssh_ports = [22, 2222]
    
    def can_handle(self, service: str, port: int) -> bool:
        """Check if this plugin can handle the given service/port."""
        return (
            port in self.ssh_ports or
            'ssh' in service.lower()
        )
    
    def get_required_params(self) -> List[str]:
        """Get required parameters."""
        return ["target"]
    
    def get_optional_params(self) -> Dict[str, Any]:
        """Get optional parameters with defaults."""
        return {
            "port": 22,
            "timeout": 60,
            "output_dir": "output/ssh",
            "json_output": True
        }
    
    def validate_params(self, **kwargs) -> bool:
        """Validate parameters."""
        if not kwargs.get("target"):
            logger.error("Target parameter is required")
            return False
        
        port = kwargs.get("port", 22)
        if not isinstance(port, int) or port < 1 or port > 65535:
            logger.error(f"Invalid port: {port}")
            return False
        
        return True
    
    def check_required_tools(self, skip_check: bool = False) -> Tuple[bool, Dict[str, Dict[str, Any]]]:
        """Check if ssh-audit is available."""
        if skip_check or getattr(self, 'skip_tool_check', False):
            return True, {}
        
        if shutil.which("ssh-audit"):
            return True, {"ssh-audit": {"available": True, "path": shutil.which("ssh-audit")}}
        else:
            return False, {"ssh-audit": {
                "available": False, 
                "install_command": "pip install ssh-audit",
                "path": None
            }}
    
    def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute SSH-Audit security assessment."""
        logger.info(f"SSH-Audit plugin execute() called for {target} with kwargs: {kwargs}")
        
        if not self.validate_params(target=target, **kwargs):
            return {"success": False, "error": "Invalid parameters"}
        
        # Check if ssh-audit is available
        tool_available, tool_status = self.check_required_tools()
        if not tool_available:
            error_msg = "ssh-audit not found. Please install it first with: pip install ssh-audit"
            logger.error(error_msg)
            
            if hasattr(self, 'output_manager') and self.output_manager:
                self.output_manager.log_tool_execution(
                    tool_name="ssh-audit",
                    target=f"{target}:{kwargs.get('port', 22)}",
                    command="ssh-audit (NOT FOUND)",
                    output=error_msg,
                    service="SSH",
                    execution_time=0
                )
            
            return {
                "success": False,
                "error": error_msg,
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
            json_output = kwargs.get("json_output", True)
            output_dir = Path(kwargs.get("output_dir", "output/ssh"))
            output_dir.mkdir(parents=True, exist_ok=True)
            
            logger.info(f"Starting SSH-Audit assessment on {target}:{port}")
            
            # Prepare output files
            json_file = output_dir / f"ssh_audit_{target}_{port}.json"
            txt_file = output_dir / f"ssh_audit_{target}_{port}.txt"
            
            # Build SSH-Audit command
            cmd = [
                "ssh-audit",
                f"{target}:{port}",
                "--timeout", str(timeout)
            ]
            
            if json_output:
                cmd.extend(["--json"])
            
            # Run SSH-Audit
            logger.info(f"Running command: {' '.join(cmd)}")
            start_time = time.time()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 30
            )
            execution_time = time.time() - start_time
            
            # Save outputs
            full_output = ""
            if result.stdout:
                full_output += result.stdout
                
                # Save JSON output if requested
                if json_output:
                    try:
                        json_data = json.loads(result.stdout)
                        with open(json_file, 'w') as f:
                            json.dump(json_data, f, indent=2)
                    except json.JSONDecodeError:
                        # If JSON parsing fails, save as text
                        with open(txt_file, 'w') as f:
                            f.write(result.stdout)
                else:
                    with open(txt_file, 'w') as f:
                        f.write(result.stdout)
            
            if result.stderr:
                full_output += f"\n\nSTDERR:\n{result.stderr}"
            
            full_output += f"\n\nReturn code: {result.returncode}"
            
            # Always log to output manager
            if hasattr(self, 'output_manager') and self.output_manager:
                self.output_manager.log_tool_execution(
                    tool_name="ssh-audit",
                    target=f"{target}:{port}",
                    command=' '.join(cmd),
                    output=full_output,
                    service="SSH",
                    execution_time=execution_time
                )
            
            # Parse findings
            if json_output and json_file.exists():
                findings = self._parse_ssh_audit_json(json_file, target, port)
                results["findings"].extend(findings)
                results["json_output"] = str(json_file)
            else:
                findings = self._parse_ssh_audit_text(full_output, target, port)
                results["findings"].extend(findings)
                results["txt_output"] = str(txt_file)
            
            results["command"] = ' '.join(cmd)
            results["execution_time"] = execution_time
            
        except subprocess.TimeoutExpired:
            error_msg = f"SSH-Audit timed out after {timeout + 30} seconds"
            logger.error(error_msg)
            results["success"] = False
            results["errors"].append(error_msg)
            
        except Exception as e:
            error_msg = f"SSH-Audit failed: {str(e)}"
            logger.error(error_msg)
            results["success"] = False
            results["errors"].append(error_msg)
        
        return results
    
    def _parse_ssh_audit_json(self, json_file: Path, target: str, port: int) -> List[Dict[str, Any]]:
        """Parse SSH-Audit JSON output for security findings."""
        findings = []
        
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            # Check for SSH version information
            banner = data.get('banner', {})
            software = banner.get('software', '')
            version = banner.get('version', '')
            
            if software:
                findings.append({
                    'type': 'ssh_version',
                    'severity': 'info',
                    'target': target,
                    'port': port,
                    'title': f'SSH Software Identified: {software}',
                    'description': f'SSH server: {software} {version}',
                    'service': 'SSH',
                    'details': {
                        'software': software,
                        'version': version,
                        'banner': banner
                    }
                })
            
            # Check algorithms
            algorithms = data.get('algorithms', {})
            
            # Check key exchange algorithms
            kex = algorithms.get('kex', [])
            for kex_alg in kex:
                if isinstance(kex_alg, dict):
                    alg_name = kex_alg.get('algorithm', '')
                    notes = kex_alg.get('notes', {})
                    
                    if notes.get('fail'):
                        findings.append({
                            'type': 'ssh_weak_kex',
                            'severity': 'high',
                            'target': target,
                            'port': port,
                            'title': 'Weak SSH Key Exchange Algorithm',
                            'description': f'Weak key exchange algorithm: {alg_name}',
                            'service': 'SSH',
                            'details': {
                                'algorithm': alg_name,
                                'type': 'key_exchange',
                                'issues': notes.get('fail', [])
                            }
                        })
                    elif notes.get('warn'):
                        findings.append({
                            'type': 'ssh_weak_kex',
                            'severity': 'medium',
                            'target': target,
                            'port': port,
                            'title': 'Questionable SSH Key Exchange Algorithm',
                            'description': f'Questionable key exchange algorithm: {alg_name}',
                            'service': 'SSH',
                            'details': {
                                'algorithm': alg_name,
                                'type': 'key_exchange',
                                'warnings': notes.get('warn', [])
                            }
                        })
            
            # Check ciphers
            enc = algorithms.get('enc', [])
            for cipher in enc:
                if isinstance(cipher, dict):
                    cipher_name = cipher.get('algorithm', '')
                    notes = cipher.get('notes', {})
                    
                    if notes.get('fail'):
                        findings.append({
                            'type': 'ssh_weak_cipher',
                            'severity': 'high',
                            'target': target,
                            'port': port,
                            'title': 'Weak SSH Cipher',
                            'description': f'Weak cipher: {cipher_name}',
                            'service': 'SSH',
                            'details': {
                                'algorithm': cipher_name,
                                'type': 'cipher',
                                'issues': notes.get('fail', [])
                            }
                        })
                    elif notes.get('warn'):
                        findings.append({
                            'type': 'ssh_weak_cipher',
                            'severity': 'medium',
                            'target': target,
                            'port': port,
                            'title': 'Questionable SSH Cipher',
                            'description': f'Questionable cipher: {cipher_name}',
                            'service': 'SSH',
                            'details': {
                                'algorithm': cipher_name,
                                'type': 'cipher',
                                'warnings': notes.get('warn', [])
                            }
                        })
            
            # Check MAC algorithms
            mac = algorithms.get('mac', [])
            for mac_alg in mac:
                if isinstance(mac_alg, dict):
                    mac_name = mac_alg.get('algorithm', '')
                    notes = mac_alg.get('notes', {})
                    
                    if notes.get('fail'):
                        findings.append({
                            'type': 'ssh_weak_mac',
                            'severity': 'high',
                            'target': target,
                            'port': port,
                            'title': 'Weak SSH MAC Algorithm',
                            'description': f'Weak MAC algorithm: {mac_name}',
                            'service': 'SSH',
                            'details': {
                                'algorithm': mac_name,
                                'type': 'mac',
                                'issues': notes.get('fail', [])
                            }
                        })
                    elif notes.get('warn'):
                        findings.append({
                            'type': 'ssh_weak_mac',
                            'severity': 'medium',
                            'target': target,
                            'port': port,
                            'title': 'Questionable SSH MAC Algorithm',
                            'description': f'Questionable MAC algorithm: {mac_name}',
                            'service': 'SSH',
                            'details': {
                                'algorithm': mac_name,
                                'type': 'mac',
                                'warnings': notes.get('warn', [])
                            }
                        })
        
        except Exception as e:
            logger.error(f"Failed to parse SSH-Audit JSON: {e}")
        
        return findings
    
    def _parse_ssh_audit_text(self, output: str, target: str, port: int) -> List[Dict[str, Any]]:
        """Parse SSH-Audit text output for security findings."""
        findings = []
        
        if not output:
            return findings
        
        try:
            lines = output.split('\n')
            
            for line in lines:
                line = line.strip()
                
                # Look for algorithm warnings/failures
                if '(fail)' in line.lower():
                    algorithm = line.split('(fail)')[0].strip()
                    findings.append({
                        'type': 'ssh_vulnerability',
                        'severity': 'high',
                        'target': target,
                        'port': port,
                        'title': 'SSH Security Issue',
                        'description': f'Failed algorithm: {algorithm}',
                        'service': 'SSH',
                        'details': {
                            'issue': line,
                            'level': 'fail'
                        }
                    })
                
                elif '(warn)' in line.lower():
                    algorithm = line.split('(warn)')[0].strip()
                    findings.append({
                        'type': 'ssh_vulnerability',
                        'severity': 'medium',
                        'target': target,
                        'port': port,
                        'title': 'SSH Security Warning',
                        'description': f'Warning for algorithm: {algorithm}',
                        'service': 'SSH',
                        'details': {
                            'issue': line,
                            'level': 'warn'
                        }
                    })
                
                # Check for version information
                if 'running' in line.lower() and 'openssh' in line.lower():
                    findings.append({
                        'type': 'ssh_version',
                        'severity': 'info',
                        'target': target,
                        'port': port,
                        'title': 'SSH Version Identified',
                        'description': line,
                        'service': 'SSH',
                        'details': {
                            'version_info': line
                        }
                    })
        
        except Exception as e:
            logger.error(f"Failed to parse SSH-Audit text output: {e}")
        
        return findings