"""
SSL/TLS service plugin for AutoTest using SSLyze.
"""

import logging
import subprocess
import json
import shutil
import sys
import datetime
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path

from ..base import Plugin, PluginType, plugin

logger = logging.getLogger(__name__)


@plugin(name="ssl")
class SSLPlugin(Plugin):
    """Plugin for SSL/TLS scanning using SSLyze."""
    
    def __init__(self):
        """Initialize the SSL plugin."""
        super().__init__()
        self.name = "SSL/TLS Service Plugin"
        self.version = "1.0.0"
        self.description = "SSL/TLS configuration scanning using SSLyze"
        self.type = PluginType.SERVICE
        self.author = "AutoTest Framework"
        
        # Tool configuration
        self.tool_name = "sslyze"
        self.required_tools = ["sslyze"]
        
        # Common SSL/TLS ports
        self.ssl_ports = [443, 8443, 9443, 465, 993, 995, 636, 989, 990, 5986]
    
    def _find_tool(self) -> Optional[str]:
        """Find sslyze executable.
        
        Returns:
            Path to sslyze executable or None
        """
        # First try regular command
        if shutil.which(self.tool_name):
            return self.tool_name
        
        # Try in Python Scripts directory
        try:
            import site
            from pathlib import Path
            import platform
            
            # Get Scripts directory
            user_base = site.USER_BASE
            if platform.system() == "Windows":
                scripts_dir = Path(user_base) / "Scripts"
                tool_path = scripts_dir / "sslyze.exe"
            else:
                scripts_dir = Path(user_base) / "bin"
                tool_path = scripts_dir / "sslyze"
            
            if tool_path.exists():
                return str(tool_path)
                
            # Also check Microsoft Store Python location
            if platform.system() == "Windows":
                local_packages = Path.home() / "AppData" / "Local" / "Packages"
                if local_packages.exists():
                    for item in local_packages.iterdir():
                        if item.name.startswith("PythonSoftwareFoundation.Python"):
                            ms_scripts = item / "LocalCache" / "local-packages" / "Python311" / "Scripts" / "sslyze.exe"
                            if ms_scripts.exists():
                                return str(ms_scripts)
        except:
            pass
        
        # Try running as Python module
        try:
            result = subprocess.run(
                [sys.executable, "-m", "sslyze", "--help"],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                return f"{sys.executable} -m sslyze"
        except:
            pass
            
        logger.warning("sslyze not found in PATH, Scripts directory, or as Python module")
        return None
    
    def get_required_params(self) -> List[str]:
        """Get required parameters for SSL plugin.
        
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
            "port": 443,
            "timeout": 300,
            "output_dir": "output/ssl",
            "heartbleed": True,
            "compression": True,
            "fallback": True
        }
    
    def validate_params(self, **kwargs) -> bool:
        """Validate SSL plugin parameters.
        
        Args:
            **kwargs: Parameters to validate
            
        Returns:
            True if parameters are valid
        """
        if not kwargs.get("target"):
            logger.error("Target parameter is required")
            return False
        
        # Validate port
        port = kwargs.get("port", 443)
        if not isinstance(port, int) or port < 1 or port > 65535:
            logger.error(f"Invalid port: {port}")
            return False
        
        return True
    
    def check_required_tools(self, skip_check: bool = False) -> Tuple[bool, Dict[str, Dict[str, Any]]]:
        """Check if sslyze is available using custom logic."""
        if skip_check or getattr(self, 'skip_tool_check', False):
            return True, {}
        
        tool_path = self._find_tool()
        if tool_path:
            return True, {self.tool_name: {"available": True, "path": tool_path}}
        else:
            return False, {self.tool_name: {
                "available": False, 
                "install_command": "pip install sslyze",
                "path": None
            }}
    
    def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute SSL/TLS scan task."""
        if not self.validate_params(target=target, **kwargs):
            return {"success": False, "error": "Invalid parameters"}
        
        # Find tool
        tool_path = self._find_tool()
        if not tool_path:
            return {
                "success": False,
                "error": "sslyze not found. Please install it first.",
                "install_command": "pip install sslyze"
            }
        
        results = {
            "success": True,
            "target": target,
            "service": "SSL/TLS",
            "findings": [],
            "errors": []
        }
        
        try:
            port = kwargs.get("port", 443)
            timeout = kwargs.get("timeout", 300)
            output_dir = Path(kwargs.get("output_dir", "output/ssl"))
            output_dir.mkdir(parents=True, exist_ok=True)
            
            logger.info(f"Starting SSL/TLS scan on {target}:{port}")
            
            # Prepare output files
            json_output = output_dir / f"ssl_{target}_{port}.json"
            txt_output = output_dir / f"ssl_{target}_{port}.txt"
            
            # Build SSLyze command for JSON output
            # Handle case where tool_path might be "python -m sslyze"
            if " " in tool_path:
                cmd = tool_path.split() + [
                    "--json_out", str(json_output),
                    "--regular",  # Regular scan (includes cipher suites, protocols, etc.)
                    f"{target}:{port}"
                ]
            else:
                cmd = [
                    tool_path,
                    "--json_out", str(json_output),
                    "--regular",  # Regular scan (includes cipher suites, protocols, etc.)
                    f"{target}:{port}"
                ]
            
            # Add additional scan options based on kwargs
            if kwargs.get('heartbleed', True):
                cmd.append("--heartbleed")
            
            if kwargs.get('compression', True):
                cmd.append("--compression")
            
            if kwargs.get('fallback', True):
                cmd.append("--fallback")
            
            # Run SSLyze
            logger.debug(f"Running command: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            # Save text output
            if result.stdout:
                with open(txt_output, 'w') as f:
                    f.write(result.stdout)
                results["text_output"] = str(txt_output)
            
            # Parse results
            findings = self._parse_results(json_output, result.stdout)
            results["findings"].extend(findings)
            results["json_output"] = str(json_output)
            results["command"] = ' '.join(cmd)
            
        except subprocess.TimeoutExpired:
            logger.error(f"SSL/TLS scan timed out for {target}:{port}")
            results["success"] = False
            results["errors"].append("Scan timed out")
        except Exception as e:
            logger.error(f"SSL/TLS scan failed for {target}:{port}: {e}")
            results["success"] = False
            results["errors"].append(str(e))
        
        return results
    
    def _parse_results(self, json_file: Path, text_output: str) -> List[Dict[str, Any]]:
        """Parse SSLyze results."""
        findings = []
        
        try:
            # Parse JSON output file
            if json_file.exists():
                with open(json_file, 'r') as f:
                    data = json.load(f)
                    
                # Process each scanned server
                for server_scan in data.get('server_scan_results', []):
                    scan_result = server_scan.get('scan_result', {})
                    
                    # Check certificate info
                    cert_info = scan_result.get('certificate_info', {})
                    if cert_info and cert_info.get('result'):
                        self._check_certificate(cert_info['result'], findings)
                    
                    # Check supported SSL/TLS versions
                    for protocol in ['ssl_2_0', 'ssl_3_0', 'tls_1_0', 'tls_1_1']:
                        proto_scan = scan_result.get(f'{protocol}_cipher_suites', {})
                        if proto_scan.get('result', {}).get('accepted_cipher_suites'):
                            findings.append({
                                'type': 'weak_protocol',
                                'severity': 'high',
                                'title': f'Weak Protocol Supported: {protocol.upper().replace("_", " ")}',
                                'description': f'Server supports deprecated {protocol.upper().replace("_", " ")} protocol',
                                'details': {
                                    'protocol': protocol,
                                    'cipher_count': len(proto_scan['result']['accepted_cipher_suites'])
                                }
                            })
                    
                    # Check for Heartbleed
                    heartbleed = scan_result.get('heartbleed', {})
                    if heartbleed.get('result', {}).get('is_vulnerable_to_heartbleed'):
                        findings.append({
                            'type': 'heartbleed',
                            'severity': 'critical',
                            'title': 'Heartbleed Vulnerability Detected',
                            'description': 'Server is vulnerable to Heartbleed (CVE-2014-0160)',
                            'details': heartbleed['result']
                        })
                    
                    # Check compression
                    compression = scan_result.get('compression', {})
                    if compression.get('result', {}).get('supports_compression'):
                        findings.append({
                            'type': 'compression',
                            'severity': 'medium',
                            'title': 'TLS Compression Enabled',
                            'description': 'Server supports TLS compression (CRIME vulnerability)',
                            'details': compression['result']
                        })
                    
                    # Check weak ciphers
                    for protocol in ['tls_1_2', 'tls_1_3']:
                        proto_scan = scan_result.get(f'{protocol}_cipher_suites', {})
                        if proto_scan.get('result'):
                            cipher_suites = proto_scan['result'].get('accepted_cipher_suites', [])
                            for cipher in cipher_suites:
                                cipher_name = cipher.get('cipher_suite', {}).get('name', '')
                                # Check for weak ciphers
                                weak_indicators = ['RC4', 'DES', 'MD5', 'EXPORT', 'NULL', 'anon']
                                if any(indicator in cipher_name for indicator in weak_indicators):
                                    findings.append({
                                        'type': 'weak_cipher',
                                        'severity': 'high',
                                        'title': f'Weak Cipher Suite: {cipher_name}',
                                        'description': f'Server supports weak cipher suite {cipher_name}',
                                        'details': cipher
                                    })
                    
        except Exception as e:
            logging.error(f"Failed to parse JSON output: {e}")
            
            # Fallback to text parsing
            if text_output:
                self._parse_text_output(text_output, findings)
        
        return findings
    
    def _check_certificate(self, cert_result: Dict[str, Any], findings: List[Dict[str, Any]]):
        """Check certificate issues."""
        cert_deployments = cert_result.get('certificate_deployments', [])
        
        for deployment in cert_deployments:
            # Check certificate validation
            path_validation = deployment.get('path_validation_results', [])
            for validation in path_validation:
                if not validation.get('was_validation_successful'):
                    findings.append({
                        'type': 'cert_validation',
                        'severity': 'high',
                        'title': 'Certificate Validation Failed',
                        'description': f"Certificate validation failed: {validation.get('error_message', 'Unknown error')}",
                        'details': validation
                    })
            
            # Check for self-signed certificates
            verified_chain = deployment.get('verified_certificate_chain', [])
            if verified_chain and len(verified_chain) == 1:
                findings.append({
                    'type': 'self_signed_cert',
                    'severity': 'medium',
                    'title': 'Self-Signed Certificate',
                    'description': 'Server is using a self-signed certificate',
                    'details': {'chain_length': 1}
                })
            
            # Check certificate expiration
            leaf_cert = deployment.get('received_certificate_chain', [{}])[0]
            if leaf_cert.get('not_valid_after'):
                try:
                    expiry = datetime.datetime.fromisoformat(leaf_cert['not_valid_after'].replace('Z', '+00:00'))
                    now = datetime.datetime.now(datetime.timezone.utc)
                    days_until_expiry = (expiry - now).days
                    
                    if days_until_expiry < 0:
                        findings.append({
                            'type': 'cert_expired',
                            'severity': 'critical',
                            'title': 'Certificate Expired',
                            'description': f'Certificate expired {-days_until_expiry} days ago',
                            'details': {'expiry_date': leaf_cert['not_valid_after']}
                        })
                    elif days_until_expiry < 30:
                        findings.append({
                            'type': 'cert_expiring',
                            'severity': 'medium',
                            'title': 'Certificate Expiring Soon',
                            'description': f'Certificate expires in {days_until_expiry} days',
                            'details': {'expiry_date': leaf_cert['not_valid_after']}
                        })
                except Exception as e:
                    logging.error(f"Failed to parse certificate expiry: {e}")
    
    def _parse_text_output(self, text_output: str, findings: List[Dict[str, Any]]):
        """Parse text output as fallback."""
        lines = text_output.splitlines()
        for line in lines:
            line_lower = line.lower()
            if 'vulnerable' in line_lower:
                findings.append({
                    'type': 'ssl_vulnerability',
                    'severity': 'high',
                    'title': 'SSL/TLS Vulnerability',
                    'description': line.strip(),
                    'details': {'raw': line}
                })
            elif 'weak' in line_lower or 'deprecated' in line_lower:
                findings.append({
                    'type': 'ssl_weakness',
                    'severity': 'medium',
                    'title': 'SSL/TLS Weakness',
                    'description': line.strip(),
                    'details': {'raw': line}
                })
    

    def can_handle(self, service: str, port: int) -> bool:
        """Check if this plugin can handle the given service/port.
        
        Args:
            service: Service name detected
            port: Port number
            
        Returns:
            True if plugin should run for this service/port
        """
        # Handle known SSL/TLS ports
        if port in self.ssl_ports:
            return True
        
        # Handle services identified as SSL/TLS
        service_lower = service.lower() if service else ""
        ssl_indicators = ["ssl", "tls", "https", "ftps", "imaps", "pop3s", "smtps", "ldaps"]
        
        return any(indicator in service_lower for indicator in ssl_indicators)
