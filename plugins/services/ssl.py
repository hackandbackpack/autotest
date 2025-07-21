"""
SSL/TLS service plugin for AutoTest using SSLyze.
"""

import logging
import subprocess
import json
from typing import Dict, Any, List, Optional
from pathlib import Path

from plugins.base import BasePlugin
from core.task_manager import Task
from core.output import OutputManager


class SSLPlugin(BasePlugin):
    """Plugin for SSL/TLS scanning using SSLyze."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the SSL plugin."""
        super().__init__(config)
        self.name = "ssl"
        self.description = "SSL/TLS configuration scanning using SSLyze"
        self.author = "AutoTest Framework"
        self.version = "1.0.0"
        
        # Tool configuration
        self.tool_name = "sslyze"
        self.required_tools = ["sslyze"]
        
        # Common SSL/TLS ports
        self.ssl_ports = [443, 8443, 9443, 465, 993, 995, 636, 989, 990, 5986]
    
    def validate_tools(self) -> bool:
        """Check if required tools are available."""
        import shutil
        return shutil.which(self.tool_name) is not None
    
    def can_handle_service(self, service_info: Dict[str, Any]) -> bool:
        """Check if this plugin can handle the detected service."""
        service = service_info.get('service', '').lower()
        port = service_info.get('port', 0)
        
        # Handle HTTPS, SSL/TLS services, or common SSL ports
        ssl_keywords = ['https', 'ssl', 'tls', 'secure']
        return any(keyword in service for keyword in ssl_keywords) or port in self.ssl_ports
    
    def execute_task(self, task: Task, output_manager: OutputManager) -> Dict[str, Any]:
        """Execute SSL/TLS scan task."""
        try:
            logging.info(f"Starting SSL/TLS scan on {task.target}:{task.port}")
            
            # Prepare output files
            json_output = output_manager.get_output_path(
                f"ssl_{task.target}_{task.port}.json"
            )
            txt_output = output_manager.get_output_path(
                f"ssl_{task.target}_{task.port}.txt"
            )
            
            # Build SSLyze command for JSON output
            cmd = [
                self.tool_name,
                "--json_out", str(json_output),
                "--regular",  # Regular scan (includes cipher suites, protocols, etc.)
                f"{task.target}:{task.port}"
            ]
            
            # Add additional scan options based on config
            if self.config.get('plugins.ssl.heartbleed', True):
                cmd.append("--heartbleed")
            
            if self.config.get('plugins.ssl.compression', True):
                cmd.append("--compression")
            
            if self.config.get('plugins.ssl.fallback', True):
                cmd.append("--fallback")
            
            # Run SSLyze
            logging.debug(f"Running command: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.get('plugins.ssl.timeout', 300)
            )
            
            # Save text output
            if result.stdout:
                output_manager.write_output(txt_output, result.stdout)
            
            # Parse results
            findings = self._parse_results(json_output, result.stdout)
            
            return {
                'success': True,
                'findings': findings,
                'output_files': {
                    'json': str(json_output),
                    'text': str(txt_output)
                },
                'command': ' '.join(cmd)
            }
            
        except subprocess.TimeoutExpired:
            logging.error(f"SSL/TLS scan timed out for {task.target}:{task.port}")
            return {
                'success': False,
                'error': 'Scan timed out',
                'findings': []
            }
        except Exception as e:
            logging.error(f"SSL/TLS scan failed for {task.target}:{task.port}: {e}")
            return {
                'success': False,
                'error': str(e),
                'findings': []
            }
    
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
                import datetime
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
    
    def get_config_template(self) -> Dict[str, Any]:
        """Return configuration template for this plugin."""
        return {
            'enabled': True,
            'timeout': 300,
            'heartbleed': True,
            'compression': True,
            'fallback': True
        }