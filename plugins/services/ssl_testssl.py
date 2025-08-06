"""
TestSSL.sh enhanced SSL/TLS testing plugin for AutoTest.
"""

import logging
import subprocess
import shutil
import time
import json
import os
from typing import Dict, Any, List, Tuple
from pathlib import Path

from ..base import Plugin, PluginType, plugin

logger = logging.getLogger(__name__)


@plugin(name="ssl_testssl")
class TestSSLPlugin(Plugin):
    """Plugin for comprehensive SSL/TLS testing using testssl.sh."""
    
    def __init__(self):
        """Initialize the TestSSL plugin."""
        super().__init__()
        self.name = "TestSSL.sh Enhanced SSL Scanner"
        self.version = "1.0.0"
        self.description = "Comprehensive SSL/TLS security testing using testssl.sh"
        self.type = PluginType.SERVICE
        self.author = "AutoTest Framework"
        
        self.required_tools = ["testssl.sh"]
        
        # SSL/TLS ports
        self.ssl_ports = [443, 8443, 9443, 465, 993, 995, 636, 989, 990, 5986]
    
    def can_handle(self, service: str, port: int) -> bool:
        """Check if this plugin can handle the given service/port."""
        return (
            port in self.ssl_ports or
            'ssl' in service.lower() or
            'tls' in service.lower() or
            'https' in service.lower()
        )
    
    def get_required_params(self) -> List[str]:
        """Get required parameters."""
        return ["target"]
    
    def get_optional_params(self) -> Dict[str, Any]:
        """Get optional parameters with defaults."""
        return {
            "port": 443,
            "timeout": 600,
            "output_dir": "output/ssl",
            "severity": "medium",  # low, medium, high, critical
            "protocol_tests": True,
            "cipher_tests": True,
            "vulnerability_tests": True
        }
    
    def validate_params(self, **kwargs) -> bool:
        """Validate parameters."""
        if not kwargs.get("target"):
            logger.error("Target parameter is required")
            return False
        
        port = kwargs.get("port", 443)
        if not isinstance(port, int) or port < 1 or port > 65535:
            logger.error(f"Invalid port: {port}")
            return False
        
        return True
    
    def check_required_tools(self, skip_check: bool = False) -> Tuple[bool, Dict[str, Dict[str, Any]]]:
        """Check if testssl.sh is available."""
        if skip_check or getattr(self, 'skip_tool_check', False):
            return True, {}
        
        # Check for testssl.sh in various locations
        possible_paths = [
            "testssl.sh",
            "/usr/local/bin/testssl.sh",
            "/opt/testssl.sh/testssl.sh",
            "/usr/share/testssl.sh/testssl.sh"
        ]
        
        for path in possible_paths:
            if shutil.which(path) or os.path.exists(path):
                return True, {"testssl.sh": {"available": True, "path": path}}
        
        return False, {"testssl.sh": {
            "available": False,
            "install_command": "git clone https://github.com/drwetter/testssl.sh.git /opt/testssl.sh && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/",
            "path": None
        }}
    
    def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute TestSSL.sh SSL/TLS assessment."""
        logger.info(f"TestSSL plugin execute() called for {target} with kwargs: {kwargs}")
        
        if not self.validate_params(target=target, **kwargs):
            return {"success": False, "error": "Invalid parameters"}
        
        # Check if testssl.sh is available
        tool_available, tool_status = self.check_required_tools()
        if not tool_available:
            error_msg = "testssl.sh not found. Please install it first with: git clone https://github.com/drwetter/testssl.sh.git"
            logger.error(error_msg)
            
            if hasattr(self, 'output_manager') and self.output_manager:
                self.output_manager.log_tool_execution(
                    tool_name="testssl.sh",
                    target=f"{target}:{kwargs.get('port', 443)}",
                    command="testssl.sh (NOT FOUND)",
                    output=error_msg,
                    service="SSL/TLS",
                    execution_time=0
                )
            
            return {
                "success": False,
                "error": error_msg,
                "install_command": "git clone https://github.com/drwetter/testssl.sh.git /opt/testssl.sh"
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
            timeout = kwargs.get("timeout", 600)
            severity = kwargs.get("severity", "medium")
            protocol_tests = kwargs.get("protocol_tests", True)
            cipher_tests = kwargs.get("cipher_tests", True)
            vulnerability_tests = kwargs.get("vulnerability_tests", True)
            output_dir = Path(kwargs.get("output_dir", "output/ssl"))
            output_dir.mkdir(parents=True, exist_ok=True)
            
            logger.info(f"Starting TestSSL assessment on {target}:{port}")
            
            # Prepare output files
            json_output = output_dir / f"testssl_{target}_{port}.json"
            txt_output = output_dir / f"testssl_{target}_{port}.txt"
            
            # Find testssl.sh path
            testssl_path = None
            possible_paths = [
                "testssl.sh",
                "/usr/local/bin/testssl.sh", 
                "/opt/testssl.sh/testssl.sh",
                "/usr/share/testssl.sh/testssl.sh"
            ]
            
            for path in possible_paths:
                if shutil.which(path) or os.path.exists(path):
                    testssl_path = path
                    break
            
            if not testssl_path:
                raise Exception("testssl.sh not found in any expected location")
            
            # Build TestSSL command
            cmd = [
                testssl_path,
                "--jsonfile", str(json_output),
                "--logfile", str(txt_output),
                "--quiet",
                "--color", "0",
                "--warnings", "off"
            ]
            
            # Add severity filter
            severity_map = {
                "low": "--severity=LOW",
                "medium": "--severity=MEDIUM", 
                "high": "--severity=HIGH",
                "critical": "--severity=CRITICAL"
            }
            if severity in severity_map:
                cmd.append(severity_map[severity])
            
            # Add specific test flags
            if protocol_tests:
                cmd.append("--protocols")
            if cipher_tests:
                cmd.append("--standard")
            if vulnerability_tests:
                cmd.append("--vulnerabilities")
            
            # Add target
            cmd.append(f"{target}:{port}")
            
            # Run TestSSL
            logger.info(f"Running command: {' '.join(cmd)}")
            start_time = time.time()
            
            # Set environment variables for testssl.sh
            env = os.environ.copy()
            env['TERM'] = 'dumb'  # Prevent issues with terminal detection
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=env
            )
            execution_time = time.time() - start_time
            
            # Combine output
            full_output = ""
            if result.stdout:
                full_output += result.stdout
            if result.stderr:
                full_output += f"\n\nSTDERR:\n{result.stderr}"
            
            full_output += f"\n\nReturn code: {result.returncode}"
            
            # Always log to output manager
            if hasattr(self, 'output_manager') and self.output_manager:
                self.output_manager.log_tool_execution(
                    tool_name="testssl.sh",
                    target=f"{target}:{port}",
                    command=' '.join(cmd),
                    output=full_output,
                    service="SSL/TLS",
                    execution_time=execution_time
                )
            
            # Parse findings from JSON output
            if json_output.exists():
                findings = self._parse_testssl_json(json_output, target, port)
                results["findings"].extend(findings)
                results["json_output"] = str(json_output)
            
            # Also parse text output for additional context
            if txt_output.exists():
                try:
                    with open(txt_output, 'r', encoding='utf-8', errors='ignore') as f:
                        txt_content = f.read()
                        results["text_output"] = str(txt_output)
                except Exception as e:
                    logger.warning(f"Failed to read text output: {e}")
            
            results["command"] = ' '.join(cmd)
            results["execution_time"] = execution_time
            
        except subprocess.TimeoutExpired:
            error_msg = f"TestSSL scan timed out after {timeout} seconds"
            logger.error(error_msg)
            results["success"] = False
            results["errors"].append(error_msg)
            
        except Exception as e:
            error_msg = f"TestSSL scan failed: {str(e)}"
            logger.error(error_msg)
            results["success"] = False
            results["errors"].append(error_msg)
        
        return results
    
    def _parse_testssl_json(self, json_file: Path, target: str, port: int) -> List[Dict[str, Any]]:
        """Parse TestSSL JSON output for security findings."""
        findings = []
        
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                # TestSSL outputs one JSON object per line
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        data = json.loads(line)
                        finding = self._process_testssl_finding(data, target, port)
                        if finding:
                            findings.append(finding)
                    except json.JSONDecodeError:
                        continue
        
        except Exception as e:
            logger.error(f"Failed to parse TestSSL JSON: {e}")
        
        return findings
    
    def _process_testssl_finding(self, data: Dict[str, Any], target: str, port: int) -> Dict[str, Any]:
        """Process a single TestSSL finding."""
        try:
            finding_id = data.get('id', '')
            severity = data.get('severity', 'INFO').lower()
            finding_text = data.get('finding', '')
            section = data.get('section', '')
            
            if not finding_id or not finding_text:
                return None
            
            # Map TestSSL severity to our severity levels
            severity_map = {
                'critical': 'critical',
                'high': 'high',
                'medium': 'medium',
                'low': 'low',
                'info': 'info',
                'ok': 'info',
                'not ok': 'medium',
                'warn': 'medium'
            }
            
            mapped_severity = severity_map.get(severity, 'info')
            
            # Determine finding type based on ID and section
            finding_type = self._categorize_testssl_finding(finding_id, section)
            
            # Create finding
            finding = {
                'type': finding_type,
                'severity': mapped_severity,
                'target': target,
                'port': port,
                'title': f'SSL/TLS Issue: {finding_id}',
                'description': finding_text,
                'service': 'SSL/TLS',
                'details': {
                    'testssl_id': finding_id,
                    'section': section,
                    'original_severity': severity,
                    'raw_finding': finding_text
                }
            }
            
            # Add specific details for certain finding types
            if 'cipher' in finding_id.lower():
                finding['details']['cipher_related'] = True
            elif 'protocol' in finding_id.lower():
                finding['details']['protocol_related'] = True
            elif any(vuln in finding_id.lower() for vuln in ['heartbleed', 'poodle', 'beast', 'crime', 'breach']):
                finding['details']['vulnerability'] = True
                finding['severity'] = 'high'  # Upgrade known vulns
            
            return finding
        
        except Exception as e:
            logger.error(f"Failed to process TestSSL finding: {e}")
            return None
    
    def _categorize_testssl_finding(self, finding_id: str, section: str) -> str:
        """Categorize TestSSL finding into our finding types."""
        finding_id_lower = finding_id.lower()
        section_lower = section.lower()
        
        # Protocol-related findings
        if any(keyword in finding_id_lower for keyword in ['tls', 'ssl', 'protocol']):
            if any(weak in finding_id_lower for weak in ['1.0', '1.1', '2.0', '3.0']):
                return 'weak_protocol'
            return 'ssl_protocol_info'
        
        # Cipher-related findings
        if 'cipher' in finding_id_lower:
            if any(weak in finding_id_lower for weak in ['weak', 'null', 'anon', 'export', 'des', 'rc4']):
                return 'weak_cipher'
            return 'cipher_info'
        
        # Certificate-related findings
        if any(cert in finding_id_lower for cert in ['cert', 'certificate']):
            if 'expired' in finding_id_lower:
                return 'cert_expired'
            elif 'self' in finding_id_lower:
                return 'self_signed_cert'
            elif 'validation' in finding_id_lower:
                return 'cert_validation'
            return 'certificate_info'
        
        # Vulnerability findings
        vulnerability_map = {
            'heartbleed': 'heartbleed',
            'poodle': 'ssl_vulnerability',
            'beast': 'ssl_vulnerability',
            'crime': 'compression',
            'breach': 'compression',
            'logjam': 'ssl_vulnerability',
            'freak': 'ssl_vulnerability',
            'sweet32': 'ssl_vulnerability'
        }
        
        for vuln_name, vuln_type in vulnerability_map.items():
            if vuln_name in finding_id_lower:
                return vuln_type
        
        # Default categorization
        if 'vulnerability' in section_lower:
            return 'ssl_vulnerability'
        elif 'cipher' in section_lower:
            return 'cipher_info'
        elif 'protocol' in section_lower:
            return 'ssl_protocol_info'
        
        return 'ssl_finding'