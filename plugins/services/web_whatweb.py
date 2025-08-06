"""
WhatWeb technology identification plugin for AutoTest.
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


@plugin(name="web_whatweb")
class WebWhatWebPlugin(Plugin):
    """Plugin for web technology identification using WhatWeb."""
    
    def __init__(self):
        """Initialize the WhatWeb plugin."""
        super().__init__()
        self.name = "WhatWeb Technology Scanner"
        self.version = "1.0.0"
        self.description = "Web technology identification using WhatWeb"
        self.type = PluginType.SERVICE
        self.author = "AutoTest Framework"
        
        self.required_tools = ["whatweb"]
        
        # Common web ports
        self.web_ports = [80, 443, 8080, 8443, 3000, 8000, 9000]
    
    def can_handle(self, service: str, port: int) -> bool:
        """Check if this plugin can handle the given service/port."""
        return (
            port in self.web_ports or
            'http' in service.lower() or
            'web' in service.lower()
        )
    
    def get_required_params(self) -> List[str]:
        """Get required parameters."""
        return ["target"]
    
    def get_optional_params(self) -> Dict[str, Any]:
        """Get optional parameters with defaults."""
        return {
            "port": 80,
            "timeout": 60,
            "output_dir": "output/web",
            "ssl": False,
            "aggression": 1
        }
    
    def validate_params(self, **kwargs) -> bool:
        """Validate parameters."""
        if not kwargs.get("target"):
            logger.error("Target parameter is required")
            return False
        
        port = kwargs.get("port", 80)
        if not isinstance(port, int) or port < 1 or port > 65535:
            logger.error(f"Invalid port: {port}")
            return False
        
        return True
    
    def check_required_tools(self, skip_check: bool = False) -> Tuple[bool, Dict[str, Dict[str, Any]]]:
        """Check if whatweb is available."""
        if skip_check or getattr(self, 'skip_tool_check', False):
            return True, {}
        
        if shutil.which("whatweb"):
            return True, {"whatweb": {"available": True, "path": shutil.which("whatweb")}}
        else:
            return False, {"whatweb": {
                "available": False, 
                "install_command": "apt install whatweb",
                "path": None
            }}
    
    def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute WhatWeb technology identification."""
        logger.info(f"WhatWeb plugin execute() called for {target} with kwargs: {kwargs}")
        
        if not self.validate_params(target=target, **kwargs):
            return {"success": False, "error": "Invalid parameters"}
        
        # Check if whatweb is available
        tool_available, tool_status = self.check_required_tools()
        if not tool_available:
            error_msg = "whatweb not found. Please install it first with: apt install whatweb"
            logger.error(error_msg)
            
            if hasattr(self, 'output_manager') and self.output_manager:
                self.output_manager.log_tool_execution(
                    tool_name="whatweb",
                    target=f"{target}:{kwargs.get('port', 80)}",
                    command="whatweb (NOT FOUND)",
                    output=error_msg,
                    service="HTTP/HTTPS",
                    execution_time=0
                )
            
            return {
                "success": False,
                "error": error_msg,
                "install_command": "apt install whatweb"
            }
        
        results = {
            "success": True,
            "target": target,
            "service": "HTTP/HTTPS",
            "findings": [],
            "errors": []
        }
        
        try:
            port = kwargs.get("port", 80)
            timeout = kwargs.get("timeout", 60)
            ssl = kwargs.get("ssl", port == 443)
            aggression = kwargs.get("aggression", 1)
            output_dir = Path(kwargs.get("output_dir", "output/web"))
            output_dir.mkdir(parents=True, exist_ok=True)
            
            logger.info(f"Starting WhatWeb scan on {target}:{port}")
            
            # Prepare output files
            json_output = output_dir / f"whatweb_{target}_{port}.json"
            txt_output = output_dir / f"whatweb_{target}_{port}.txt"
            
            # Build WhatWeb command
            protocol = "https" if ssl else "http"
            url = f"{protocol}://{target}:{port}"
            
            cmd = [
                "whatweb",
                "--log-json", str(json_output),
                "--log-brief", str(txt_output),
                f"--aggression={aggression}",
                "--max-threads=1",
                f"--read-timeout={timeout}",
                "--user-agent", "Mozilla/5.0 (compatible; AutoTest Scanner)",
                url
            ]
            
            # Run WhatWeb
            logger.info(f"Running command: {' '.join(cmd)}")
            start_time = time.time()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 30  # Extra buffer for WhatWeb overhead
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
                    tool_name="whatweb",
                    target=f"{target}:{port}",
                    command=' '.join(cmd),
                    output=full_output,
                    service="HTTP/HTTPS",
                    execution_time=execution_time
                )
            
            # Parse findings from JSON output
            if json_output.exists():
                findings = self._parse_whatweb_json(json_output, target, port)
                results["findings"].extend(findings)
                results["json_output"] = str(json_output)
            
            # Also parse text output if available
            if txt_output.exists():
                try:
                    with open(txt_output, 'r', encoding='utf-8', errors='ignore') as f:
                        txt_content = f.read()
                        results["text_summary"] = txt_content
                except Exception as e:
                    logger.warning(f"Failed to read text output: {e}")
            
            results["command"] = ' '.join(cmd)
            results["execution_time"] = execution_time
            results["txt_output"] = str(txt_output)
            
        except subprocess.TimeoutExpired:
            error_msg = f"WhatWeb scan timed out after {timeout + 30} seconds"
            logger.error(error_msg)
            results["success"] = False
            results["errors"].append(error_msg)
            
        except Exception as e:
            error_msg = f"WhatWeb scan failed: {str(e)}"
            logger.error(error_msg)
            results["success"] = False
            results["errors"].append(error_msg)
        
        return results
    
    def _parse_whatweb_json(self, json_file: Path, target: str, port: int) -> List[Dict[str, Any]]:
        """Parse WhatWeb JSON output for technology findings."""
        findings = []
        
        try:
            with open(json_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            if not isinstance(data, list):
                data = [data]
            
            for entry in data:
                if not isinstance(entry, dict):
                    continue
                
                plugins = entry.get('plugins', {})
                target_url = entry.get('target', '')
                
                # Extract technology findings
                technologies = []
                security_findings = []
                
                for plugin_name, plugin_data in plugins.items():
                    if not isinstance(plugin_data, dict):
                        continue
                    
                    version = plugin_data.get('version', [''])[0] if plugin_data.get('version') else ''
                    string_matches = plugin_data.get('string', [])
                    
                    # Check for security-relevant technologies
                    security_issues = self._check_security_implications(plugin_name, version, string_matches)
                    security_findings.extend(security_issues)
                    
                    # Add technology identification
                    tech_info = f"{plugin_name}"
                    if version:
                        tech_info += f" {version}"
                    
                    technologies.append(tech_info)
                
                # Add technology identification finding
                if technologies:
                    findings.append({
                        'type': 'web_technology',
                        'severity': 'info',
                        'target': target,
                        'port': port,
                        'title': 'Web Technologies Identified',
                        'description': f"Technologies: {', '.join(technologies)}",
                        'service': 'HTTP/HTTPS',
                        'details': {
                            'technologies': technologies,
                            'url': target_url
                        }
                    })
                
                # Add security findings
                findings.extend(security_findings)
        
        except Exception as e:
            logger.error(f"Failed to parse WhatWeb JSON: {e}")
        
        return findings
    
    def _check_security_implications(self, plugin_name: str, version: str, string_matches: List[str]) -> List[Dict[str, Any]]:
        """Check for security implications of identified technologies."""
        findings = []
        plugin_lower = plugin_name.lower()
        
        # Check for outdated/vulnerable software
        vulnerable_versions = {
            'apache': {'2.2', '2.0', '1.3'},
            'nginx': {'1.0', '0.8', '0.7'},
            'iis': {'6.0', '7.0', '7.5'},
            'php': {'5.6', '5.5', '5.4', '5.3', '5.2', '7.0', '7.1'},
            'jquery': {'1.0', '1.1', '1.2', '1.3', '1.4', '1.5', '1.6', '1.7', '1.8'},
            'wordpress': {'4.', '3.', '2.'},
            'drupal': {'7.', '6.', '8.0', '8.1', '8.2', '8.3'},
            'joomla': {'3.0', '3.1', '3.2', '3.3', '3.4', '2.'},
        }
        
        # Check for version-based vulnerabilities
        for tech, vuln_versions in vulnerable_versions.items():
            if tech in plugin_lower and version:
                for vuln_ver in vuln_versions:
                    if version.startswith(vuln_ver):
                        findings.append({
                            'type': 'outdated_software',
                            'severity': 'high',
                            'target': '',  # Will be filled by caller
                            'port': 0,     # Will be filled by caller
                            'title': f'Outdated {plugin_name} Version',
                            'description': f"Potentially vulnerable {plugin_name} version {version} detected",
                            'service': 'HTTP/HTTPS',
                            'details': {
                                'software': plugin_name,
                                'version': version,
                                'vulnerability_type': 'outdated_version'
                            }
                        })
                        break
        
        # Check for security-sensitive technologies
        security_sensitive = {
            'phpmyadmin': 'high',
            'adminer': 'medium', 
            'webmin': 'high',
            'cpanel': 'medium',
            'plesk': 'medium',
            'tomcat': 'medium',
            'jenkins': 'high',
            'gitlab': 'medium',
            'grafana': 'medium'
        }
        
        for sensitive_tech, severity in security_sensitive.items():
            if sensitive_tech in plugin_lower:
                findings.append({
                    'type': 'sensitive_application',
                    'severity': severity,
                    'target': '',  # Will be filled by caller
                    'port': 0,     # Will be filled by caller
                    'title': f'Sensitive Application: {plugin_name}',
                    'description': f"Administrative/sensitive application {plugin_name} detected",
                    'service': 'HTTP/HTTPS',
                    'details': {
                        'application': plugin_name,
                        'version': version,
                        'risk': 'administrative_interface'
                    }
                })
        
        # Check for information disclosure
        disclosure_indicators = [
            'server-status', 'server-info', 'phpinfo', 'test.php',
            'debug', 'error', 'exception', 'stack trace'
        ]
        
        for string_match in string_matches:
            if any(indicator in string_match.lower() for indicator in disclosure_indicators):
                findings.append({
                    'type': 'information_disclosure',
                    'severity': 'medium',
                    'target': '',  # Will be filled by caller
                    'port': 0,     # Will be filled by caller  
                    'title': 'Information Disclosure',
                    'description': f"Potential information disclosure: {string_match}",
                    'service': 'HTTP/HTTPS',
                    'details': {
                        'disclosure_type': string_match,
                        'plugin': plugin_name
                    }
                })
        
        return findings