"""
Nikto web vulnerability scanner plugin for AutoTest.
"""

import logging
import subprocess
import shutil
import time
from typing import Dict, Any, List, Tuple
from pathlib import Path

from ..base import Plugin, PluginType, plugin

logger = logging.getLogger(__name__)


@plugin(name="web_nikto")
class WebNiktoPlugin(Plugin):
    """Plugin for web vulnerability scanning using Nikto."""
    
    def __init__(self):
        """Initialize the Nikto plugin."""
        super().__init__()
        self.name = "Nikto Web Scanner"
        self.version = "1.0.0"
        self.description = "Web vulnerability scanning using Nikto"
        self.type = PluginType.SERVICE
        self.author = "AutoTest Framework"
        
        self.required_tools = ["nikto"]
        
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
            "timeout": 600,
            "output_dir": "output/web",
            "ssl": False,
            "format": "txt"
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
        """Check if nikto is available."""
        if skip_check or getattr(self, 'skip_tool_check', False):
            return True, {}
        
        if shutil.which("nikto"):
            return True, {"nikto": {"available": True, "path": shutil.which("nikto")}}
        else:
            return False, {"nikto": {
                "available": False, 
                "install_command": "apt install nikto",
                "path": None
            }}
    
    def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute Nikto web vulnerability scan."""
        logger.info(f"Nikto plugin execute() called for {target} with kwargs: {kwargs}")
        
        if not self.validate_params(target=target, **kwargs):
            return {"success": False, "error": "Invalid parameters"}
        
        # Check if nikto is available
        tool_available, tool_status = self.check_required_tools()
        if not tool_available:
            error_msg = "nikto not found. Please install it first with: apt install nikto"
            logger.error(error_msg)
            
            if hasattr(self, 'output_manager') and self.output_manager:
                self.output_manager.log_tool_execution(
                    tool_name="nikto",
                    target=f"{target}:{kwargs.get('port', 80)}",
                    command="nikto (NOT FOUND)",
                    output=error_msg,
                    service="HTTP/HTTPS",
                    execution_time=0
                )
            
            return {
                "success": False,
                "error": error_msg,
                "install_command": "apt install nikto"
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
            timeout = kwargs.get("timeout", 600)
            ssl = kwargs.get("ssl", port == 443)
            output_dir = Path(kwargs.get("output_dir", "output/web"))
            output_dir.mkdir(parents=True, exist_ok=True)
            
            logger.info(f"Starting Nikto scan on {target}:{port}")
            
            # Prepare output file
            output_file = output_dir / f"nikto_{target}_{port}.txt"
            
            # Build Nikto command
            protocol = "https" if ssl else "http"
            cmd = [
                "nikto",
                "-h", f"{protocol}://{target}:{port}",
                "-output", str(output_file),
                "-Format", "txt",
                "-timeout", str(min(timeout // 10, 60))  # Per-request timeout
            ]
            
            # Add SSL options if needed
            if ssl:
                cmd.extend(["-ssl"])
            
            # Run Nikto
            logger.info(f"Running command: {' '.join(cmd)}")
            start_time = time.time()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
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
                    tool_name="nikto",
                    target=f"{target}:{port}",
                    command=' '.join(cmd),
                    output=full_output,
                    service="HTTP/HTTPS",
                    execution_time=execution_time
                )
            
            # Parse findings from output file
            if output_file.exists():
                findings = self._parse_nikto_output(output_file, target, port)
                results["findings"].extend(findings)
                results["output_file"] = str(output_file)
            
            results["command"] = ' '.join(cmd)
            results["execution_time"] = execution_time
            
        except subprocess.TimeoutExpired:
            error_msg = f"Nikto scan timed out after {timeout} seconds"
            logger.error(error_msg)
            results["success"] = False
            results["errors"].append(error_msg)
            
        except Exception as e:
            error_msg = f"Nikto scan failed: {str(e)}"
            logger.error(error_msg)
            results["success"] = False
            results["errors"].append(error_msg)
        
        return results
    
    def _parse_nikto_output(self, output_file: Path, target: str, port: int) -> List[Dict[str, Any]]:
        """Parse Nikto output file for security findings."""
        findings = []
        
        try:
            with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Parse Nikto findings
            lines = content.split('\n')
            for line in lines:
                line = line.strip()
                
                # Skip headers and empty lines
                if not line or line.startswith('-') or line.startswith('+'):
                    continue
                
                # Look for vulnerability indicators
                if any(indicator in line.lower() for indicator in [
                    'vulnerability', 'exploit', 'injection', 'xss', 'sql',
                    'directory listing', 'backup', 'config', 'admin',
                    'default', 'weak', 'insecure'
                ]):
                    severity = self._determine_severity(line)
                    findings.append({
                        'type': 'web_vulnerability',
                        'severity': severity,
                        'target': target,
                        'port': port,
                        'title': 'Web Vulnerability Found',
                        'description': line,
                        'service': 'HTTP/HTTPS'
                    })
                
                # Check for specific high-risk findings
                if any(high_risk in line.lower() for high_risk in [
                    'sql injection', 'command injection', 'file inclusion',
                    'directory traversal', 'remote file inclusion'
                ]):
                    findings.append({
                        'type': 'critical_web_vulnerability',
                        'severity': 'critical',
                        'target': target,
                        'port': port,
                        'title': 'Critical Web Vulnerability',
                        'description': line,
                        'service': 'HTTP/HTTPS'
                    })
        
        except Exception as e:
            logger.error(f"Failed to parse Nikto output: {e}")
        
        return findings
    
    def _determine_severity(self, finding: str) -> str:
        """Determine severity based on finding content."""
        finding_lower = finding.lower()
        
        if any(critical in finding_lower for critical in [
            'sql injection', 'command injection', 'remote code execution',
            'file inclusion', 'directory traversal'
        ]):
            return 'critical'
        
        if any(high in finding_lower for high in [
            'xss', 'csrf', 'authentication bypass', 'admin', 'config'
        ]):
            return 'high'
        
        if any(medium in finding_lower for medium in [
            'directory listing', 'backup', 'default', 'information disclosure'
        ]):
            return 'medium'
        
        return 'low'