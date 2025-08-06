"""
Gobuster directory enumeration plugin for AutoTest.
"""

import logging
import subprocess
import shutil
import time
from typing import Dict, Any, List, Tuple
from pathlib import Path

from ..base import Plugin, PluginType, plugin

logger = logging.getLogger(__name__)


@plugin(name="web_gobuster")
class WebGobusterPlugin(Plugin):
    """Plugin for web directory enumeration using Gobuster."""
    
    def __init__(self):
        """Initialize the Gobuster plugin."""
        super().__init__()
        self.name = "Gobuster Directory Enumeration"
        self.version = "1.0.0"
        self.description = "Web directory and file enumeration using Gobuster"
        self.type = PluginType.SERVICE
        self.author = "AutoTest Framework"
        
        self.required_tools = ["gobuster"]
        
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
            "timeout": 300,
            "output_dir": "output/web",
            "ssl": False,
            "wordlist": "/usr/share/wordlists/dirb/common.txt",
            "threads": 10,
            "status_codes": "200,204,301,302,307,401,403"
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
        """Check if gobuster is available."""
        if skip_check or getattr(self, 'skip_tool_check', False):
            return True, {}
        
        if shutil.which("gobuster"):
            return True, {"gobuster": {"available": True, "path": shutil.which("gobuster")}}
        else:
            return False, {"gobuster": {
                "available": False, 
                "install_command": "apt install gobuster",
                "path": None
            }}
    
    def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute Gobuster directory enumeration."""
        logger.info(f"Gobuster plugin execute() called for {target} with kwargs: {kwargs}")
        
        if not self.validate_params(target=target, **kwargs):
            return {"success": False, "error": "Invalid parameters"}
        
        # Check if gobuster is available
        tool_available, tool_status = self.check_required_tools()
        if not tool_available:
            error_msg = "gobuster not found. Please install it first with: apt install gobuster"
            logger.error(error_msg)
            
            if hasattr(self, 'output_manager') and self.output_manager:
                self.output_manager.log_tool_execution(
                    tool_name="gobuster",
                    target=f"{target}:{kwargs.get('port', 80)}",
                    command="gobuster (NOT FOUND)",
                    output=error_msg,
                    service="HTTP/HTTPS",
                    execution_time=0
                )
            
            return {
                "success": False,
                "error": error_msg,
                "install_command": "apt install gobuster"
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
            timeout = kwargs.get("timeout", 300)
            ssl = kwargs.get("ssl", port == 443)
            threads = kwargs.get("threads", 10)
            status_codes = kwargs.get("status_codes", "200,204,301,302,307,401,403")
            wordlist = kwargs.get("wordlist", "/usr/share/wordlists/dirb/common.txt")
            output_dir = Path(kwargs.get("output_dir", "output/web"))
            output_dir.mkdir(parents=True, exist_ok=True)
            
            logger.info(f"Starting Gobuster directory enumeration on {target}:{port}")
            
            # Prepare output file
            output_file = output_dir / f"gobuster_{target}_{port}.txt"
            
            # Build Gobuster command
            protocol = "https" if ssl else "http"
            base_url = f"{protocol}://{target}:{port}"
            
            cmd = [
                "gobuster", "dir",
                "-u", base_url,
                "-w", wordlist,
                "-o", str(output_file),
                "-t", str(threads),
                "-s", status_codes,
                "--timeout", f"{min(timeout // 10, 30)}s",
                "--no-error"
            ]
            
            # Add SSL options if needed
            if ssl:
                cmd.extend(["-k"])  # Skip SSL certificate verification
            
            # Use fallback wordlists if default doesn't exist
            wordlists_to_try = [
                wordlist,
                "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
                "/usr/share/dirb/wordlists/common.txt",
                "/usr/share/wordlists/dirb/big.txt"
            ]
            
            wordlist_found = None
            for wl in wordlists_to_try:
                if Path(wl).exists():
                    wordlist_found = wl
                    break
            
            if not wordlist_found:
                # Create a basic wordlist
                basic_wordlist = output_dir / "basic_dirs.txt"
                basic_dirs = [
                    "admin", "administrator", "backup", "config", "test", "dev",
                    "api", "login", "panel", "dashboard", "uploads", "files",
                    "images", "css", "js", "assets", "includes", "lib", "tmp"
                ]
                with open(basic_wordlist, 'w') as f:
                    f.write('\n'.join(basic_dirs))
                wordlist_found = str(basic_wordlist)
            
            # Update command with found wordlist
            cmd[cmd.index("-w") + 1] = wordlist_found
            
            # Run Gobuster
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
                    tool_name="gobuster",
                    target=f"{target}:{port}",
                    command=' '.join(cmd),
                    output=full_output,
                    service="HTTP/HTTPS",
                    execution_time=execution_time
                )
            
            # Parse findings from output
            findings = self._parse_gobuster_output(result.stdout, target, port, protocol)
            results["findings"].extend(findings)
            
            # Also read output file if it exists
            if output_file.exists():
                try:
                    with open(output_file, 'r') as f:
                        file_findings = self._parse_gobuster_output(f.read(), target, port, protocol)
                        results["findings"].extend(file_findings)
                except Exception as e:
                    logger.warning(f"Failed to read output file: {e}")
            
            results["command"] = ' '.join(cmd)
            results["execution_time"] = execution_time
            results["output_file"] = str(output_file)
            
        except subprocess.TimeoutExpired:
            error_msg = f"Gobuster scan timed out after {timeout} seconds"
            logger.error(error_msg)
            results["success"] = False
            results["errors"].append(error_msg)
            
        except Exception as e:
            error_msg = f"Gobuster scan failed: {str(e)}"
            logger.error(error_msg)
            results["success"] = False
            results["errors"].append(error_msg)
        
        return results
    
    def _parse_gobuster_output(self, output: str, target: str, port: int, protocol: str) -> List[Dict[str, Any]]:
        """Parse Gobuster output for interesting findings."""
        findings = []
        
        if not output:
            return findings
        
        try:
            lines = output.split('\n')
            for line in lines:
                line = line.strip()
                
                # Skip empty lines and headers
                if not line or line.startswith('=') or 'Gobuster' in line:
                    continue
                
                # Look for found directories/files
                if '(Status:' in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        path = parts[0]
                        status_info = ' '.join(parts[1:])
                        
                        # Determine severity based on path and status
                        severity = self._determine_severity(path, status_info)
                        
                        finding = {
                            'type': 'directory_found',
                            'severity': severity,
                            'target': target,
                            'port': port,
                            'title': f'Directory/File Found: {path}',
                            'description': f"Found {protocol}://{target}:{port}{path} - {status_info}",
                            'service': 'HTTP/HTTPS',
                            'details': {
                                'path': path,
                                'status': status_info,
                                'url': f"{protocol}://{target}:{port}{path}"
                            }
                        }
                        findings.append(finding)
        
        except Exception as e:
            logger.error(f"Failed to parse Gobuster output: {e}")
        
        return findings
    
    def _determine_severity(self, path: str, status_info: str) -> str:
        """Determine severity based on discovered path and status."""
        path_lower = path.lower()
        
        # High-risk paths
        high_risk_paths = [
            'admin', 'administrator', 'config', 'backup', 'test', 'dev',
            'api', 'panel', 'dashboard', 'login', 'auth', 'upload'
        ]
        
        # Medium-risk paths
        medium_risk_paths = [
            'images', 'files', 'documents', 'logs', 'tmp', 'temp',
            'includes', 'lib', 'assets', 'css', 'js'
        ]
        
        # Check for high-risk paths
        if any(risk_path in path_lower for risk_path in high_risk_paths):
            return 'high'
        
        # Check for medium-risk paths
        if any(risk_path in path_lower for risk_path in medium_risk_paths):
            return 'medium'
        
        # Check status codes
        if '200' in status_info:
            return 'medium'  # Accessible content
        elif any(code in status_info for code in ['301', '302', '307']):
            return 'low'  # Redirects
        elif '403' in status_info:
            return 'medium'  # Forbidden but exists
        elif '401' in status_info:
            return 'high'  # Requires authentication
        
        return 'low'