"""
Hydra authentication testing plugin for AutoTest.
REQUIRES EXPLICIT --auth-test FLAG FOR EXECUTION.
"""

import logging
import subprocess
import shutil
import time
from typing import Dict, Any, List, Tuple
from pathlib import Path

from ..base import Plugin, PluginType, plugin

logger = logging.getLogger(__name__)


@plugin(name="auth_hydra")
class AuthHydraPlugin(Plugin):
    """Plugin for authentication testing using Hydra - REQUIRES --auth-test FLAG."""
    
    def __init__(self):
        """Initialize the Hydra plugin."""
        super().__init__()
        self.name = "Hydra Authentication Testing"
        self.version = "1.0.0"
        self.description = "Authentication testing using Hydra (REQUIRES --auth-test FLAG)"
        self.type = PluginType.SERVICE
        self.author = "AutoTest Framework"
        
        self.required_tools = ["hydra"]
        
        # Services that Hydra can test
        self.supported_services = {
            22: "ssh",
            23: "telnet",
            21: "ftp",
            25: "smtp",
            53: "dns",
            80: "http-get",
            110: "pop3",
            143: "imap",
            443: "https-get",
            993: "imaps",
            995: "pop3s",
            1433: "mssql",
            3306: "mysql",
            5432: "postgres",
            5985: "winrm",
            5986: "winrm-ssl"
        }
    
    def can_handle(self, service: str, port: int) -> bool:
        """Check if this plugin can handle the given service/port - ONLY if auth testing enabled."""
        # This plugin should only be considered if auth testing is explicitly enabled
        # The actual authorization check happens in validate_params
        return (
            port in self.supported_services or
            any(svc in service.lower() for svc in ['ssh', 'ftp', 'http', 'telnet', 'smtp'])
        )
    
    def get_required_params(self) -> List[str]:
        """Get required parameters."""
        return ["target", "auth_test_enabled"]
    
    def get_optional_params(self) -> Dict[str, Any]:
        """Get optional parameters with defaults."""
        return {
            "port": 22,
            "timeout": 300,
            "output_dir": "output/auth",
            "service": "ssh",
            "username_list": "/usr/share/wordlists/metasploit/unix_users.txt",
            "password_list": "/usr/share/wordlists/rockyou.txt",
            "threads": 4,
            "max_attempts": 10,
            "stop_on_success": True
        }
    
    def validate_params(self, **kwargs) -> bool:
        """Validate parameters - MUST have auth_test_enabled=True."""
        if not kwargs.get("target"):
            logger.error("Target parameter is required")
            return False
        
        # CRITICAL: Check for authentication testing authorization
        if not kwargs.get("auth_test_enabled", False):
            logger.error("Authentication testing requires explicit authorization via --auth-test flag")
            return False
        
        port = kwargs.get("port", 22)
        if not isinstance(port, int) or port < 1 or port > 65535:
            logger.error(f"Invalid port: {port}")
            return False
        
        return True
    
    def check_required_tools(self, skip_check: bool = False) -> Tuple[bool, Dict[str, Dict[str, Any]]]:
        """Check if hydra is available."""
        if skip_check or getattr(self, 'skip_tool_check', False):
            return True, {}
        
        if shutil.which("hydra"):
            return True, {"hydra": {"available": True, "path": shutil.which("hydra")}}
        else:
            return False, {"hydra": {
                "available": False,
                "install_command": "apt install hydra",
                "path": None
            }}
    
    def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute Hydra authentication testing - ONLY IF AUTHORIZED."""
        logger.info(f"Hydra plugin execute() called for {target} with kwargs: {kwargs}")
        
        # CRITICAL: Validate authorization first
        if not self.validate_params(target=target, **kwargs):
            return {"success": False, "error": "Authentication testing not authorized or invalid parameters"}
        
        # Check if hydra is available
        tool_available, tool_status = self.check_required_tools()
        if not tool_available:
            error_msg = "hydra not found. Please install it first with: apt install hydra"
            logger.error(error_msg)
            
            if hasattr(self, 'output_manager') and self.output_manager:
                self.output_manager.log_tool_execution(
                    tool_name="hydra",
                    target=f"{target}:{kwargs.get('port', 22)}",
                    command="hydra (NOT FOUND)",
                    output=error_msg,
                    service="Authentication Testing",
                    execution_time=0
                )
            
            return {
                "success": False,
                "error": error_msg,
                "install_command": "apt install hydra"
            }
        
        results = {
            "success": True,
            "target": target,
            "service": "Authentication Testing",
            "findings": [],
            "errors": [],
            "warning": "AUTHENTICATION TESTING PERFORMED - ENSURE PROPER AUTHORIZATION"
        }
        
        try:
            port = kwargs.get("port", 22)
            timeout = kwargs.get("timeout", 300)
            service = kwargs.get("service", self.supported_services.get(port, "ssh"))
            username_list = kwargs.get("username_list", "/usr/share/wordlists/metasploit/unix_users.txt")
            password_list = kwargs.get("password_list", "/usr/share/wordlists/rockyou.txt")
            threads = kwargs.get("threads", 4)
            max_attempts = kwargs.get("max_attempts", 10)
            stop_on_success = kwargs.get("stop_on_success", True)
            output_dir = Path(kwargs.get("output_dir", "output/auth"))
            output_dir.mkdir(parents=True, exist_ok=True)
            
            logger.warning(f"STARTING AUTHENTICATION TESTING on {target}:{port} - ENSURE PROPER AUTHORIZATION")
            
            # Prepare output file
            output_file = output_dir / f"hydra_{target}_{port}_{service}.txt"
            
            # Check if wordlists exist, create basic ones if not
            if not Path(username_list).exists():
                logger.warning(f"Username list {username_list} not found, using basic list")
                basic_users = output_dir / "basic_users.txt"
                with open(basic_users, 'w') as f:
                    f.write("\\n".join(["admin", "administrator", "root", "user", "test", "guest", "demo"]))
                username_list = str(basic_users)
            
            if not Path(password_list).exists():
                logger.warning(f"Password list {password_list} not found, using basic list")
                basic_passwords = output_dir / "basic_passwords.txt"
                with open(basic_passwords, 'w') as f:
                    f.write("\\n".join(["password", "123456", "admin", "test", "guest", "root", "demo"]))
                password_list = str(basic_passwords)
            
            # Build Hydra command
            cmd = [
                "hydra",
                "-L", username_list,
                "-P", password_list,
                "-t", str(threads),
                "-W", str(timeout),
                "-o", str(output_file),
                "-f" if stop_on_success else "-c", str(max_attempts),
                "-v",  # Verbose output
                f"{target}:{port}",
                service
            ]
            
            # Add service-specific options
            if service in ["http-get", "https-get"]:
                cmd.extend(["-m", "/"])  # Default path for HTTP
            elif service == "ssh":
                cmd.extend(["-e", "nsr"])  # Try null, same as login, reverse
            
            # Run Hydra with WARNING
            logger.warning(f"EXECUTING AUTHENTICATION ATTACK: {' '.join(cmd)}")
            start_time = time.time()
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 60
            )
            execution_time = time.time() - start_time
            
            # Combine output with warnings
            full_output = "*** AUTHENTICATION TESTING PERFORMED ***\\n"
            full_output += "*** ENSURE PROPER AUTHORIZATION AND LEGAL COMPLIANCE ***\\n\\n"
            
            if result.stdout:
                full_output += result.stdout
            if result.stderr:
                full_output += f"\\n\\nSTDERR:\\n{result.stderr}"
            
            full_output += f"\\n\\nReturn code: {result.returncode}"
            
            # Always log to output manager with warnings
            if hasattr(self, 'output_manager') and self.output_manager:
                self.output_manager.log_tool_execution(
                    tool_name="hydra",
                    target=f"{target}:{port}",
                    command=' '.join(cmd),
                    output=full_output,
                    service="Authentication Testing",
                    execution_time=execution_time
                )
            
            # Parse findings
            findings = self._parse_hydra_output(result.stdout, target, port, service)
            results["findings"].extend(findings)
            
            # Also check output file
            if output_file.exists():
                try:
                    with open(output_file, 'r') as f:
                        file_content = f.read()
                        file_findings = self._parse_hydra_output(file_content, target, port, service)
                        results["findings"].extend(file_findings)
                except Exception as e:
                    logger.warning(f"Failed to read output file: {e}")
            
            results["command"] = ' '.join(cmd)
            results["execution_time"] = execution_time
            results["output_file"] = str(output_file)
            
        except subprocess.TimeoutExpired:
            error_msg = f"Hydra authentication test timed out after {timeout + 60} seconds"
            logger.error(error_msg)
            results["success"] = False
            results["errors"].append(error_msg)
            
        except Exception as e:
            error_msg = f"Hydra authentication test failed: {str(e)}"
            logger.error(error_msg)
            results["success"] = False
            results["errors"].append(error_msg)
        
        return results
    
    def _parse_hydra_output(self, output: str, target: str, port: int, service: str) -> List[Dict[str, Any]]:
        """Parse Hydra output for authentication findings."""
        findings = []
        
        if not output or not output.strip():
            return findings
        
        try:
            lines = output.split('\\n')
            
            for line in lines:
                line = line.strip()
                
                # Look for successful logins
                if '[' in line and '] host:' in line and 'login:' in line and 'password:' in line:
                    # Parse format: [PORT][SERVICE] host: IP   login: USER   password: PASS
                    try:
                        parts = line.split()
                        login_idx = parts.index('login:')
                        password_idx = parts.index('password:')
                        
                        if login_idx + 1 < len(parts) and password_idx + 1 < len(parts):
                            username = parts[login_idx + 1]
                            password = parts[password_idx + 1]
                            
                            finding = {
                                'type': 'weak_credentials',
                                'severity': 'critical',
                                'target': target,
                                'port': port,
                                'title': f'Weak Credentials Found: {service.upper()}',
                                'description': f'Successful authentication with {username}:{password}',
                                'service': service.upper(),
                                'details': {
                                    'username': username,
                                    'password': password,
                                    'service': service,
                                    'method': 'brute_force',
                                    'warning': 'AUTHENTICATION TESTING - ENSURE AUTHORIZATION'
                                }
                            }
                            findings.append(finding)
                    except (ValueError, IndexError):
                        # If parsing fails, still record as generic finding
                        finding = {
                            'type': 'authentication_success',
                            'severity': 'critical',
                            'target': target,
                            'port': port,
                            'title': 'Authentication Success Detected',
                            'description': line,
                            'service': service.upper(),
                            'details': {
                                'raw_output': line,
                                'service': service
                            }
                        }
                        findings.append(finding)
                
                # Look for other interesting findings
                elif any(indicator in line.lower() for indicator in [
                    'valid password', 'login successful', 'authentication successful'
                ]):
                    finding = {
                        'type': 'authentication_finding',
                        'severity': 'high',
                        'target': target,
                        'port': port,
                        'title': 'Authentication Finding',
                        'description': line,
                        'service': service.upper(),
                        'details': {
                            'raw_output': line,
                            'service': service
                        }
                    }
                    findings.append(finding)
        
        except Exception as e:
            logger.error(f"Failed to parse Hydra output: {e}")
        
        return findings