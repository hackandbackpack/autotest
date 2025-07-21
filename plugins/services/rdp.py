"""RDP service plugin using NetExec for AutoTest framework."""

import subprocess
import logging
from typing import Dict, Any, List, Optional
import re
import socket

from ..base import Plugin, PluginType, plugin

logger = logging.getLogger(__name__)


@plugin(name="rdp")
class RDPPlugin(Plugin):
    """Plugin for testing RDP services using NetExec and other tools."""
    
    def __init__(self):
        """Initialize RDP plugin."""
        super().__init__()
        self.name = "RDP Service Plugin"
        self.version = "1.0.0"
        self.description = "Test RDP services for vulnerabilities and misconfigurations"
        self.type = PluginType.SERVICE
        self.netexec_path = self._find_netexec()
        
    def _find_netexec(self) -> str:
        """Find NetExec executable path.
        
        Returns:
            Path to netexec executable
        """
        for cmd in ["netexec", "nxc", "crackmapexec", "cme"]:
            try:
                result = subprocess.run([cmd, "--version"], 
                                     capture_output=True, text=True)
                if result.returncode == 0:
                    return cmd
            except FileNotFoundError:
                continue
        
        logger.warning("NetExec not found in PATH")
        return "netexec"
    
    def get_required_params(self) -> List[str]:
        """Get required parameters for RDP plugin.
        
        Returns:
            List of required parameter names
        """
        return ["target"]
    
    def get_optional_params(self) -> Dict[str, Any]:
        """Get optional parameters with defaults.
        
        Returns:
            Dictionary of optional parameters and their defaults
        """
        return {
            "username": None,
            "password": None,
            "domain": None,
            "hash": None,
            "local_auth": False,
            "nla_check": True,
            "encryption_check": True,
            "screenshot": False,
            "timeout": 30,
            "port": 3389,
            "threads": 5
        }
    
    def validate_params(self, **kwargs) -> bool:
        """Validate RDP plugin parameters.
        
        Args:
            **kwargs: Parameters to validate
            
        Returns:
            True if parameters are valid
        """
        if not kwargs.get("target"):
            logger.error("Target parameter is required")
            return False
        
        # Validate port
        port = kwargs.get("port", 3389)
        if not isinstance(port, int) or port < 1 or port > 65535:
            logger.error(f"Invalid port: {port}")
            return False
        
        # Validate authentication if provided
        if kwargs.get("username") and not (kwargs.get("password") or kwargs.get("hash")):
            logger.error("Password or hash required when username is provided")
            return False
        
        return True
    
    def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute RDP testing.
        
        Args:
            target: Target host or network
            **kwargs: Additional parameters
            
        Returns:
            Dictionary containing test results
        """
        if not self.validate_params(target=target, **kwargs):
            return {"success": False, "error": "Invalid parameters"}
        
        results = {
            "success": True,
            "target": target,
            "service": "RDP",
            "port": kwargs.get("port", 3389),
            "vulnerabilities": [],
            "configuration": {},
            "findings": {}
        }
        
        # Check if RDP port is open
        if not self._check_port_open(target, kwargs.get("port", 3389)):
            results["success"] = False
            results["error"] = "RDP port not accessible"
            return results
        
        # Get RDP configuration info
        results["configuration"] = self._get_rdp_info(target, kwargs)
        
        # Check for vulnerabilities
        results["vulnerabilities"] = self._check_vulnerabilities(target, kwargs)
        
        # If credentials provided, attempt authentication
        if kwargs.get("username"):
            auth_results = self._test_authentication(target, kwargs)
            results["authentication"] = auth_results
            
            # Take screenshot if requested and auth successful
            if kwargs.get("screenshot") and auth_results.get("success"):
                results["screenshot"] = self._take_screenshot(target, kwargs)
        
        # Analyze results
        results["findings"] = self._analyze_results(results)
        
        return results
    
    def _check_port_open(self, host: str, port: int) -> bool:
        """Check if RDP port is open.
        
        Args:
            host: Target host
            port: RDP port
            
        Returns:
            True if port is open
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception as e:
            logger.error(f"Port check failed: {e}")
            return False
    
    def _get_rdp_info(self, target: str, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """Get RDP configuration information.
        
        Args:
            target: Target host
            kwargs: Plugin parameters
            
        Returns:
            RDP configuration info
        """
        info = {
            "nla_required": None,
            "encryption_level": None,
            "rdp_version": None,
            "security_layer": None
        }
        
        # Use NetExec to get basic RDP info
        cmd = [self.netexec_path, "rdp", target]
        
        if kwargs.get("port", 3389) != 3389:
            cmd.extend(["--port", str(kwargs["port"])])
        
        try:
            output = self._run_command(cmd, kwargs.get("timeout", 30))
            
            # Parse NLA status
            if "NLA:" in output:
                info["nla_required"] = "Enabled" in output
            
            # Parse encryption info
            if "Encryption:" in output:
                enc_match = re.search(r'Encryption:\s*(\w+)', output)
                if enc_match:
                    info["encryption_level"] = enc_match.group(1)
            
            # Parse RDP version
            if "RDP" in output and "version" in output.lower():
                ver_match = re.search(r'RDP\s*version\s*(\d+\.\d+)', output, re.I)
                if ver_match:
                    info["rdp_version"] = ver_match.group(1)
            
        except Exception as e:
            logger.error(f"Failed to get RDP info: {e}")
        
        # Additional checks using other methods if available
        if kwargs.get("nla_check", True):
            info["nla_details"] = self._check_nla_detailed(target, kwargs)
        
        return info
    
    def _check_nla_detailed(self, target: str, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """Perform detailed NLA check.
        
        Args:
            target: Target host
            kwargs: Plugin parameters
            
        Returns:
            NLA details
        """
        nla_info = {
            "enabled": False,
            "enforced": False,
            "credssp_supported": False
        }
        
        # Try to connect without NLA to see if it's enforced
        try:
            # This would use rdp-sec-check or similar tool if available
            # For now, we'll use NetExec's capability
            cmd = [self.netexec_path, "rdp", target, "--rdp-timeout", "5"]
            output = self._run_command(cmd, 10)
            
            if "NLA_REQUIRED" in output or "CredSSP" in output:
                nla_info["enabled"] = True
                nla_info["enforced"] = True
            elif "NLA" in output:
                nla_info["enabled"] = True
                
        except Exception as e:
            logger.debug(f"NLA check failed: {e}")
        
        return nla_info
    
    def _check_vulnerabilities(self, target: str, kwargs: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for RDP vulnerabilities.
        
        Args:
            target: Target host
            kwargs: Plugin parameters
            
        Returns:
            List of detected vulnerabilities
        """
        vulns = []
        
        # Check for BlueKeep (CVE-2019-0708)
        if self._check_bluekeep(target, kwargs):
            vulns.append({
                "name": "BlueKeep (CVE-2019-0708)",
                "severity": "CRITICAL",
                "description": "System is vulnerable to BlueKeep RCE vulnerability",
                "remediation": "Apply CVE-2019-0708 security update immediately",
                "cve": "CVE-2019-0708"
            })
        
        # Check for missing NLA
        config = self._get_rdp_info(target, kwargs)
        if config.get("nla_required") is False:
            vulns.append({
                "name": "NLA Not Required",
                "severity": "MEDIUM",
                "description": "Network Level Authentication is not enforced",
                "remediation": "Enable NLA requirement in system properties",
                "impact": "Allows pre-authentication attacks and credential brute forcing"
            })
        
        # Check for weak encryption
        enc_level = config.get("encryption_level", "").lower()
        if enc_level in ["low", "client compatible", "none"]:
            vulns.append({
                "name": "Weak RDP Encryption",
                "severity": "MEDIUM",
                "description": f"Weak encryption level: {enc_level}",
                "remediation": "Configure RDP to use High or FIPS encryption level"
            })
        
        # Check for DoS vulnerabilities
        if self._check_rdp_dos(target, kwargs):
            vulns.append({
                "name": "RDP DoS Vulnerability",
                "severity": "LOW",
                "description": "RDP service susceptible to denial of service",
                "remediation": "Apply latest Windows security updates"
            })
        
        return vulns
    
    def _check_bluekeep(self, target: str, kwargs: Dict[str, Any]) -> bool:
        """Check for BlueKeep vulnerability.
        
        Args:
            target: Target host
            kwargs: Plugin parameters
            
        Returns:
            True if vulnerable
        """
        try:
            # Use NetExec's bluekeep module if available
            cmd = [self.netexec_path, "rdp", target, "-M", "bluekeep"]
            output = self._run_command(cmd, kwargs.get("timeout", 30))
            
            return "VULNERABLE" in output.upper()
        except Exception as e:
            logger.debug(f"BlueKeep check failed: {e}")
            return False
    
    def _check_rdp_dos(self, target: str, kwargs: Dict[str, Any]) -> bool:
        """Check for RDP DoS vulnerabilities.
        
        Args:
            target: Target host
            kwargs: Plugin parameters
            
        Returns:
            True if vulnerable
        """
        # This would implement checks for known DoS vulnerabilities
        # For safety, we'll just return False in production
        return False
    
    def _test_authentication(self, target: str, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """Test RDP authentication.
        
        Args:
            target: Target host
            kwargs: Plugin parameters
            
        Returns:
            Authentication test results
        """
        auth_results = {
            "success": False,
            "method": None,
            "message": None
        }
        
        cmd = [self.netexec_path, "rdp", target]
        
        # Add credentials
        cmd.extend(["-u", kwargs["username"]])
        
        if kwargs.get("password"):
            cmd.extend(["-p", kwargs["password"]])
            auth_results["method"] = "password"
        elif kwargs.get("hash"):
            cmd.extend(["-H", kwargs["hash"]])
            auth_results["method"] = "hash"
        
        if kwargs.get("domain"):
            cmd.extend(["-d", kwargs["domain"]])
        
        if kwargs.get("local_auth"):
            cmd.append("--local-auth")
        
        # Add port if not default
        if kwargs.get("port", 3389) != 3389:
            cmd.extend(["--port", str(kwargs["port"])])
        
        try:
            output = self._run_command(cmd, kwargs.get("timeout", 30))
            
            if "Administrator" in output or "STATUS_SUCCESS" in output:
                auth_results["success"] = True
                auth_results["message"] = "Authentication successful"
                
                # Check if admin
                if "Administrator" in output or "(Pwn3d!)" in output:
                    auth_results["admin_access"] = True
            else:
                auth_results["message"] = "Authentication failed"
                
        except Exception as e:
            auth_results["message"] = f"Authentication test failed: {e}"
            logger.error(auth_results["message"])
        
        return auth_results
    
    def _take_screenshot(self, target: str, kwargs: Dict[str, Any]) -> Dict[str, Any]:
        """Take RDP screenshot if possible.
        
        Args:
            target: Target host
            kwargs: Plugin parameters
            
        Returns:
            Screenshot results
        """
        screenshot_info = {
            "captured": False,
            "path": None
        }
        
        # NetExec RDP screenshot capability
        cmd = [self.netexec_path, "rdp", target]
        cmd.extend(["-u", kwargs["username"]])
        
        if kwargs.get("password"):
            cmd.extend(["-p", kwargs["password"]])
        elif kwargs.get("hash"):
            cmd.extend(["-H", kwargs["hash"]])
        
        cmd.append("--screenshot")
        
        try:
            output = self._run_command(cmd, kwargs.get("timeout", 60))
            
            # Parse output for screenshot path
            path_match = re.search(r'Screenshot saved to:\s*(.+)', output)
            if path_match:
                screenshot_info["captured"] = True
                screenshot_info["path"] = path_match.group(1).strip()
                
        except Exception as e:
            logger.error(f"Screenshot capture failed: {e}")
        
        return screenshot_info
    
    def _run_command(self, cmd: List[str], timeout: int) -> str:
        """Run a command with timeout.
        
        Args:
            cmd: Command to run
            timeout: Timeout in seconds
            
        Returns:
            Command output
        """
        logger.debug(f"Running command: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            if result.returncode != 0 and result.stderr:
                logger.warning(f"Command stderr: {result.stderr}")
            
            return result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            raise Exception(f"Command timed out after {timeout} seconds")
        except Exception as e:
            raise Exception(f"Command execution failed: {e}")
    
    def _analyze_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze results for security findings.
        
        Args:
            results: Test results
            
        Returns:
            Security findings
        """
        findings = {}
        
        # Check for critical vulnerabilities
        critical_vulns = [v for v in results.get("vulnerabilities", []) 
                         if v.get("severity") == "CRITICAL"]
        if critical_vulns:
            findings["critical_vulnerabilities"] = {
                "severity": "CRITICAL",
                "count": len(critical_vulns),
                "vulns": [v["name"] for v in critical_vulns],
                "description": "Critical vulnerabilities require immediate patching"
            }
        
        # Check for weak configuration
        config = results.get("configuration", {})
        weak_configs = []
        
        if config.get("nla_required") is False:
            weak_configs.append("NLA not enforced")
        
        if config.get("encryption_level", "").lower() in ["low", "none"]:
            weak_configs.append(f"Weak encryption: {config['encryption_level']}")
        
        if weak_configs:
            findings["weak_configuration"] = {
                "severity": "MEDIUM",
                "issues": weak_configs,
                "description": "RDP configuration weaknesses detected"
            }
        
        # Check authentication results
        auth = results.get("authentication", {})
        if auth.get("success") and auth.get("admin_access"):
            findings["admin_access"] = {
                "severity": "HIGH",
                "description": "Administrative access obtained via RDP",
                "impact": "Full system compromise possible"
            }
        
        # Check for information disclosure
        if results.get("screenshot", {}).get("captured"):
            findings["information_disclosure"] = {
                "severity": "LOW",
                "description": "Desktop screenshot captured",
                "path": results["screenshot"]["path"]
            }
        
        return findings