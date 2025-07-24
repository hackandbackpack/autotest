"""RDP service plugin using netexec for AutoTest framework."""

import logging
from typing import Dict, Any, List, Optional, Tuple
import re
import socket

from ..base import PluginType, plugin
from ..base_classes.netexec_base import NetExecPlugin

logger = logging.getLogger(__name__)


@plugin(name="rdp")
class RDPPlugin(NetExecPlugin):
    """Plugin for testing RDP services using netexec and other tools."""
    
    def __init__(self):
        """Initialize RDP plugin."""
        super().__init__(protocol="rdp", default_port=3389)
        self.name = "RDP Service Plugin"
        self.version = "1.0.0"
        self.description = "Test RDP services for vulnerabilities and misconfigurations"
        self.type = PluginType.SERVICE
        
    
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
            "findings": []
        }
        
        # Check if netexec is available
        if not self.netexec_executor.is_available():
            logger.warning("netexec not available, performing limited RDP checks")
            # Still check if port is open
            if self._check_port_open(target, kwargs.get("port", 3389)):
                results["findings"].append({
                    'type': 'rdp_service_detected',
                    'title': 'RDP Service Detected',
                    'severity': 'info',
                    'description': f'RDP service is running on port {kwargs.get("port", 3389)}',
                    'recommendation': 'Install netexec (pipx install netexec) for comprehensive RDP security testing'
                })
            else:
                results["success"] = False
                results["error"] = "RDP port not accessible"
            return results
        
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
        
        # Analyze results and convert to findings list
        analysis = self._analyze_results(results)
        
        # Convert analysis dict to findings list format
        findings_list = []
        
        # Critical vulnerabilities
        if "critical_vulnerabilities" in analysis:
            for vuln_name in analysis["critical_vulnerabilities"]["vulns"]:
                findings_list.append({
                    'type': 'rdp_critical_vulnerability',
                    'title': vuln_name,
                    'severity': 'critical',
                    'description': analysis["critical_vulnerabilities"]["description"]
                })
        
        # Weak configuration
        if "weak_configuration" in analysis:
            findings_list.append({
                'type': 'rdp_weak_configuration',
                'title': 'Weak RDP Configuration',
                'severity': 'medium',
                'description': analysis["weak_configuration"]["description"],
                'details': {'issues': analysis["weak_configuration"]["issues"]}
            })
        
        # Admin access
        if "admin_access" in analysis:
            findings_list.append({
                'type': 'rdp_admin_access',
                'title': 'Administrative Access Obtained',
                'severity': 'high',
                'description': analysis["admin_access"]["description"],
                'impact': analysis["admin_access"]["impact"]
            })
        
        # Information disclosure
        if "information_disclosure" in analysis:
            findings_list.append({
                'type': 'rdp_information_disclosure',
                'title': 'Desktop Screenshot Captured',
                'severity': 'low',
                'description': analysis["information_disclosure"]["description"],
                'path': analysis["information_disclosure"]["path"]
            })
        
        results["findings"] = findings_list
        
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
        
        # Use netexec to get basic RDP info
        cmd = self.build_base_command(target, port=kwargs.get("port", 3389))
        
        try:
            result = self.execute_netexec(
                cmd, 
                kwargs.get("timeout", 30),
                self.output_manager
            )
            output = result.stdout + result.stderr
            
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
            # For now, we'll use netexec's capability
            cmd = self.build_base_command(target, additional_args=["--rdp-timeout", "5"])
            result = self.execute_netexec(cmd, 10, self.output_manager)
            output = result.stdout + result.stderr
            
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
        enc_level = config.get("encryption_level") or ""
        enc_level = enc_level.lower()
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
            # Use netexec's bluekeep module if available
            cmd = self.build_base_command(target, additional_args=["-M", "bluekeep"])
            result = self.execute_netexec(cmd, kwargs.get("timeout", 30), self.output_manager)
            output = result.stdout + result.stderr
            
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
        
        # Build command with authentication
        cmd = self.build_base_command(target, **kwargs)
        
        # Determine auth method
        if kwargs.get("password"):
            auth_results["method"] = "password"
        elif kwargs.get("hash"):
            auth_results["method"] = "hash"
        
        try:
            result = self.execute_netexec(
                cmd, 
                kwargs.get("timeout", 30),
                self.output_manager
            )
            output = result.stdout + result.stderr
            
            # Use parent class method to check authentication success
            if self.check_authentication_success(output):
                auth_results["success"] = True
                auth_results["message"] = "Authentication successful"
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
        
        # Build command with screenshot option
        cmd = self.build_base_command(
            target,
            username=kwargs.get("username"),
            password=kwargs.get("password"),
            hash=kwargs.get("hash"),
            additional_args=["--screenshot"]
        )
        
        try:
            result = self.execute_netexec(
                cmd, 
                kwargs.get("timeout", 60),
                self.output_manager
            )
            output = result.stdout + result.stderr
            
            # Parse output for screenshot path
            path_match = re.search(r'Screenshot saved to:\s*(.+)', output)
            if path_match:
                screenshot_info["captured"] = True
                screenshot_info["path"] = path_match.group(1).strip()
                
        except Exception as e:
            logger.error(f"Screenshot capture failed: {e}")
        
        return screenshot_info
    
    
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
        
        enc_level = (config.get("encryption_level") or "").lower()
        if enc_level in ["low", "none"]:
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
    
    def can_handle(self, service: str, port: int) -> bool:
        """Check if this plugin can handle the given service/port.
        
        Args:
            service: Service name detected
            port: Port number
            
        Returns:
            True if plugin should run for this service/port
        """
        # Handle known RDP ports
        if port in [3389, 3388]:
            return True
        
        # Handle services identified as RDP
        service_lower = service.lower() if service else ""
        rdp_indicators = ["rdp", "ms-wbt-server", "terminal", "remote desktop"]
        
        return any(indicator in service_lower for indicator in rdp_indicators)
