"""SMB service plugin using netexec for AutoTest framework."""

import logging
from typing import Dict, Any, List, Optional, Tuple
import re

from ..base import PluginType, plugin
from ..base_classes.netexec_base import NetExecPlugin

logger = logging.getLogger(__name__)


@plugin(name="smb")
class SMBPlugin(NetExecPlugin):
    """Plugin for testing SMB services using netexec."""
    
    def __init__(self):
        """Initialize SMB plugin."""
        super().__init__(protocol="smb", default_port=445)
        self.name = "SMB Service Plugin"
        self.version = "1.0.0"
        self.description = "Test SMB services for vulnerabilities using netexec"
        self.type = PluginType.SERVICE
        
    
    def get_required_params(self) -> List[str]:
        """Get required parameters for SMB plugin.
        
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
            "shares": True,
            "sessions": True,
            "disks": False,
            "users": False,
            "groups": False,
            "loggedon_users": False,
            "pass_pol": False,
            "sam": False,
            "lsa": False,
            "ntds": False,
            "timeout": 30,
            "threads": 10,
            "port": 445
        }
    
    def validate_params(self, **kwargs) -> bool:
        """Validate SMB plugin parameters.
        
        Args:
            **kwargs: Parameters to validate
            
        Returns:
            True if parameters are valid
        """
        if not kwargs.get("target"):
            logger.error("Target parameter is required")
            return False
        
        # Validate authentication - need either password or hash
        if kwargs.get("username") and not (kwargs.get("password") or kwargs.get("hash")):
            logger.error("Password or hash required when username is provided")
            return False
        
        # Validate port
        port = kwargs.get("port", 445)
        if not isinstance(port, int) or port < 1 or port > 65535:
            logger.error(f"Invalid port: {port}")
            return False
        
        return True
    
    def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute SMB testing using netexec.
        
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
            "service": "SMB",
            "port": kwargs.get("port", 445),
            "vulnerabilities": [],
            "shares": [],
            "users": [],
            "sessions": [],
            "findings": {}
        }
        
        # Build base command using parent class method
        base_cmd = self.build_base_command(target, **kwargs)
        
        # Test basic connectivity
        try:
            result = self.execute_netexec(
                base_cmd, 
                kwargs.get("timeout", 30),
                self.output_manager
            )
            output = result.stdout + result.stderr
            # Use parent class connectivity parser as base
            connectivity = self.parse_connectivity_output(output)
            # Enhance with SMB-specific parsing
            results["findings"]["connectivity"] = self._enhance_smb_connectivity(connectivity, output)
        except Exception as e:
            logger.error(f"Connectivity test failed: {e}")
            results["success"] = False
            results["error"] = str(e)
            return results
        
        # If authenticated, run additional modules
        if kwargs.get("username"):
            # Enumerate shares
            if kwargs.get("shares", True):
                try:
                    result = self.execute_netexec(
                        base_cmd + ["--shares"], 
                        kwargs.get("timeout", 30),
                        self.output_manager
                    )
                    shares_output = result.stdout + result.stderr
                    results["shares"] = self._parse_shares(shares_output)
                except Exception as e:
                    logger.error(f"Share enumeration failed: {e}")
            
            # Enumerate sessions
            if kwargs.get("sessions", True):
                try:
                    result = self.execute_netexec(
                        base_cmd + ["--sessions"],
                        kwargs.get("timeout", 30),
                        self.output_manager
                    )
                    sessions_output = result.stdout + result.stderr
                    results["sessions"] = self._parse_sessions(sessions_output)
                except Exception as e:
                    logger.error(f"Session enumeration failed: {e}")
            
            # Enumerate users
            if kwargs.get("users", False):
                try:
                    result = self.execute_netexec(
                        base_cmd + ["--users"],
                        kwargs.get("timeout", 30),
                        self.output_manager
                    )
                    users_output = result.stdout + result.stderr
                    results["users"] = self._parse_users(users_output)
                except Exception as e:
                    logger.error(f"User enumeration failed: {e}")
            
            # Check for specific vulnerabilities
            results["vulnerabilities"] = self._check_vulnerabilities(
                base_cmd, kwargs
            )
        
        # Analyze results for security findings
        security_findings = self._analyze_results(results)
        
        # Convert to proper findings format
        findings_list = []
        
        # SMB signing not enforced
        if "weak_signing" in security_findings:
            findings_list.append({
                'type': 'smb_signing_not_enforced',
                'title': 'SMB Signing Not Enforced',
                'severity': 'medium',
                'description': security_findings['weak_signing']['description']
            })
        
        # SMBv1 enabled
        if "smbv1_enabled" in security_findings:
            findings_list.append({
                'type': 'smb_v1_enabled',
                'title': 'SMB Version 1 Enabled',
                'severity': 'high',
                'description': security_findings['smbv1_enabled']['description']
            })
        
        # Dangerous shares accessible
        if "dangerous_shares" in security_findings:
            findings_list.append({
                'type': 'smb_dangerous_shares',
                'title': 'Administrative Shares Accessible',
                'severity': 'high',
                'description': security_findings['dangerous_shares']['description'],
                'details': {'shares': security_findings['dangerous_shares']['shares']}
            })
        
        # Add vulnerabilities to findings
        for vuln in results.get("vulnerabilities", []):
            if "MS17-010" in vuln.get("name", ""):
                findings_list.append({
                    'type': 'ms17_010',
                    'title': vuln['name'],
                    'severity': 'critical',
                    'description': vuln['description'],
                    'recommendation': vuln.get('remediation', '')
                })
        
        results["findings"] = findings_list
        
        return results
    
    
    def _enhance_smb_connectivity(self, base_info: Dict[str, Any], output: str) -> Dict[str, Any]:
        """Enhance connectivity info with SMB-specific details.
        
        Args:
            base_info: Base connectivity info from parent class
            output: Raw netexec output
            
        Returns:
            Enhanced connectivity information
        """
        # Start with base info from parent class
        info = base_info.copy()
        
        # Add SMB-specific fields
        info["smb_signing"] = None
        info["smb_version"] = None
        
        if info["accessible"]:
            # Check SMB signing (already handled by parent class)
            if info.get("signing") == "enabled":
                info["smb_signing"] = "required"
            elif info.get("signing") == "disabled":
                info["smb_signing"] = "not required"
                
            # Check SMB version (netexec might show SMBv1 in output)
            if "SMBv1" in output or "SMB1" in output:
                info["smb_version"] = "SMBv1"
        
        return info
    
    def _parse_shares(self, output: str) -> List[Dict[str, Any]]:
        """Parse share enumeration output.
        
        Args:
            output: netexec shares output
            
        Returns:
            List of shares
        """
        shares = []
        
        # Parse netexec share output format
        for line in output.splitlines():
            if "READ" in line or "WRITE" in line:
                parts = line.split()
                for i, part in enumerate(parts):
                    if part in ["READ", "WRITE"]:
                        share_name = parts[i-1]
                        permission = part
                        
                        # Check if share already exists
                        existing = next((s for s in shares if s["name"] == share_name), None)
                        if existing:
                            if permission not in existing["permissions"]:
                                existing["permissions"].append(permission)
                        else:
                            shares.append({
                                "name": share_name,
                                "permissions": [permission],
                                "comment": ""
                            })
        
        return shares
    
    def _parse_sessions(self, output: str) -> List[Dict[str, str]]:
        """Parse session enumeration output.
        
        Args:
            output: netexec sessions output
            
        Returns:
            List of active sessions
        """
        sessions = []
        
        for line in output.splitlines():
            # Look for session information patterns
            if "\\" in line and "@" in line:
                session_match = re.search(r'([^\s\\]+\\[^\s@]+)@([^\s]+)', line)
                if session_match:
                    sessions.append({
                        "user": session_match.group(1),
                        "host": session_match.group(2)
                    })
        
        return sessions
    
    def _parse_users(self, output: str) -> List[Dict[str, Any]]:
        """Parse user enumeration output.
        
        Args:
            output: netexec users output
            
        Returns:
            List of users
        """
        users = []
        
        for line in output.splitlines():
            # Parse user entries from netexec output
            user_match = re.search(r'([^\s\\]+\\[^\s]+)\s+(\w+:\w+)', line)
            if user_match:
                users.append({
                    "username": user_match.group(1),
                    "rid": user_match.group(2)
                })
        
        return users
    
    def _check_vulnerabilities(self, base_cmd: List[str], kwargs: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check for specific SMB vulnerabilities.
        
        Args:
            base_cmd: Base netexec command
            kwargs: Plugin parameters
            
        Returns:
            List of detected vulnerabilities
        """
        vulns = []
        
        # Check for MS17-010 (EternalBlue)
        try:
            result = self.execute_netexec(
                base_cmd + ["-M", "ms17-010"],
                kwargs.get("timeout", 30),
                self.output_manager
            )
            ms17_output = result.stdout + result.stderr
            if "VULNERABLE" in ms17_output:
                vulns.append({
                    "name": "MS17-010 (EternalBlue)",
                    "severity": "CRITICAL",
                    "description": "System is vulnerable to EternalBlue exploit",
                    "remediation": "Apply MS17-010 security update immediately"
                })
        except Exception as e:
            logger.debug(f"MS17-010 check failed: {e}")
        
        # Check for SMB signing
        if not kwargs.get("username"):
            # Can still check signing without auth
            result = self.execute_netexec(base_cmd, kwargs.get("timeout", 30), self.output_manager)
            connectivity = self._enhance_smb_connectivity(
                self.parse_connectivity_output(result.stdout + result.stderr),
                result.stdout + result.stderr
            )
            if connectivity.get("smb_signing") == "not required":
                vulns.append({
                    "name": "SMB Signing Not Required",
                    "severity": "MEDIUM",
                    "description": "SMB signing is not required, allowing relay attacks",
                    "remediation": "Enable SMB signing requirement via Group Policy"
                })
        
        return vulns
    
    def _analyze_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze results for security findings.
        
        Args:
            results: Test results
            
        Returns:
            Security findings
        """
        findings = {}
        
        # Check for dangerous shares
        dangerous_shares = ["C$", "ADMIN$", "IPC$"]
        accessible_dangerous = [
            s for s in results.get("shares", [])
            if s["name"] in dangerous_shares and "READ" in s["permissions"]
        ]
        
        if accessible_dangerous:
            findings["dangerous_shares"] = {
                "severity": "HIGH",
                "shares": [s["name"] for s in accessible_dangerous],
                "description": "Administrative shares are accessible"
            }
        
        # Check for weak configurations
        connectivity = results.get("connectivity", {})
        
        # SMB signing not enforced
        if connectivity.get("smb_signing") == "not required":
            findings["weak_signing"] = {
                "severity": "MEDIUM",
                "description": "SMB signing not enforced"
            }
            
        # SMBv1 enabled
        if connectivity.get("smb_version") == "SMBv1":
            findings["smbv1_enabled"] = {
                "severity": "HIGH",
                "description": "SMB Version 1 is enabled"
            }
        
        # Check for information disclosure
        if len(results.get("users", [])) > 0:
            findings["user_enumeration"] = {
                "severity": "LOW",
                "count": len(results["users"]),
                "description": "User enumeration possible"
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
        # Handle known SMB ports
        if port in [139, 445]:
            return True
        
        # Handle services identified as SMB/NetBIOS
        service_lower = service.lower() if service else ""
        smb_indicators = ["smb", "netbios", "microsoft-ds", "netbios-ssn"]
        
        return any(indicator in service_lower for indicator in smb_indicators)
