"""
SNMP service plugin for AutoTest using OneSixtyOne.
"""

import logging
import shutil
import subprocess
from typing import Dict, Any, List, Optional
from pathlib import Path

from ..base import Plugin, PluginType, plugin

logger = logging.getLogger(__name__)


@plugin(name="snmp")
class SNMPPlugin(Plugin):
    """Plugin for SNMP enumeration using OneSixtyOne."""
    
    def __init__(self):
        """Initialize the SNMP plugin."""
        super().__init__()
        self.name = "SNMP Service Plugin"
        self.version = "1.0.0"
        self.description = "SNMP enumeration using OneSixtyOne"
        self.type = PluginType.SERVICE
        self.author = "AutoTest Framework"
        self.port = 161  # Default SNMP port
        
        # Tool configuration
        self.tool_name = "onesixtyone"
        self.required_tools = ["onesixtyone"]
        
        # Default wordlist
        self.default_community_list = '/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt'
    
    def _find_tool(self) -> Optional[str]:
        """Find onesixtyone executable.
        
        Returns:
            Path to onesixtyone executable or None
        """
        import shutil
        if shutil.which(self.tool_name):
            return self.tool_name
        logger.warning("onesixtyone not found in PATH")
        return None
    
    def get_required_params(self) -> List[str]:
        """Get required parameters for SNMP plugin.
        
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
            "port": 161,
            "community_list": self.default_community_list,
            "timeout": 300,
            "output_dir": "output/snmp"
        }
    
    def validate_params(self, **kwargs) -> bool:
        """Validate SNMP plugin parameters.
        
        Args:
            **kwargs: Parameters to validate
            
        Returns:
            True if parameters are valid
        """
        if not kwargs.get("target"):
            logger.error("Target parameter is required")
            return False
        
        # Validate port
        port = kwargs.get("port", 161)
        if not isinstance(port, int) or port < 1 or port > 65535:
            logger.error(f"Invalid port: {port}")
            return False
        
        # Check if community list file exists
        community_list = kwargs.get("community_list", self.default_community_list)
        if not Path(community_list).exists():
            logger.warning(f"Community list file not found: {community_list}")
        
        return True
    
    def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute SNMP enumeration using onesixtyone.
        
        Args:
            target: Target host or network
            **kwargs: Additional parameters
            
        Returns:
            Dictionary containing test results
        """
        if not self.validate_params(target=target, **kwargs):
            return {"success": False, "error": "Invalid parameters"}
        
        # Find tool
        tool_path = self._find_tool()
        if not tool_path:
            return {
                "success": False,
                "error": "onesixtyone not found. Please install it first.",
                "install_command": "apt-get install onesixtyone"
            }
        
        results = {
            "success": True,
            "target": target,
            "service": "SNMP",
            "findings": [],
            "errors": []
        }
        
        try:
            port = kwargs.get("port", 161)
            community_list = kwargs.get("community_list", self.default_community_list)
            timeout = kwargs.get("timeout", 300)
            output_dir = Path(kwargs.get("output_dir", "output/snmp"))
            output_dir.mkdir(parents=True, exist_ok=True)
            
            logger.info(f"Starting SNMP enumeration on {target}:{port}")
            
            # Prepare output file
            output_file = output_dir / f"snmp_{target}_{port}.txt"
            
            # Build OneSixtyOne command
            cmd = [
                tool_path,
                "-c", community_list,  # Community string file
                "-o", str(output_file),     # Output file
                target
            ]
            
            # Run OneSixtyOne
            logger.debug(f"Running command: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            # Parse results
            findings = self._parse_results(output_file, result.stdout)
            results["findings"].extend(findings)
            
            # Save raw output
            if result.stdout:
                raw_output = output_dir / f"snmp_{target}_{port}_raw.txt"
                with open(raw_output, 'w') as f:
                    f.write(result.stdout)
                results["raw_output"] = str(raw_output)
            
            results["output_file"] = str(output_file)
            results["command"] = ' '.join(cmd)
            
        except subprocess.TimeoutExpired:
            logger.error(f"SNMP scan timed out for {target}:{port}")
            results["success"] = False
            results["errors"].append("Scan timed out")
        except Exception as e:
            logger.error(f"SNMP scan failed for {target}:{port}: {e}")
            results["success"] = False
            results["errors"].append(str(e))
        
        return results
    
    def _parse_results(self, output_file: Path, stdout: str) -> List[Dict[str, Any]]:
        """Parse OneSixtyOne results."""
        findings = []
        
        # Parse stdout for successful community strings
        if stdout:
            for line in stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                    
                # OneSixtyOne format: IP [community] system description
                if '[' in line and ']' in line:
                    parts = line.split('[', 1)
                    if len(parts) == 2:
                        ip = parts[0].strip()
                        rest = parts[1]
                        if ']' in rest:
                            community = rest.split(']')[0]
                            description = rest.split(']', 1)[1].strip()
                            
                            # Determine if it's a default/common community string
                            common_communities = ['public', 'private', 'community', 'default', 'admin']
                            finding_type = 'snmp_community'
                            if community.lower() in common_communities:
                                finding_type = 'snmp_default_community'
                            
                            findings.append({
                                'type': finding_type,
                                'severity': 'high',
                                'title': 'Common Community String In Use',
                                'description': f'SNMP community string "{community}" is accessible',
                                'details': {
                                    'ip': ip,
                                    'community': community,
                                    'system_description': description
                                }
                            })
        
        # Also check output file if it exists
        if output_file.exists():
            try:
                with open(output_file, 'r') as f:
                    content = f.read()
                    # Parse file content if different from stdout
                    if content and content != stdout:
                        # Additional parsing logic if needed
                        pass
            except Exception as e:
                logging.error(f"Failed to read output file: {e}")
        
        return findings
    

    
    def can_handle(self, service: str, port: int) -> bool:
        """Check if this plugin can handle the given service/port.
        
        Args:
            service: Service name detected
            port: Port number
            
        Returns:
            True if plugin should run for this service/port
        """
        # Handle known SNMP ports
        if port in [161, 162]:
            return True
        
        # Handle services identified as SNMP
        service_lower = service.lower() if service else ""
        snmp_indicators = ["snmp", "simple network management"]
        
        return any(indicator in service_lower for indicator in snmp_indicators)
