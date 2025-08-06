"""
RPC enumeration plugin for AutoTest using rpcinfo and rpcdump.
"""

import logging
import subprocess
import shutil
import time
from typing import Dict, Any, List, Tuple
from pathlib import Path

from ..base import Plugin, PluginType, plugin

logger = logging.getLogger(__name__)


@plugin(name="rpc_enum")
class RPCEnumPlugin(Plugin):
    """Plugin for RPC service enumeration using rpcinfo and rpcdump."""
    
    def __init__(self):
        """Initialize the RPC enumeration plugin."""
        super().__init__()
        self.name = "RPC Service Enumeration"
        self.version = "1.0.0"
        self.description = "RPC service enumeration using rpcinfo and rpcdump"
        self.type = PluginType.SERVICE
        self.author = "AutoTest Framework"
        
        self.required_tools = ["rpcinfo"]
        
        # RPC-related ports
        self.rpc_ports = [111, 135, 593]  # portmapper, MS-RPC endpoint mapper, MS-RPC over HTTP
    
    def can_handle(self, service: str, port: int) -> bool:
        """Check if this plugin can handle the given service/port."""
        return (
            port in self.rpc_ports or
            'rpc' in service.lower() or
            'portmapper' in service.lower()
        )
    
    def get_required_params(self) -> List[str]:
        """Get required parameters."""
        return ["target"]
    
    def get_optional_params(self) -> Dict[str, Any]:
        """Get optional parameters with defaults."""
        return {
            "port": 111,
            "timeout": 60,
            "output_dir": "output/rpc",
            "tcp": True,
            "udp": True
        }
    
    def validate_params(self, **kwargs) -> bool:
        """Validate parameters."""
        if not kwargs.get("target"):
            logger.error("Target parameter is required")
            return False
        
        port = kwargs.get("port", 111)
        if not isinstance(port, int) or port < 1 or port > 65535:
            logger.error(f"Invalid port: {port}")
            return False
        
        return True
    
    def check_required_tools(self, skip_check: bool = False) -> Tuple[bool, Dict[str, Dict[str, Any]]]:
        """Check if rpcinfo is available."""
        if skip_check or getattr(self, 'skip_tool_check', False):
            return True, {}
        
        tools_status = {}
        
        # Check rpcinfo
        if shutil.which("rpcinfo"):
            tools_status["rpcinfo"] = {"available": True, "path": shutil.which("rpcinfo")}
        else:
            tools_status["rpcinfo"] = {
                "available": False,
                "install_command": "apt install rpcbind",
                "path": None
            }
        
        # Check if any impacket tools are available for Windows RPC
        impacket_tools = ["rpcdump.py", "rpcmap.py"]
        for tool in impacket_tools:
            if shutil.which(tool):
                tools_status[tool] = {"available": True, "path": shutil.which(tool)}
                break
        else:
            tools_status["impacket"] = {
                "available": False,
                "install_command": "pip install impacket",
                "path": None
            }
        
        # Return success if at least rpcinfo is available
        return tools_status["rpcinfo"]["available"], tools_status
    
    def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute RPC enumeration."""
        logger.info(f"RPC enumeration plugin execute() called for {target} with kwargs: {kwargs}")
        
        if not self.validate_params(target=target, **kwargs):
            return {"success": False, "error": "Invalid parameters"}
        
        # Check if required tools are available
        tool_available, tool_status = self.check_required_tools()
        if not tool_available:
            error_msg = "rpcinfo not found. Please install it first with: apt install rpcbind"
            logger.error(error_msg)
            
            if hasattr(self, 'output_manager') and self.output_manager:
                self.output_manager.log_tool_execution(
                    tool_name="rpcinfo",
                    target=target,
                    command="rpcinfo (NOT FOUND)",
                    output=error_msg,
                    service="RPC",
                    execution_time=0
                )
            
            return {
                "success": False,
                "error": error_msg,
                "install_command": "apt install rpcbind"
            }
        
        results = {
            "success": True,
            "target": target,
            "service": "RPC",
            "findings": [],
            "errors": []
        }
        
        try:
            port = kwargs.get("port", 111)
            timeout = kwargs.get("timeout", 60)
            tcp = kwargs.get("tcp", True)
            udp = kwargs.get("udp", True)
            output_dir = Path(kwargs.get("output_dir", "output/rpc"))
            output_dir.mkdir(parents=True, exist_ok=True)
            
            logger.info(f"Starting RPC enumeration on {target}:{port}")
            
            start_time = time.time()
            full_output = f"=== RPC ENUMERATION FOR {target} ===\n\n"
            
            # Test basic connectivity
            full_output += "=== BASIC RPC CONNECTIVITY TEST ===\n"
            try:
                ping_cmd = ["rpcinfo", "-p", target]
                ping_result = subprocess.run(
                    ping_cmd,
                    capture_output=True,
                    text=True,
                    timeout=timeout // 4
                )
                
                full_output += f"Command: {' '.join(ping_cmd)}\n"
                if ping_result.stdout:
                    full_output += f"Output:\n{ping_result.stdout}\n"
                    # Parse RPC services from output
                    rpc_findings = self._parse_rpcinfo_output(ping_result.stdout, target, port)
                    results["findings"].extend(rpc_findings)
                else:
                    full_output += "No RPC services found or portmapper not accessible\n"
                
                if ping_result.stderr:
                    full_output += f"Errors: {ping_result.stderr}\n"
                
                full_output += f"Return code: {ping_result.returncode}\n\n"
                
            except subprocess.TimeoutExpired:
                full_output += "RPC portmapper query timed out\n\n"
            except Exception as e:
                full_output += f"RPC portmapper query failed: {e}\n\n"
            
            # Try TCP-specific enumeration
            if tcp:
                full_output += "=== TCP RPC SERVICES ===\n"
                try:
                    tcp_cmd = ["rpcinfo", "-t", target, "portmapper"]
                    tcp_result = subprocess.run(
                        tcp_cmd,
                        capture_output=True,
                        text=True,
                        timeout=timeout // 4
                    )
                    
                    full_output += f"Command: {' '.join(tcp_cmd)}\n"
                    if tcp_result.stdout:
                        full_output += f"Output:\n{tcp_result.stdout}\n"
                    else:
                        full_output += "No TCP RPC response\n"
                    
                    if tcp_result.stderr:
                        full_output += f"Errors: {tcp_result.stderr}\n"
                    
                    full_output += f"Return code: {tcp_result.returncode}\n\n"
                    
                except subprocess.TimeoutExpired:
                    full_output += "TCP RPC query timed out\n\n"
                except Exception as e:
                    full_output += f"TCP RPC query failed: {e}\n\n"
            
            # Try UDP-specific enumeration
            if udp:
                full_output += "=== UDP RPC SERVICES ===\n"
                try:
                    udp_cmd = ["rpcinfo", "-u", target, "portmapper"]
                    udp_result = subprocess.run(
                        udp_cmd,
                        capture_output=True,
                        text=True,
                        timeout=timeout // 4
                    )
                    
                    full_output += f"Command: {' '.join(udp_cmd)}\n"
                    if udp_result.stdout:
                        full_output += f"Output:\n{udp_result.stdout}\n"
                    else:
                        full_output += "No UDP RPC response\n"
                    
                    if udp_result.stderr:
                        full_output += f"Errors: {udp_result.stderr}\n"
                    
                    full_output += f"Return code: {udp_result.returncode}\n\n"
                    
                except subprocess.TimeoutExpired:
                    full_output += "UDP RPC query timed out\n\n"
                except Exception as e:
                    full_output += f"UDP RPC query failed: {e}\n\n"
            
            # Try Windows RPC enumeration if impacket is available
            if port == 135 and any("rpcdump" in tool for tool in tool_status.keys()):
                full_output += "=== WINDOWS RPC ENDPOINT ENUMERATION ===\n"
                try:
                    # Find rpcdump tool
                    rpcdump_cmd = None
                    for tool_name, tool_info in tool_status.items():
                        if "rpcdump" in tool_name and tool_info.get("available"):
                            rpcdump_cmd = [tool_info["path"], target]
                            break
                    
                    if rpcdump_cmd:
                        rpcdump_result = subprocess.run(
                            rpcdump_cmd,
                            capture_output=True,
                            text=True,
                            timeout=timeout // 2
                        )
                        
                        full_output += f"Command: {' '.join(rpcdump_cmd)}\n"
                        if rpcdump_result.stdout:
                            full_output += f"Output:\n{rpcdump_result.stdout}\n"
                            # Parse Windows RPC findings
                            win_rpc_findings = self._parse_rpcdump_output(rpcdump_result.stdout, target, port)
                            results["findings"].extend(win_rpc_findings)
                        
                        if rpcdump_result.stderr:
                            full_output += f"Errors: {rpcdump_result.stderr}\n"
                        
                        full_output += f"Return code: {rpcdump_result.returncode}\n\n"
                    
                except subprocess.TimeoutExpired:
                    full_output += "Windows RPC enumeration timed out\n\n"
                except Exception as e:
                    full_output += f"Windows RPC enumeration failed: {e}\n\n"
            
            execution_time = time.time() - start_time
            
            # Always log to output manager
            if hasattr(self, 'output_manager') and self.output_manager:
                self.output_manager.log_tool_execution(
                    tool_name="rpcinfo + rpcdump",
                    target=f"{target}:{port}",
                    command="RPC enumeration suite",
                    output=full_output,
                    service="RPC",
                    execution_time=execution_time
                )
            
            # Save output to file
            output_file = output_dir / f"rpc_enum_{target}_{port}.txt"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(full_output)
            
            results["output_file"] = str(output_file)
            results["execution_time"] = execution_time
            
        except Exception as e:
            error_msg = f"RPC enumeration failed: {str(e)}"
            logger.error(error_msg)
            results["success"] = False
            results["errors"].append(error_msg)
        
        return results
    
    def _parse_rpcinfo_output(self, output: str, target: str, port: int) -> List[Dict[str, Any]]:
        """Parse rpcinfo output for RPC service findings."""
        findings = []
        
        if not output or not output.strip():
            return findings
        
        try:
            lines = output.split('\n')
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith('program'):
                    continue
                
                # Parse rpcinfo -p output format:
                # program vers proto   port  service
                parts = line.split()
                if len(parts) >= 4:
                    program = parts[0]
                    version = parts[1]
                    protocol = parts[2]
                    rpc_port = parts[3]
                    service_name = parts[4] if len(parts) > 4 else 'unknown'
                    
                    # Determine severity based on service
                    severity = self._determine_rpc_severity(service_name, program)
                    
                    finding = {
                        'type': 'rpc_service',
                        'severity': severity,
                        'target': target,
                        'port': port,
                        'title': f'RPC Service: {service_name}',
                        'description': f'RPC service {service_name} (program {program}) on {protocol} port {rpc_port}',
                        'service': 'RPC',
                        'details': {
                            'rpc_program': program,
                            'rpc_version': version,
                            'protocol': protocol,
                            'rpc_port': rpc_port,
                            'service_name': service_name
                        }
                    }
                    
                    findings.append(finding)
        
        except Exception as e:
            logger.error(f"Failed to parse rpcinfo output: {e}")
        
        return findings
    
    def _parse_rpcdump_output(self, output: str, target: str, port: int) -> List[Dict[str, Any]]:
        """Parse rpcdump output for Windows RPC endpoint findings."""
        findings = []
        
        if not output or not output.strip():
            return findings
        
        try:
            lines = output.split('\n')
            
            for line in lines:
                line = line.strip()
                
                # Look for RPC endpoint information
                if 'Protocol:' in line and 'Endpoint:' in line:
                    finding = {
                        'type': 'windows_rpc_endpoint',
                        'severity': 'info',
                        'target': target,
                        'port': port,
                        'title': 'Windows RPC Endpoint',
                        'description': line,
                        'service': 'MS-RPC',
                        'details': {
                            'endpoint_info': line
                        }
                    }
                    findings.append(finding)
                
                # Look for specific RPC services
                elif any(rpc_svc in line.lower() for rpc_svc in [
                    'spoolss', 'samr', 'lsarpc', 'netlogon', 'srvsvc', 'wkssvc'
                ]):
                    severity = 'medium' if any(sensitive in line.lower() for sensitive in [
                        'samr', 'lsarpc', 'netlogon'
                    ]) else 'info'
                    
                    finding = {
                        'type': 'windows_rpc_service',
                        'severity': severity,
                        'target': target,
                        'port': port,
                        'title': 'Windows RPC Service Found',
                        'description': line,
                        'service': 'MS-RPC',
                        'details': {
                            'service_info': line
                        }
                    }
                    findings.append(finding)
        
        except Exception as e:
            logger.error(f"Failed to parse rpcdump output: {e}")
        
        return findings
    
    def _determine_rpc_severity(self, service_name: str, program: str) -> str:
        """Determine severity based on RPC service type."""
        service_lower = service_name.lower()
        
        # High-risk RPC services
        high_risk_services = [
            'mountd', 'nfs', 'ypbind', 'ypserv', 'rexd', 'rusersd',
            'rstatd', 'rwalld', 'sprayd'
        ]
        
        # Medium-risk RPC services
        medium_risk_services = [
            'portmapper', 'rpcbind', 'lockd', 'status'
        ]
        
        if any(high_risk in service_lower for high_risk in high_risk_services):
            return 'high'
        elif any(medium_risk in service_lower for medium_risk in medium_risk_services):
            return 'medium'
        
        return 'info'