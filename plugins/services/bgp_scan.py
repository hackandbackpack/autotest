"""
BGP scanning plugin for AutoTest.
"""

import logging
import subprocess
import shutil
import time
import socket
from typing import Dict, Any, List, Tuple
from pathlib import Path

from ..base import Plugin, PluginType, plugin

logger = logging.getLogger(__name__)


@plugin(name="bgp_scan")
class BGPScanPlugin(Plugin):
    """Plugin for BGP service detection and basic enumeration."""
    
    def __init__(self):
        """Initialize the BGP plugin."""
        super().__init__()
        self.name = "BGP Service Scanner"
        self.version = "1.0.0"
        self.description = "BGP service detection and enumeration"
        self.type = PluginType.SERVICE
        self.author = "AutoTest Framework"
        
        # BGP doesn't require specific tools for basic detection
        self.required_tools = []
        
        # BGP port
        self.bgp_ports = [179]
    
    def can_handle(self, service: str, port: int) -> bool:
        """Check if this plugin can handle the given service/port."""
        return (
            port == 179 or
            'bgp' in service.lower()
        )
    
    def get_required_params(self) -> List[str]:
        """Get required parameters."""
        return ["target"]
    
    def get_optional_params(self) -> Dict[str, Any]:
        """Get optional parameters with defaults."""
        return {
            "port": 179,
            "timeout": 30,
            "output_dir": "output/bgp"
        }
    
    def validate_params(self, **kwargs) -> bool:
        """Validate parameters."""
        if not kwargs.get("target"):
            logger.error("Target parameter is required")
            return False
        
        port = kwargs.get("port", 179)
        if not isinstance(port, int) or port < 1 or port > 65535:
            logger.error(f"Invalid port: {port}")
            return False
        
        return True
    
    def check_required_tools(self, skip_check: bool = False) -> Tuple[bool, Dict[str, Dict[str, Any]]]:
        """BGP plugin uses built-in Python functionality."""
        return True, {}
    
    def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute BGP service detection."""
        logger.info(f"BGP plugin execute() called for {target} with kwargs: {kwargs}")
        
        if not self.validate_params(target=target, **kwargs):
            return {"success": False, "error": "Invalid parameters"}
        
        results = {
            "success": True,
            "target": target,
            "service": "BGP",
            "findings": [],
            "errors": []
        }
        
        try:
            port = kwargs.get("port", 179)
            timeout = kwargs.get("timeout", 30)
            output_dir = Path(kwargs.get("output_dir", "output/bgp"))
            output_dir.mkdir(parents=True, exist_ok=True)
            
            logger.info(f"Starting BGP detection on {target}:{port}")
            
            start_time = time.time()
            full_output = f"=== BGP SERVICE DETECTION FOR {target}:{port} ===\n\n"
            
            # Test 1: Basic TCP connection test
            full_output += "=== TCP CONNECTION TEST ===\n"
            tcp_connected = False
            try:
                sock = socket.create_connection((target, port), timeout=timeout)
                tcp_connected = True
                sock.close()
                full_output += f"TCP connection successful to {target}:{port}\n"
                
                # Add finding for BGP service detection
                results["findings"].append({
                    'type': 'bgp_service',
                    'severity': 'info',
                    'target': target,
                    'port': port,
                    'title': 'BGP Service Detected',
                    'description': f'BGP service detected on {target}:{port}',
                    'service': 'BGP',
                    'details': {
                        'port': port,
                        'protocol': 'TCP',
                        'service_type': 'BGP'
                    }
                })
                
            except socket.timeout:
                full_output += f"TCP connection timeout to {target}:{port}\n"
            except socket.error as e:
                full_output += f"TCP connection failed to {target}:{port}: {e}\n"
            except Exception as e:
                full_output += f"TCP connection error to {target}:{port}: {e}\n"
            
            full_output += "\n"
            
            # Test 2: BGP Banner Grab (if TCP connected)
            if tcp_connected:
                full_output += "=== BGP BANNER GRAB ===\n"
                try:
                    sock = socket.create_connection((target, port), timeout=timeout)
                    sock.settimeout(5)  # Short timeout for banner
                    
                    # Try to receive initial data (some BGP implementations send greeting)
                    try:
                        banner = sock.recv(1024)
                        if banner:
                            full_output += f"Received banner: {banner[:100]}\n"
                            
                            results["findings"].append({
                                'type': 'bgp_banner',
                                'severity': 'info',
                                'target': target,
                                'port': port,
                                'title': 'BGP Banner Information',
                                'description': f'BGP banner received: {banner[:100]}',
                                'service': 'BGP',
                                'details': {
                                    'banner': banner.decode('utf-8', errors='ignore')[:200],
                                    'banner_length': len(banner)
                                }
                            })
                        else:
                            full_output += "No banner received\n"
                    except socket.timeout:
                        full_output += "No banner received (timeout)\n"
                    
                    sock.close()
                    
                except Exception as e:
                    full_output += f"Banner grab failed: {e}\n"
                
                full_output += "\n"
                
                # Test 3: BGP Open Message Attempt
                full_output += "=== BGP OPEN MESSAGE TEST ===\n"
                try:
                    sock = socket.create_connection((target, port), timeout=timeout)
                    sock.settimeout(10)
                    
                    # Craft a basic BGP OPEN message
                    # This is for detection only - not a full BGP implementation
                    bgp_open = self._craft_bgp_open_message()
                    
                    sock.send(bgp_open)
                    full_output += "Sent BGP OPEN message\n"
                    
                    # Try to receive response
                    try:
                        response = sock.recv(1024)
                        if response:
                            full_output += f"Received BGP response: {len(response)} bytes\n"
                            
                            # Analyze response
                            if len(response) >= 19:  # Minimum BGP message length
                                msg_type = response[18] if len(response) > 18 else 0
                                full_output += f"BGP message type: {msg_type}\n"
                                
                                if msg_type in [1, 3, 4, 5]:  # Valid BGP message types
                                    results["findings"].append({
                                        'type': 'bgp_response',
                                        'severity': 'medium',
                                        'target': target,
                                        'port': port,
                                        'title': 'BGP Protocol Response',
                                        'description': f'Valid BGP protocol response received (type: {msg_type})',
                                        'service': 'BGP',
                                        'details': {
                                            'response_length': len(response),
                                            'message_type': msg_type,
                                            'response_hex': response[:50].hex()
                                        }
                                    })
                        else:
                            full_output += "No BGP response received\n"
                    
                    except socket.timeout:
                        full_output += "BGP response timeout\n"
                    
                    sock.close()
                    
                except Exception as e:
                    full_output += f"BGP open message test failed: {e}\n"
            
            execution_time = time.time() - start_time
            
            # Check for security implications
            if tcp_connected:
                results["findings"].append({
                    'type': 'bgp_exposure',
                    'severity': 'medium',
                    'target': target,
                    'port': port,
                    'title': 'BGP Service Exposed',
                    'description': f'BGP routing service is accessible from external networks',
                    'service': 'BGP',
                    'details': {
                        'risk': 'BGP services should typically not be accessible from untrusted networks',
                        'recommendation': 'Verify BGP service exposure is intentional and properly secured'
                    }
                })
            
            # Always log to output manager
            if hasattr(self, 'output_manager') and self.output_manager:
                self.output_manager.log_tool_execution(
                    tool_name="bgp_scan",
                    target=f"{target}:{port}",
                    command="BGP service detection",
                    output=full_output,
                    service="BGP",
                    execution_time=execution_time
                )
            
            # Save output to file
            output_file = output_dir / f"bgp_scan_{target}_{port}.txt"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(full_output)
            
            results["output_file"] = str(output_file)
            results["execution_time"] = execution_time
            
        except Exception as e:
            error_msg = f"BGP scan failed: {str(e)}"
            logger.error(error_msg)
            results["success"] = False
            results["errors"].append(error_msg)
        
        return results
    
    def _craft_bgp_open_message(self) -> bytes:
        """Craft a basic BGP OPEN message for service detection."""
        # BGP OPEN Message format (simplified for detection)
        # Marker: 16 bytes of 0xFF
        marker = b'\xff' * 16
        
        # Length: 2 bytes (29 bytes total for basic OPEN)
        length = b'\x00\x1d'
        
        # Type: 1 byte (1 = OPEN)
        msg_type = b'\x01'
        
        # Version: 1 byte (4 = BGP-4)
        version = b'\x04'
        
        # My AS: 2 bytes (64512 = private AS)
        my_as = b'\xfc\x00'
        
        # Hold Time: 2 bytes (180 seconds)
        hold_time = b'\x00\xb4'
        
        # BGP Identifier: 4 bytes (1.1.1.1)
        bgp_id = b'\x01\x01\x01\x01'
        
        # Optional Parameters Length: 1 byte (0 = no optional parameters)
        opt_params_len = b'\x00'
        
        return marker + length + msg_type + version + my_as + hold_time + bgp_id + opt_params_len