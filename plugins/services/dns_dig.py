"""
Dig DNS enumeration plugin for AutoTest.
"""

import logging
import subprocess
import shutil
import time
from typing import Dict, Any, List, Tuple
from pathlib import Path

from ..base import Plugin, PluginType, plugin

logger = logging.getLogger(__name__)


@plugin(name="dns_dig")
class DNSDigPlugin(Plugin):
    """Plugin for DNS enumeration using dig."""
    
    def __init__(self):
        """Initialize the dig plugin."""
        super().__init__()
        self.name = "Dig DNS Enumeration"
        self.version = "1.0.0"
        self.description = "DNS enumeration and zone transfer testing using dig"
        self.type = PluginType.SERVICE
        self.author = "AutoTest Framework"
        
        self.required_tools = ["dig"]
        
        # DNS port
        self.dns_ports = [53]
    
    def can_handle(self, service: str, port: int) -> bool:
        """Check if this plugin can handle the given service/port."""
        return (
            port == 53 or
            'dns' in service.lower()
        )
    
    def get_required_params(self) -> List[str]:
        """Get required parameters."""
        return ["target"]
    
    def get_optional_params(self) -> Dict[str, Any]:
        """Get optional parameters with defaults."""
        return {
            "port": 53,
            "timeout": 60,
            "output_dir": "output/dns",
            "record_types": ["A", "AAAA", "MX", "NS", "SOA", "TXT", "CNAME", "PTR"]
        }
    
    def validate_params(self, **kwargs) -> bool:
        """Validate parameters."""
        if not kwargs.get("target"):
            logger.error("Target parameter is required")
            return False
        
        return True
    
    def check_required_tools(self, skip_check: bool = False) -> Tuple[bool, Dict[str, Dict[str, Any]]]:
        """Check if dig is available."""
        if skip_check or getattr(self, 'skip_tool_check', False):
            return True, {}
        
        if shutil.which("dig"):
            return True, {"dig": {"available": True, "path": shutil.which("dig")}}
        else:
            return False, {"dig": {
                "available": False, 
                "install_command": "apt install dnsutils",
                "path": None
            }}
    
    def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        """Execute dig DNS enumeration."""
        logger.info(f"Dig plugin execute() called for {target} with kwargs: {kwargs}")
        
        if not self.validate_params(target=target, **kwargs):
            return {"success": False, "error": "Invalid parameters"}
        
        # Check if dig is available
        tool_available, tool_status = self.check_required_tools()
        if not tool_available:
            error_msg = "dig not found. Please install it first with: apt install dnsutils"
            logger.error(error_msg)
            
            if hasattr(self, 'output_manager') and self.output_manager:
                self.output_manager.log_tool_execution(
                    tool_name="dig",
                    target=target,
                    command="dig (NOT FOUND)",
                    output=error_msg,
                    service="DNS",
                    execution_time=0
                )
            
            return {
                "success": False,
                "error": error_msg,
                "install_command": "apt install dnsutils"
            }
        
        results = {
            "success": True,
            "target": target,
            "service": "DNS",
            "findings": [],
            "errors": []
        }
        
        try:
            timeout = kwargs.get("timeout", 60)
            record_types = kwargs.get("record_types", ["A", "AAAA", "MX", "NS", "SOA", "TXT", "CNAME", "PTR"])
            output_dir = Path(kwargs.get("output_dir", "output/dns"))
            output_dir.mkdir(parents=True, exist_ok=True)
            
            logger.info(f"Starting dig enumeration on {target}")
            
            start_time = time.time()
            full_output = f"=== DIG DNS ENUMERATION FOR {target} ===\n\n"
            
            # Query each record type
            for record_type in record_types:
                try:
                    cmd = ["dig", "+short", record_type, target]
                    
                    result = subprocess.run(
                        cmd,
                        capture_output=True,
                        text=True,
                        timeout=timeout // len(record_types)
                    )
                    
                    full_output += f"=== {record_type} RECORDS ===\n"
                    full_output += f"Command: {' '.join(cmd)}\n"
                    
                    if result.stdout:
                        full_output += f"Results:\n{result.stdout}\n"
                        # Parse findings for this record type
                        type_findings = self._parse_record_output(record_type, result.stdout, target)
                        results["findings"].extend(type_findings)
                    else:
                        full_output += "No records found\n"
                    
                    if result.stderr:
                        full_output += f"Errors: {result.stderr}\n"
                    
                    full_output += f"Return code: {result.returncode}\n\n"
                    
                except subprocess.TimeoutExpired:
                    full_output += f"Timeout querying {record_type} records\n\n"
                except Exception as e:
                    full_output += f"Error querying {record_type} records: {e}\n\n"
            
            # Test zone transfer
            full_output += "=== ZONE TRANSFER TEST ===\n"
            
            # First get name servers
            try:
                ns_cmd = ["dig", "+short", "NS", target]
                ns_result = subprocess.run(ns_cmd, capture_output=True, text=True, timeout=30)
                
                if ns_result.stdout:
                    nameservers = [ns.strip().rstrip('.') for ns in ns_result.stdout.split('\n') if ns.strip()]
                    
                    for ns in nameservers[:3]:  # Test first 3 name servers
                        try:
                            axfr_cmd = ["dig", f"@{ns}", "AXFR", target]
                            axfr_result = subprocess.run(axfr_cmd, capture_output=True, text=True, timeout=30)
                            
                            full_output += f"\nZone transfer test against {ns}:\n"
                            full_output += f"Command: {' '.join(axfr_cmd)}\n"
                            
                            if axfr_result.returncode == 0 and axfr_result.stdout:
                                if "XFR size" in axfr_result.stdout or len(axfr_result.stdout.split('\n')) > 10:
                                    full_output += "ZONE TRANSFER SUCCESSFUL!\n"
                                    full_output += axfr_result.stdout + "\n"
                                    
                                    # Add critical finding for zone transfer
                                    results["findings"].append({
                                        'type': 'zone_transfer',
                                        'severity': 'critical',
                                        'target': target,
                                        'port': 53,
                                        'title': 'DNS Zone Transfer Allowed',
                                        'description': f'Name server {ns} allows zone transfers (AXFR)',
                                        'service': 'DNS',
                                        'details': {
                                            'nameserver': ns,
                                            'vulnerability': 'zone_transfer_enabled',
                                            'impact': 'Full DNS zone disclosure'
                                        }
                                    })
                                else:
                                    full_output += "Zone transfer denied\n"
                            else:
                                full_output += "Zone transfer denied or failed\n"
                                if axfr_result.stderr:
                                    full_output += f"Error: {axfr_result.stderr}\n"
                            
                        except subprocess.TimeoutExpired:
                            full_output += f"Zone transfer test timeout for {ns}\n"
                        except Exception as e:
                            full_output += f"Zone transfer test error for {ns}: {e}\n"
                else:
                    full_output += "No name servers found for zone transfer testing\n"
                    
            except Exception as e:
                full_output += f"Error getting name servers: {e}\n"
            
            # Test reverse DNS for A records
            full_output += "\n=== REVERSE DNS LOOKUPS ===\n"
            a_records = [f for f in results["findings"] if f.get('details', {}).get('record_type') == 'A']
            
            for a_record in a_records[:5]:  # Limit to first 5 IPs
                try:
                    ip = a_record.get('details', {}).get('value', '')
                    if ip:
                        reverse_cmd = ["dig", "+short", "-x", ip]
                        reverse_result = subprocess.run(reverse_cmd, capture_output=True, text=True, timeout=10)
                        
                        full_output += f"\nReverse lookup for {ip}:\n"
                        if reverse_result.stdout:
                            full_output += f"PTR: {reverse_result.stdout.strip()}\n"
                        else:
                            full_output += "No PTR record found\n"
                            
                except Exception as e:
                    full_output += f"Reverse lookup error for {ip}: {e}\n"
            
            execution_time = time.time() - start_time
            
            # Always log to output manager
            if hasattr(self, 'output_manager') and self.output_manager:
                self.output_manager.log_tool_execution(
                    tool_name="dig",
                    target=target,
                    command=f"dig multiple record types + zone transfer test",
                    output=full_output,
                    service="DNS",
                    execution_time=execution_time
                )
            
            # Save output to file
            output_file = output_dir / f"dig_{target}.txt"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(full_output)
            
            results["output_file"] = str(output_file)
            results["execution_time"] = execution_time
            
        except Exception as e:
            error_msg = f"Dig scan failed: {str(e)}"
            logger.error(error_msg)
            results["success"] = False
            results["errors"].append(error_msg)
        
        return results
    
    def _parse_record_output(self, record_type: str, output: str, target: str) -> List[Dict[str, Any]]:
        """Parse dig output for specific record type."""
        findings = []
        
        if not output or not output.strip():
            return findings
        
        try:
            lines = [line.strip() for line in output.split('\n') if line.strip()]
            
            for line in lines:
                if line:
                    # Determine severity based on record type and content
                    severity = 'info'
                    title = f'{record_type} Record Found'
                    
                    # Special handling for different record types
                    if record_type == 'TXT':
                        if any(sensitive in line.lower() for sensitive in [
                            'v=spf1', 'dmarc', 'dkim', 'google-site-verification', 
                            'ms=', '_domainkey', 'password', 'key='
                        ]):
                            severity = 'medium'
                            title = 'Sensitive TXT Record Found'
                    
                    elif record_type in ['MX', 'NS']:
                        severity = 'medium'
                        title = f'Mail/DNS Server Record Found'
                    
                    elif record_type == 'SOA':
                        severity = 'medium' 
                        title = 'DNS Zone Authority Record Found'
                    
                    finding = {
                        'type': 'dns_record',
                        'severity': severity,
                        'target': target,
                        'port': 53,
                        'title': title,
                        'description': f'{record_type} record: {line}',
                        'service': 'DNS',
                        'details': {
                            'record_type': record_type,
                            'value': line,
                            'domain': target
                        }
                    }
                    
                    findings.append(finding)
        
        except Exception as e:
            logger.error(f"Failed to parse {record_type} record output: {e}")
        
        return findings