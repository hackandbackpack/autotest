"""
Ultra-simplified output management for AutoTest framework.
"""

import os
from datetime import datetime
from typing import Dict, Any, List
from .utils import create_directory, get_timestamp


class OutputManager:
    """
    Ultra-simplified output manager with performance optimizations.
    """
    
    SEPARATOR = "=" * 80
    LINE_SEP = "-" * 80
    
    def __init__(self, output_dir: str = "output"):
        """
        Initialize OutputManager with buffered I/O.
        
        Args:
            output_dir: Directory for output files
        """
        self.output_dir = output_dir
        self.session_id = get_timestamp()
        
        create_directory(self.output_dir)
        
        self.console_log_path = os.path.join(self.output_dir, "console_output.log")
        self.findings_path = os.path.join(self.output_dir, "findings.txt")
        
        # Buffered logging for performance
        self._log_buffer = []
        self._buffer_size = 10  # Flush after 10 entries
        
        # Initialize console log
        self._write_console_header()
    
    def _write_console_header(self) -> None:
        """Write console log header."""
        header_lines = [
            "AUTOTEST CONSOLE OUTPUT LOG",
            self.SEPARATOR,
            f"Session: {self.session_id}",
            f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            self.SEPARATOR,
            ""
        ]
        with open(self.console_log_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(header_lines))
    
    def log_tool_execution(self, tool_name: str, target: str, command: str, 
                          output: str, service: str = None, execution_time: float = None) -> None:
        """
        Log tool execution with buffered I/O for performance.
        
        Args:
            tool_name: Name of the tool executed
            target: Target host/port
            command: Command that was executed
            output: Tool output
            service: Service name
            execution_time: Execution time in seconds
        """
        timestamp = datetime.now().strftime('%H:%M:%S')
        
        # Build log entry efficiently
        parts = [
            f"[{timestamp}] === {tool_name.upper()} SCAN ===",
            f"Target: {target}"
        ]
        
        if service:
            parts.append(f"Service: {service}")
        
        parts.extend([
            f"Command: {command}",
            f"Execution Time: {execution_time:.2f} seconds" if execution_time else None,
            self.LINE_SEP,
            output,
            self.SEPARATOR,
            ""
        ])
        
        # Filter None values and join
        log_entry = '\n'.join(filter(None, parts))
        
        # Buffer for performance
        self._log_buffer.append(log_entry)
        
        # Flush buffer when full
        if len(self._log_buffer) >= self._buffer_size:
            self._flush_console_log()
    
    def _flush_console_log(self) -> None:
        """Flush buffered console log entries."""
        if not self._log_buffer:
            return
            
        with open(self.console_log_path, 'a', encoding='utf-8') as f:
            f.write('\n'.join(self._log_buffer) + '\n')
        
        self._log_buffer.clear()
    
    def save_security_findings(self, findings: List[Dict[str, Any]], update: bool = True) -> str:
        """
        Optimized security findings processing with O(n) complexity.
        
        Args:
            findings: List of security findings
            update: Whether to append to existing findings
            
        Returns:
            Path to findings file
        """
        if not findings:
            return self.findings_path
        
        # Process findings in single pass - O(n) instead of O(n²)
        severity_groups = {
            'critical': {},
            'high': {},
            'medium': {},
            'low': {},
            'info': {}
        }
        
        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            if severity not in severity_groups:
                severity = 'info'
            
            # Extract finding info efficiently
            finding_type = finding.get('type', finding.get('title', 'Unknown Issue'))
            host_entry = self._build_host_entry(finding)
            
            # Group by type within severity using dict
            type_group = severity_groups[severity]
            if finding_type not in type_group:
                type_group[finding_type] = set()  # Use set for automatic deduplication
            type_group[finding_type].add(host_entry)
        
        # Generate report efficiently
        report_lines = self._build_findings_header(update)
        
        severity_headers = {
            'critical': 'CRITICAL FINDINGS',
            'high': 'HIGH RISK FINDINGS',
            'medium': 'MEDIUM RISK FINDINGS',
            'low': 'LOW RISK FINDINGS',
            'info': 'INFORMATIONAL FINDINGS'
        }
        
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            type_groups = severity_groups[severity]
            if not type_groups:
                continue
            
            # Add severity header
            header = severity_headers[severity]
            report_lines.extend([header, "-" * len(header)])
            
            # Add findings by type
            for finding_type in sorted(type_groups.keys()):
                report_lines.append(f"- {finding_type}")
                # Hosts already deduplicated by set
                for host in sorted(type_groups[finding_type]):
                    report_lines.append(f"  {host}")
                report_lines.append("")
            
            report_lines.append("")
        
        # Write to file
        mode = 'a' if update and os.path.exists(self.findings_path) else 'w'
        with open(self.findings_path, mode, encoding='utf-8') as f:
            f.write('\n'.join(report_lines) + '\n')
        
        return self.findings_path
    
    def _build_host_entry(self, finding: Dict[str, Any]) -> str:
        """Build host entry with context efficiently."""
        target = finding.get('target', 'Unknown')
        port = finding.get('port', '')
        host_entry = f"{target}:{port}" if port else target
        
        # Add context for specific finding types
        details = finding.get('details', {})
        finding_type = finding.get('type', '')
        
        if finding_type == 'snmp_community' and isinstance(details, dict):
            community = details.get('community')
            if community:
                host_entry += f" (Community: {community})"
        elif finding_type in ('weak_cipher', 'medium_cipher') and isinstance(details, dict):
            cipher_info = details.get('cipher_suite', {})
            if isinstance(cipher_info, dict):
                cipher_name = cipher_info.get('name')
                if cipher_name:
                    host_entry += f" ({cipher_name})"
        
        return host_entry
    
    def _build_findings_header(self, update: bool) -> List[str]:
        """Build findings report header."""
        if update:
            return []
        
        return [
            "AUTOTEST SECURITY FINDINGS",
            "=" * 60,
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ""
        ]
    
    def generate_reports(self, results: Dict[str, Any]) -> Dict[str, str]:
        """Return paths to our two output files."""
        # Ensure any buffered logs are flushed
        self._flush_console_log()
        
        return {
            'console': self.console_log_path,
            'findings': self.findings_path
        }
    
    def create_summary_log(self) -> str:
        """Add session summary to console log."""
        # Flush any remaining buffer first
        self._flush_console_log()
        
        timestamp = datetime.now().strftime('%H:%M:%S')
        summary_lines = [
            "",
            f"[{timestamp}] === SESSION COMPLETE ===",
            f"Output Directory: {self.output_dir}",
            f"Console Log: {os.path.basename(self.console_log_path)}",
            f"Findings: {os.path.basename(self.findings_path)}",
            self.SEPARATOR
        ]
        
        with open(self.console_log_path, 'a', encoding='utf-8') as f:
            f.write('\n'.join(summary_lines) + '\n')
        
        return self.console_log_path