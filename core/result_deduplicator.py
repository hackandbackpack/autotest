"""
Result deduplication and merging system for AutoTest playbooks.

Handles intelligent deduplication of security findings from multiple tools
while preserving raw outputs for detailed analysis.
"""

import json
import hashlib
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

from .playbook import MergeStrategy, DeduplicationConfig

logger = logging.getLogger(__name__)


class SeverityLevel(Enum):
    """Standard severity levels for security findings."""
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


@dataclass
class SecurityFinding:
    """Represents a single security finding."""
    vulnerability: str
    description: str
    severity: SeverityLevel
    endpoint: str = ""
    port: int = 0
    service: str = ""
    tool: str = ""
    raw_output: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    sources: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary."""
        return {
            'vulnerability': self.vulnerability,
            'description': self.description,
            'severity': self.severity.name,
            'endpoint': self.endpoint,
            'port': self.port,
            'service': self.service,
            'tool': self.tool,
            'timestamp': self.timestamp,
            'sources': self.sources,
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'SecurityFinding':
        """Create SecurityFinding from dictionary."""
        return cls(
            vulnerability=data.get('vulnerability', ''),
            description=data.get('description', ''),
            severity=SeverityLevel[data.get('severity', 'INFO')],
            endpoint=data.get('endpoint', ''),
            port=data.get('port', 0),
            service=data.get('service', ''),
            tool=data.get('tool', ''),
            raw_output=data.get('raw_output', ''),
            timestamp=data.get('timestamp', datetime.now().isoformat()),
            sources=data.get('sources', []),
            metadata=data.get('metadata', {})
        )


class ResultParser:
    """Parses tool outputs into standardized SecurityFindings."""
    
    @staticmethod
    def parse_nikto_output(output: str, target: str, port: int) -> List[SecurityFinding]:
        """Parse Nikto output into security findings."""
        findings = []
        
        # Basic nikto parsing - look for vulnerability indicators
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('-'):
                continue
            
            # Look for vulnerability patterns
            vuln_keywords = ['vuln', 'error', 'warn', 'risk', 'exposed', 'not present', 'not defined', 
                           'outdated', 'deprecated', 'weak', 'insecure', 'missing', 'default file']
            if any(keyword in line.lower() for keyword in vuln_keywords):
                severity = SeverityLevel.MEDIUM
                if any(critical in line.lower() for critical in ['critical', 'high', 'exploit']):
                    severity = SeverityLevel.HIGH
                elif any(low in line.lower() for low in ['low', 'info', 'note']):
                    severity = SeverityLevel.LOW
                
                findings.append(SecurityFinding(
                    vulnerability="Web Vulnerability",
                    description=line,
                    severity=severity,
                    endpoint=f"{target}:{port}",
                    port=port,
                    service="http",
                    tool="nikto",
                    sources=["nikto"]
                ))
        
        return findings
    
    @staticmethod  
    def parse_ssh_audit_output(output: str, target: str, port: int) -> List[SecurityFinding]:
        """Parse SSH-audit JSON output into security findings."""
        findings = []
        
        try:
            data = json.loads(output)
            
            # Parse SSH audit results
            if 'errors' in data:
                for error in data['errors']:
                    findings.append(SecurityFinding(
                        vulnerability="SSH Configuration Error",
                        description=error,
                        severity=SeverityLevel.HIGH,
                        endpoint=f"{target}:{port}",
                        port=port,
                        service="ssh",
                        tool="ssh-audit",
                        sources=["ssh-audit"]
                    ))
            
            if 'warnings' in data:
                for warning in data['warnings']:
                    findings.append(SecurityFinding(
                        vulnerability="SSH Configuration Warning",
                        description=warning,
                        severity=SeverityLevel.MEDIUM,
                        endpoint=f"{target}:{port}",
                        port=port,
                        service="ssh", 
                        tool="ssh-audit",
                        sources=["ssh-audit"]
                    ))
                    
        except json.JSONDecodeError:
            # Fallback to text parsing
            if 'fail' in output.lower() or 'error' in output.lower():
                findings.append(SecurityFinding(
                    vulnerability="SSH Security Issue",
                    description="SSH audit detected security issues",
                    severity=SeverityLevel.MEDIUM,
                    endpoint=f"{target}:{port}",
                    port=port,
                    service="ssh",
                    tool="ssh-audit",
                    sources=["ssh-audit"]
                ))
        
        return findings
    
    @staticmethod
    def parse_testssl_output(output: str, target: str, port: int) -> List[SecurityFinding]:
        """Parse TestSSL JSON output into security findings."""
        findings = []
        
        try:
            data = json.loads(output)
            
            if isinstance(data, list):
                for item in data:
                    if item.get('severity') in ['HIGH', 'CRITICAL', 'MEDIUM', 'LOW']:
                        severity_map = {
                            'CRITICAL': SeverityLevel.CRITICAL,
                            'HIGH': SeverityLevel.HIGH,
                            'MEDIUM': SeverityLevel.MEDIUM,
                            'LOW': SeverityLevel.LOW
                        }
                        
                        findings.append(SecurityFinding(
                            vulnerability=item.get('id', 'SSL/TLS Issue'),
                            description=item.get('finding', ''),
                            severity=severity_map.get(item.get('severity'), SeverityLevel.MEDIUM),
                            endpoint=f"{target}:{port}",
                            port=port,
                            service="ssl",
                            tool="testssl",
                            sources=["testssl"],
                            metadata={'cve': item.get('cve', '')}
                        ))
                        
        except json.JSONDecodeError:
            logger.warning(f"Failed to parse TestSSL JSON output for {target}:{port}")
        
        return findings
    
    @staticmethod
    def parse_gobuster_output(output: str, target: str, port: int) -> List[SecurityFinding]:
        """Parse Gobuster directory enumeration output."""
        findings = []
        
        lines = output.split('\n')
        for line in lines:
            line = line.strip()
            if line.startswith('/') and 'Status:' in line:
                # Found directory/file
                parts = line.split()
                if len(parts) >= 3:
                    path = parts[0]
                    status_code = parts[2] if 'Status:' in parts[1] else 'Unknown'
                    
                    # Consider certain paths as potential security issues
                    if any(sensitive in path.lower() for sensitive in ['admin', 'config', 'backup', 'test', '.env', 'debug']):
                        findings.append(SecurityFinding(
                            vulnerability="Sensitive Directory/File Exposed",
                            description=f"Found potentially sensitive path: {path} (Status: {status_code})",
                            severity=SeverityLevel.MEDIUM,
                            endpoint=f"{target}:{port}{path}",
                            port=port,
                            service="http",
                            tool="gobuster",
                            sources=["gobuster"]
                        ))
        
        return findings


class ResultDeduplicator:
    """Handles deduplication and merging of security findings."""
    
    def __init__(self, config: DeduplicationConfig):
        self.config = config
        self.findings: Dict[str, SecurityFinding] = {}
        self.raw_outputs: Dict[str, str] = {}
        self.tool_runs: List[Dict[str, Any]] = []
        
    def add_tool_output(self, tool_name: str, target: str, port: int, 
                       raw_output: str, command: str) -> None:
        """Add raw tool output and parse into findings."""
        # Store raw output with unique key (include microseconds for uniqueness)
        timestamp = datetime.now().isoformat()
        import uuid
        output_key = f"{tool_name}_{target}_{port}_{timestamp}_{uuid.uuid4().hex[:8]}"
        self.raw_outputs[output_key] = raw_output
        
        # Record tool execution
        self.tool_runs.append({
            'tool': tool_name,
            'target': target,
            'port': port,
            'command': command,
            'timestamp': timestamp,
            'output_key': output_key
        })
        
        # Parse output into findings
        findings = self._parse_tool_output(tool_name, raw_output, target, port)
        
        # Add findings with deduplication
        for finding in findings:
            finding.raw_output = output_key  # Reference to raw output
            self._add_finding(finding)
    
    def _parse_tool_output(self, tool_name: str, output: str, 
                          target: str, port: int) -> List[SecurityFinding]:
        """Parse tool output based on tool type."""
        parser_map = {
            'nikto': ResultParser.parse_nikto_output,
            'ssh-audit': ResultParser.parse_ssh_audit_output,
            'testssl': ResultParser.parse_testssl_output,
            'testssl.sh': ResultParser.parse_testssl_output,
            'gobuster': ResultParser.parse_gobuster_output
        }
        
        parser = parser_map.get(tool_name)
        if parser:
            return parser(output, target, port)
        else:
            # Generic parsing - look for common vulnerability indicators
            return self._generic_parse(output, target, port, tool_name)
    
    def _generic_parse(self, output: str, target: str, port: int, tool_name: str) -> List[SecurityFinding]:
        """Generic parsing for unknown tools."""
        findings = []
        
        # Look for common vulnerability indicators
        vuln_indicators = ['vuln', 'vulnerable', 'exploit', 'cve-', 'risk', 'warning', 'error']
        
        lines = output.split('\n')
        for line in lines:
            line_lower = line.lower()
            if any(indicator in line_lower for indicator in vuln_indicators):
                severity = SeverityLevel.MEDIUM
                if any(high in line_lower for high in ['critical', 'high', 'exploit']):
                    severity = SeverityLevel.HIGH
                elif any(low in line_lower for low in ['low', 'info', 'note']):
                    severity = SeverityLevel.LOW
                
                findings.append(SecurityFinding(
                    vulnerability=f"{tool_name.title()} Finding",
                    description=line.strip(),
                    severity=severity,
                    endpoint=f"{target}:{port}",
                    port=port,
                    tool=tool_name,
                    sources=[tool_name]
                ))
        
        return findings
    
    def _add_finding(self, finding: SecurityFinding) -> None:
        """Add finding with deduplication logic."""
        if not self.config.enabled:
            # No deduplication - add with unique key
            unique_key = f"{finding.tool}_{finding.endpoint}_{len(self.findings)}"
            self.findings[unique_key] = finding
            return
        
        # Generate deduplication key
        dedup_key = self._generate_dedup_key(finding)
        
        if dedup_key in self.findings:
            # Merge with existing finding
            self.findings[dedup_key] = self._merge_findings(self.findings[dedup_key], finding)
        else:
            self.findings[dedup_key] = finding
    
    def _generate_dedup_key(self, finding: SecurityFinding) -> str:
        """Generate deduplication key based on configured fields."""
        key_parts = []
        
        for field in self.config.fields:
            if hasattr(finding, field):
                value = getattr(finding, field)
                if isinstance(value, Enum):
                    key_parts.append(value.name)
                else:
                    key_parts.append(str(value))
        
        # Create hash from key parts for consistent deduplication
        key_string = "|".join(key_parts)
        return hashlib.md5(key_string.encode()).hexdigest()
    
    def _merge_findings(self, existing: SecurityFinding, new: SecurityFinding) -> SecurityFinding:
        """Merge two findings based on configured strategy."""
        if self.config.merge_strategy == MergeStrategy.HIGHEST_SEVERITY:
            if new.severity.value > existing.severity.value:
                # Keep new finding but combine sources
                new.sources = list(set(existing.sources + new.sources))
                return new
            else:
                # Keep existing but add new source
                existing.sources = list(set(existing.sources + new.sources))
                return existing
                
        elif self.config.merge_strategy == MergeStrategy.COMBINE_SOURCES:
            # Combine all information
            existing.sources = list(set(existing.sources + new.sources))
            existing.description += f" | {new.description}"
            # Take highest severity
            if new.severity.value > existing.severity.value:
                existing.severity = new.severity
            return existing
            
        elif self.config.merge_strategy == MergeStrategy.LAST_WINS:
            new.sources = list(set(existing.sources + new.sources))
            return new
            
        else:  # FIRST_WINS
            existing.sources = list(set(existing.sources + new.sources))
            return existing
    
    def get_deduplicated_findings(self) -> List[SecurityFinding]:
        """Get all deduplicated findings."""
        return list(self.findings.values())
    
    def get_findings_by_severity(self, min_severity: SeverityLevel = SeverityLevel.LOW) -> List[SecurityFinding]:
        """Get findings filtered by minimum severity."""
        return [f for f in self.findings.values() if f.severity.value >= min_severity.value]
    
    def get_raw_output(self, output_key: str) -> Optional[str]:
        """Get raw output by key."""
        return self.raw_outputs.get(output_key)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get deduplication statistics."""
        findings = list(self.findings.values())
        severity_counts = {}
        tool_counts = {}
        
        for finding in findings:
            severity = finding.severity.name
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            for tool in finding.sources:
                tool_counts[tool] = tool_counts.get(tool, 0) + 1
        
        return {
            'total_findings': len(findings),
            'total_raw_outputs': len(self.raw_outputs),
            'tool_runs': len(self.tool_runs),
            'severity_distribution': severity_counts,
            'tool_distribution': tool_counts,
            'deduplication_enabled': self.config.enabled,
            'merge_strategy': self.config.merge_strategy.value
        }
    
    def export_results(self, output_dir: Path, formats: List[str] = None) -> Dict[str, Path]:
        """Export deduplicated results in various formats."""
        if formats is None:
            formats = ['json']
        
        output_files = {}
        findings = self.get_deduplicated_findings()
        
        # JSON export
        if 'json' in formats:
            json_file = output_dir / "deduplicated_findings.json"
            json_data = {
                'findings': [f.to_dict() for f in findings],
                'statistics': self.get_statistics(),
                'raw_outputs': {k: v for k, v in self.raw_outputs.items()},
                'tool_runs': self.tool_runs
            }
            
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, indent=2, ensure_ascii=False)
            output_files['json'] = json_file
        
        # CSV export
        if 'csv' in formats:
            import csv
            csv_file = output_dir / "deduplicated_findings.csv"
            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['Vulnerability', 'Severity', 'Description', 'Endpoint', 'Port', 'Service', 'Sources', 'Timestamp'])
                
                for finding in findings:
                    writer.writerow([
                        finding.vulnerability,
                        finding.severity.name,
                        finding.description,
                        finding.endpoint,
                        finding.port,
                        finding.service,
                        ', '.join(finding.sources),
                        finding.timestamp
                    ])
            output_files['csv'] = csv_file
        
        # HTML report export
        if 'html' in formats:
            html_file = output_dir / "deduplicated_findings.html"
            self._export_html_report(findings, html_file)
            output_files['html'] = html_file
        
        logger.info(f"Exported {len(findings)} deduplicated findings to {len(output_files)} formats")
        return output_files
    
    def _export_html_report(self, findings: List[SecurityFinding], html_file: Path) -> None:
        """Export findings as HTML report."""
        # Build HTML content safely without .format() conflicts
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        count = len(findings)
        
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>AutoTest Security Findings Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        .finding {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
        .critical {{ border-left: 5px solid #ff0000; }}
        .high {{ border-left: 5px solid #ff6600; }}
        .medium {{ border-left: 5px solid #ffaa00; }}
        .low {{ border-left: 5px solid #ffff00; }}
        .info {{ border-left: 5px solid #0066ff; }}
        .severity {{ font-weight: bold; padding: 2px 8px; border-radius: 3px; color: white; }}
        .critical-sev {{ background-color: #ff0000; }}
        .high-sev {{ background-color: #ff6600; }}
        .medium-sev {{ background-color: #ffaa00; }}
        .low-sev {{ background-color: #ffff00; color: black; }}
        .info-sev {{ background-color: #0066ff; }}
    </style>
</head>
<body>
    <h1>AutoTest Security Findings Report</h1>
    <p>Generated: {timestamp}</p>
    <p>Total Findings: {count}</p>
"""
        
        # Sort findings by severity (highest first)
        findings.sort(key=lambda x: x.severity.value, reverse=True)
        
        for finding in findings:
            severity_class = finding.severity.name.lower()
            html_content += f"""
    <div class="finding {severity_class}">
        <h3>{finding.vulnerability}</h3>
        <p><span class="severity {severity_class}-sev">{finding.severity.name}</span></p>
        <p><strong>Endpoint:</strong> {finding.endpoint}</p>
        <p><strong>Description:</strong> {finding.description}</p>
        <p><strong>Sources:</strong> {', '.join(finding.sources)}</p>
        <p><strong>Service:</strong> {finding.service}</p>
        <p><strong>Timestamp:</strong> {finding.timestamp}</p>
    </div>
"""
        
        html_content += """
</body>
</html>
"""
        
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)