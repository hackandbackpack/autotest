"""
Playbook management system for AutoTest.

Provides YAML-based customizable security testing workflows.
"""

import yaml
import logging
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class Priority(Enum):
    """Task priority levels."""
    LOW = 1
    MEDIUM = 2  
    HIGH = 3
    CRITICAL = 4


class MergeStrategy(Enum):
    """Result deduplication merge strategies."""
    HIGHEST_SEVERITY = "highest_severity"
    COMBINE_SOURCES = "combine_sources"
    FIRST_WINS = "first_wins"
    LAST_WINS = "last_wins"


@dataclass
class CommandDefinition:
    """Definition of a single command in a playbook."""
    name: str
    command: str
    enabled: bool = True
    priority: Priority = Priority.MEDIUM
    timeout: int = 300
    requires: List[str] = field(default_factory=list)
    custom: bool = False
    auth_required: bool = False
    description: str = ""
    
    @classmethod
    def from_dict(cls, name: str, data: Dict[str, Any]) -> 'CommandDefinition':
        """Create CommandDefinition from dictionary."""
        return cls(
            name=name,
            command=data['command'],
            enabled=data.get('enabled', True),
            priority=Priority[data.get('priority', 'medium').upper()],
            timeout=data.get('timeout', 300),
            requires=data.get('requires', []),
            custom=data.get('custom', False),
            auth_required=data.get('auth_required', False),
            description=data.get('description', '')
        )


@dataclass 
class DeduplicationConfig:
    """Configuration for result deduplication."""
    enabled: bool = True
    fields: List[str] = field(default_factory=lambda: ["vulnerability", "endpoint"])
    merge_strategy: MergeStrategy = MergeStrategy.HIGHEST_SEVERITY
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DeduplicationConfig':
        """Create DeduplicationConfig from dictionary."""
        return cls(
            enabled=data.get('enabled', True),
            fields=data.get('fields', ["vulnerability", "endpoint", "severity"]),
            merge_strategy=MergeStrategy(data.get('merge_strategy', 'highest_severity'))
        )


@dataclass
class PlaybookSettings:
    """Global playbook settings."""
    timeout: int = 600
    max_parallel: int = 10
    output_formats: List[str] = field(default_factory=lambda: ["json", "txt"])
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PlaybookSettings':
        """Create PlaybookSettings from dictionary."""
        return cls(
            timeout=data.get('timeout', 600),
            max_parallel=data.get('max_parallel', 10),
            output_formats=data.get('output_format', ["json", "txt"])
        )


class Playbook:
    """Represents a complete security testing playbook."""
    
    def __init__(self, name: str, description: str = "", version: str = "1.0"):
        self.name = name
        self.description = description
        self.version = version
        self.settings = PlaybookSettings()
        self.services: Dict[str, List[CommandDefinition]] = {}
        self.variables: Dict[str, str] = {}
        self.deduplication = DeduplicationConfig()
        
    @classmethod
    def from_yaml(cls, yaml_path: Path) -> 'Playbook':
        """Load playbook from YAML file."""
        try:
            with open(yaml_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)
                
            playbook = cls(
                name=data.get('name', yaml_path.stem),
                description=data.get('description', ''),
                version=data.get('version', '1.0')
            )
            
            # Load settings
            if 'settings' in data:
                playbook.settings = PlaybookSettings.from_dict(data['settings'])
            
            # Load services and commands
            if 'services' in data:
                for service_name, commands_data in data['services'].items():
                    playbook.services[service_name] = []
                    for cmd_data in commands_data:
                        cmd_name = cmd_data.get('name', f"unnamed_{len(playbook.services[service_name])}")
                        cmd_def = CommandDefinition.from_dict(cmd_name, cmd_data)
                        playbook.services[service_name].append(cmd_def)
            
            # Load variables
            playbook.variables = data.get('variables', {})
            
            # Load deduplication config
            if 'post_process' in data and 'deduplication' in data['post_process']:
                playbook.deduplication = DeduplicationConfig.from_dict(
                    data['post_process']['deduplication']
                )
                
            logger.info(f"Loaded playbook '{playbook.name}' with {len(playbook.services)} service types")
            return playbook
            
        except Exception as e:
            raise PlaybookError(f"Failed to load playbook from {yaml_path}: {e}")
    
    def get_commands_for_service(self, service: str, port: int) -> List[CommandDefinition]:
        """Get all enabled commands for a specific service."""
        commands = []
        
        # Direct service match
        if service.lower() in self.services:
            commands.extend([cmd for cmd in self.services[service.lower()] if cmd.enabled])
        
        # Port-based service mapping
        port_service_map = {
            80: 'http', 443: 'https', 22: 'ssh', 21: 'ftp', 
            25: 'smtp', 53: 'dns', 139: 'smb', 445: 'smb',
            3389: 'rdp', 23: 'telnet', 110: 'pop3', 143: 'imap'
        }
        
        if port in port_service_map:
            mapped_service = port_service_map[port]
            if mapped_service in self.services:
                commands.extend([cmd for cmd in self.services[mapped_service] if cmd.enabled])
        
        # Handle HTTPS as HTTP with SSL
        if port == 443 and 'http' in self.services:
            commands.extend([cmd for cmd in self.services['http'] if cmd.enabled])
        
        return commands
    
    def substitute_variables(self, command_template: str, context: Dict[str, Any]) -> str:
        """Substitute variables in command template."""
        # Combine playbook variables with context
        all_vars = {**self.variables, **context}
        
        # Simple variable substitution using {variable} syntax
        result = command_template
        for var_name, var_value in all_vars.items():
            pattern = f"{{{var_name}}}"
            result = result.replace(pattern, str(var_value))
        
        # Check for unsubstituted variables
        unsubstituted = re.findall(r'\{([^}]+)\}', result)
        if unsubstituted:
            logger.warning(f"Unsubstituted variables in command: {unsubstituted}")
        
        return result
    
    def validate(self) -> List[str]:
        """Validate playbook configuration."""
        issues = []
        
        # Check required fields
        if not self.name:
            issues.append("Playbook name is required")
        
        # Validate commands
        for service_name, commands in self.services.items():
            for cmd in commands:
                if not cmd.command:
                    issues.append(f"Command '{cmd.name}' in service '{service_name}' has empty command")
                
                # Check for required variables in command
                variables_in_cmd = re.findall(r'\{([^}]+)\}', cmd.command)
                for var in variables_in_cmd:
                    if var not in self.variables and var not in ['target', 'port', 'service', 'protocol', 'output_dir', 'timestamp', 'scan_id']:
                        issues.append(f"Command '{cmd.name}' references undefined variable: {var}")
        
        # Validate timeout values
        if self.settings.timeout <= 0:
            issues.append("Global timeout must be positive")
        
        for service_commands in self.services.values():
            for cmd in service_commands:
                if cmd.timeout <= 0:
                    issues.append(f"Command '{cmd.name}' timeout must be positive")
        
        return issues
    
    def to_yaml(self) -> str:
        """Export playbook to YAML format."""
        data = {
            'name': self.name,
            'description': self.description,
            'version': self.version,
            'settings': {
                'timeout': self.settings.timeout,
                'max_parallel': self.settings.max_parallel,
                'output_format': self.settings.output_formats
            },
            'services': {},
            'variables': self.variables,
            'post_process': {
                'deduplication': {
                    'enabled': self.deduplication.enabled,
                    'fields': self.deduplication.fields,
                    'merge_strategy': self.deduplication.merge_strategy.value
                }
            }
        }
        
        # Convert services and commands
        for service_name, commands in self.services.items():
            data['services'][service_name] = []
            for cmd in commands:
                cmd_data = {
                    'name': cmd.name,
                    'command': cmd.command,
                    'enabled': cmd.enabled,
                    'priority': cmd.priority.name.lower(),
                    'timeout': cmd.timeout
                }
                if cmd.requires:
                    cmd_data['requires'] = cmd.requires
                if cmd.custom:
                    cmd_data['custom'] = cmd.custom
                if cmd.auth_required:
                    cmd_data['auth_required'] = cmd.auth_required
                if cmd.description:
                    cmd_data['description'] = cmd.description
                    
                data['services'][service_name].append(cmd_data)
        
        return yaml.dump(data, default_flow_style=False, sort_keys=False)


class PlaybookManager:
    """Manages the single AutoTest playbook."""
    
    def __init__(self, playbook_path: Optional[Path] = None):
        """Initialize the playbook manager.
        
        Args:
            playbook_path: Path to the playbook file. If None, uses default location.
        """
        if playbook_path is None:
            # Check for user customized version first
            user_playbook = Path.home() / '.autotest' / 'playbook.yml'
            default_playbook = Path(__file__).parent.parent / 'playbook.yml'
            
            if user_playbook.exists():
                self.playbook_path = user_playbook
            else:
                self.playbook_path = default_playbook
        else:
            self.playbook_path = Path(playbook_path)
        
        self._ensure_user_directory()
    
    def _ensure_user_directory(self):
        """Ensure user configuration directory exists."""
        user_dir = Path.home() / '.autotest'
        user_dir.mkdir(parents=True, exist_ok=True)
    
    def load_playbook(self) -> Playbook:
        """Load the AutoTest playbook."""
        try:
            if self.playbook_path.exists():
                playbook = Playbook.from_yaml(self.playbook_path)
                logging.info(f"Loaded playbook from: {self.playbook_path}")
                return playbook
            else:
                # Create default playbook if none exists
                logging.info("No playbook found, creating default playbook")
                return self.create_default_playbook()
        except PlaybookError as e:
            logging.error(f"Failed to load playbook from {self.playbook_path}: {e}")
            logging.info("Creating default playbook instead")
            return self.create_default_playbook()
    
    def save_playbook(self, playbook: Playbook) -> None:
        """Save the playbook to user's configuration directory."""
        user_playbook_path = Path.home() / '.autotest' / 'playbook.yml'
        
        try:
            yaml_content = playbook.to_yaml()
            with open(user_playbook_path, 'w', encoding='utf-8') as f:
                f.write(yaml_content)
            logging.info(f"Saved playbook to: {user_playbook_path}")
        except Exception as e:
            raise PlaybookError(f"Failed to save playbook: {e}")
    
    def get_playbook_path(self) -> Path:
        """Get the current playbook path."""
        return self.playbook_path
    
    def validate_playbook(self) -> Tuple[bool, List[str]]:
        """Validate the current playbook and return issues."""
        try:
            playbook = self.load_playbook()
            issues = playbook.validate()
            return len(issues) == 0, issues
        except Exception as e:
            return False, [f"Could not load playbook: {e}"]
    
    def create_default_playbook(self) -> Playbook:
        """Create a default playbook matching current AutoTest behavior."""
        playbook = Playbook(
            name="default",
            description="Default AutoTest security testing playbook",
            version="1.0"
        )
        
        # HTTP/HTTPS services
        playbook.services['http'] = [
            CommandDefinition(
                name="nikto-standard",
                command="nikto -h {protocol}://{target}:{port} -output {output_dir}/nikto_{target}_{port}.txt -Format txt",
                priority=Priority.HIGH,
                description="Standard Nikto web vulnerability scan"
            ),
            CommandDefinition(
                name="whatweb-fingerprint", 
                command="whatweb --color=never --no-errors -a 1 {protocol}://{target}:{port} --log-json {output_dir}/whatweb_{target}_{port}.json",
                priority=Priority.MEDIUM,
                description="Web application fingerprinting"
            ),
            CommandDefinition(
                name="gobuster-directories",
                command="gobuster dir -u {protocol}://{target}:{port} -w {wordlist} -o {output_dir}/gobuster_{target}_{port}.txt -q",
                priority=Priority.HIGH,
                requires=["gobuster"],
                description="Directory enumeration"
            )
        ]
        
        # SSH services  
        playbook.services['ssh'] = [
            CommandDefinition(
                name="ssh-audit",
                command="ssh-audit --json {target}:{port} > {output_dir}/ssh_audit_{target}_{port}.json",
                priority=Priority.HIGH,
                description="SSH security audit"
            )
        ]
        
        # SMB services
        playbook.services['smb'] = [
            CommandDefinition(
                name="netexec-shares",
                command="netexec smb {target} --shares -u '' -p ''",
                priority=Priority.HIGH,
                description="SMB share enumeration"
            ),
            CommandDefinition(
                name="netexec-auth-test",
                command="netexec smb {target} -u {username_list} -p {password_list}",
                priority=Priority.MEDIUM,
                auth_required=True,
                description="SMB authentication testing"
            )
        ]
        
        # SSL/TLS services
        playbook.services['ssl'] = [
            CommandDefinition(
                name="testssl-comprehensive",
                command="testssl.sh --jsonfile {output_dir}/testssl_{target}_{port}.json --quiet {target}:{port}",
                priority=Priority.HIGH,
                requires=["testssl.sh"],
                description="SSL/TLS security assessment"
            )
        ]
        
        # Set default variables
        playbook.variables = {
            'wordlist': '/usr/share/wordlists/dirb/common.txt',
            'username_list': '/usr/share/wordlists/metasploit/unix_users.txt', 
            'password_list': '/usr/share/wordlists/rockyou.txt'
        }
        
        return playbook
    
    def save_playbook(self, playbook: Playbook, name: str = None) -> Path:
        """Save playbook to file."""
        if not name:
            name = playbook.name
        
        # Save to user directory
        user_dir = Path.home() / ".autotest/playbooks"
        user_dir.mkdir(parents=True, exist_ok=True)
        
        playbook_path = user_dir / f"{name}.yml"
        with open(playbook_path, 'w', encoding='utf-8') as f:
            f.write(playbook.to_yaml())
        
        logger.info(f"Saved playbook '{name}' to {playbook_path}")
        return playbook_path


class PlaybookError(Exception):
    """Exception raised for playbook-related errors."""
    pass