#!/usr/bin/env python3
"""
AutoTest - Automated Network Penetration Testing Framework

A modular tool for automating common network penetration testing tasks.
"""

import sys
import os
import logging
import signal
import threading
from pathlib import Path
from typing import List, Optional, Dict, Any
import click
from rich.console import Console
from rich.logging import RichHandler

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config import Config
from core.exceptions import AutoTestException
from core.input_parser import InputParser
from core.discovery import Discovery
from core.task_manager import TaskManager, Task
from core.output import OutputManager
from core.utils import create_directory, get_timestamp

# Import plugins
from plugins.services.smb import SMBPlugin
from plugins.services.rdp import RDPPlugin

# Import UI (optional - not available on Windows)
try:
    from ui.tui import AutoTestTUI
    TUI_AVAILABLE = True
except ImportError:
    TUI_AVAILABLE = False
    AutoTestTUI = None


# Setup logging
console = Console()


def setup_logging(log_level: str, log_file: Optional[Path] = None) -> None:
    """Setup logging configuration."""
    # Convert string level to logging constant
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(numeric_level)
    
    # Console handler with rich formatting
    console_handler = RichHandler(
        console=console,
        show_time=True,
        show_path=False
    )
    console_handler.setLevel(numeric_level)
    root_logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(numeric_level)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)


class AutoTest:
    """Main AutoTest application class."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize AutoTest."""
        self.config = Config(config_path)
        self.config.validate_config()
        
        self.input_parser = InputParser()
        self.discovery = None
        self.task_manager = None
        self.output_manager = None
        self.plugins = []
        self.tui = None
        
        # Shutdown handling
        self.shutdown_event = threading.Event()
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        logging.info("Shutdown signal received")
        self.shutdown()
    
    def load_plugins(self) -> None:
        """Load all available plugins."""
        logging.info("Loading plugins...")
        
        # Load service plugins
        try:
            # SMB plugin
            smb_plugin = SMBPlugin(self.config)
            self.plugins.append(smb_plugin)
            logging.info(f"Loaded plugin: SMB")
            
            # RDP plugin
            rdp_plugin = RDPPlugin(self.config)
            self.plugins.append(rdp_plugin)
            logging.info(f"Loaded plugin: RDP")
            
        except Exception as e:
            logging.error(f"Failed to load plugins: {e}")
            raise
        
        logging.info(f"Loaded {len(self.plugins)} plugins")
    
    def execute_plugin_task(self, task: Task) -> Any:
        """Execute a task using the appropriate plugin."""
        # Find the plugin for this task
        plugin = None
        for p in self.plugins:
            if p.name == task.plugin_name:
                plugin = p
                break
        
        if not plugin:
            raise AutoTestException(f"No plugin found for task: {task.plugin_name}")
        
        # Execute the task
        return plugin.execute_task(task, self.output_manager)
    
    def run_scan(
        self,
        targets: List[str],
        ports: Optional[str] = None,
        no_tui: bool = False
    ) -> None:
        """Run the main scanning workflow."""
        start_time = get_timestamp()
        logging.info(f"Starting AutoTest scan at {start_time}")
        
        # Create output directory
        timestamp = get_timestamp()
        output_dir_name = f"autotest_scan_{timestamp}"
        output_base = self.config.get('general.output_dir', 'output')
        output_dir = Path(output_base) / output_dir_name
        create_directory(str(output_dir))
        logging.info(f"Output directory: {output_dir}")
        
        # Initialize output manager
        self.output_manager = OutputManager(str(output_dir))
        
        # Save configuration
        self.config.save_runtime_config(output_dir)
        
        # Setup log file in output directory
        log_file = output_dir / "autotest.log"
        setup_logging(self.config.get('general.log_level', 'INFO'), log_file)
        
        try:
            # Phase 1: Discovery
            logging.info("Phase 1: Host and port discovery")
            self.discovery = Discovery(self.config)
            discovered_hosts = self.discovery.discover_hosts(targets, ports)
            
            if not discovered_hosts:
                logging.warning("No live hosts found")
                return
            
            # Export discovery results
            discovery_file = output_dir / "discovery_results.json"
            self.discovery.export_discovery_results(discovery_file)
            
            # Phase 2: Service Enumeration
            logging.info(f"Phase 2: Service enumeration on {len(discovered_hosts)} hosts")
            
            # Initialize task manager
            self.task_manager = TaskManager(self.config)
            
            # Create tasks from discovery results
            self.task_manager.create_tasks_from_discovery(discovered_hosts, self.plugins)
            
            # Setup TUI if not disabled and available
            if not no_tui and TUI_AVAILABLE:
                try:
                    self.tui = AutoTestTUI()
                    tui_thread = threading.Thread(target=self.tui.run)
                    tui_thread.daemon = True
                    tui_thread.start()
                except Exception as e:
                    logging.warning(f"Failed to start TUI: {e}")
                    self.tui = None
            elif not no_tui and not TUI_AVAILABLE:
                logging.info("Terminal UI not available on this platform")
            
            # Start task execution
            self.task_manager.start(self.execute_plugin_task)
            
            # Wait for completion
            logging.info("Waiting for tasks to complete...")
            completed = self.task_manager.wait_for_completion()
            
            if not completed:
                logging.warning("Scan timed out or was interrupted")
            
            # Phase 3: Reporting
            logging.info("Phase 3: Generating reports")
            self._generate_reports(output_dir)
            
        except KeyboardInterrupt:
            logging.info("Scan interrupted by user")
        except Exception as e:
            logging.error(f"Scan failed: {e}")
            raise
        finally:
            # Cleanup
            self.shutdown()
            
            # Create summary
            if self.output_manager:
                summary_file = self.output_manager.create_summary_log()
                logging.info(f"Output summary: {summary_file}")
            
            end_time = get_timestamp()
            logging.info(f"Scan completed at {end_time}")
    
    def _generate_reports(self, output_dir: Path) -> None:
        """Generate final reports."""
        # Collect all results
        results = {
            'scan_info': {
                'start_time': self.task_manager.stats.get('start_time'),
                'end_time': self.task_manager.stats.get('end_time'),
                'output_directory': str(output_dir)
            },
            'summary': self.task_manager.get_progress(),
            'hosts': {}
        }
        
        # Organize results by host
        for task in self.task_manager.completed_tasks:
            host = task.target
            if host not in results['hosts']:
                results['hosts'][host] = {
                    'tasks': [],
                    'open_ports': set(),
                    'services': set()
                }
            
            task_result = {
                'port': task.port,
                'service': task.service,
                'tool': task.plugin_name,
                'status': task.status.value,
                'started_at': task.started_at,
                'completed_at': task.completed_at,
                'result': task.result
            }
            
            results['hosts'][host]['tasks'].append(task_result)
            results['hosts'][host]['open_ports'].add(task.port)
            if task.service:
                results['hosts'][host]['services'].add(task.service)
        
        # Add failed tasks
        for task in self.task_manager.failed_tasks:
            host = task.target
            if host not in results['hosts']:
                results['hosts'][host] = {
                    'tasks': [],
                    'open_ports': set(),
                    'services': set()
                }
            
            task_result = {
                'port': task.port,
                'service': task.service,
                'tool': task.plugin_name,
                'status': task.status.value,
                'started_at': task.started_at,
                'completed_at': task.completed_at,
                'error': task.error
            }
            
            results['hosts'][host]['tasks'].append(task_result)
        
        # Convert sets to lists for JSON serialization
        for host_data in results['hosts'].values():
            host_data['open_ports'] = sorted(list(host_data['open_ports']))
            host_data['services'] = sorted(list(host_data['services']))
        
        # Generate reports in configured formats
        generated_reports = self.output_manager.generate_reports(results)
        
        for format_type, report_path in generated_reports.items():
            logging.info(f"Generated {format_type} report: {report_path}")
    
    def shutdown(self) -> None:
        """Shutdown the application cleanly."""
        logging.info("Shutting down AutoTest...")
        
        if self.task_manager and self.task_manager.running:
            self.task_manager.stop()
        
        self.shutdown_event.set()


@click.command()
@click.argument('targets', nargs=-1, required=True)
@click.option('-c', '--config', help='Path to configuration file')
@click.option('-p', '--ports', help='Port specification (default: from config)')
@click.option('-o', '--output', help='Output directory (default: from config)')
@click.option('--no-tui', is_flag=True, help='Disable TUI progress display')
@click.option('--log-level', default='INFO', 
              type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR']),
              help='Logging level')
@click.option('-f', '--file', help='Read targets from file')
@click.option('--nmap-xml', help='Import targets from Nmap XML file')
@click.option('--masscan-json', help='Import targets from Masscan JSON file')
def main(
    targets: tuple,
    config: Optional[str],
    ports: Optional[str],
    output: Optional[str],
    no_tui: bool,
    log_level: str,
    file: Optional[str],
    nmap_xml: Optional[str],
    masscan_json: Optional[str]
):
    """
    AutoTest - Automated Network Penetration Testing Framework
    
    Targets can be specified as:
    - IP addresses (192.168.1.1)
    - CIDR ranges (192.168.1.0/24)
    - Domains (example.com)
    - Multiple targets separated by spaces
    
    Examples:
        autotest 192.168.1.0/24
        autotest 10.0.0.1 10.0.0.2 10.0.0.3
        autotest -f targets.txt
        autotest --nmap-xml scan.xml
    """
    # Setup initial logging
    setup_logging(log_level)
    
    try:
        # Initialize AutoTest
        app = AutoTest(config)
        
        # Override output directory if specified
        if output:
            app.config.config['general']['output_dir'] = output
        
        # Load plugins
        app.load_plugins()
        
        # Parse targets
        input_parser = InputParser()
        all_targets = []
        
        # Add command line targets
        if targets:
            all_targets.extend(targets)
        
        # Add targets from file
        if file:
            file_targets = input_parser.parse_targets(Path(file))
            all_targets.extend(file_targets)
        
        # Add targets from Nmap XML
        if nmap_xml:
            nmap_results = input_parser.parse_nmap_xml(Path(nmap_xml))
            all_targets.extend(nmap_results['hosts'].keys())
        
        # Add targets from Masscan JSON
        if masscan_json:
            masscan_results = input_parser.parse_masscan_json(Path(masscan_json))
            all_targets.extend(masscan_results['hosts'].keys())
        
        if not all_targets:
            console.print("[red]Error:[/red] No targets specified")
            sys.exit(1)
        
        # Process and validate targets
        processed_targets = input_parser.parse_targets(all_targets)
        
        console.print(f"[green]Starting scan of {len(processed_targets)} targets[/green]")
        
        # Run the scan
        app.run_scan(processed_targets, ports, no_tui)
        
    except AutoTestException as e:
        console.print(f"[red]Error:[/red] {e}")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Unexpected error:[/red] {e}")
        logging.exception("Unexpected error")
        sys.exit(1)


if __name__ == '__main__':
    main()