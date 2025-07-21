#!/usr/bin/env python3
"""
AutoTest - Automated Network Penetration Testing Framework

A comprehensive framework for automated security testing that orchestrates
multiple tools to perform reconnaissance, vulnerability scanning, and exploitation.
"""

import argparse
import asyncio
import json
import logging
import os
import sys
import signal
import time
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional

from core.config import Config, ValidationError
from core.dispatcher import Dispatcher
from core.results import ResultsManager
from ui.tui import AutoTestTUI, TaskStatus
from utils.logger import setup_logging, get_logger
from utils.network import parse_targets, validate_targets


__version__ = "1.0.0"


class AutoTest:
    """Main AutoTest application class"""
    
    def __init__(self, config_path: Optional[str] = None, no_ui: bool = False):
        """Initialize AutoTest
        
        Args:
            config_path: Path to configuration file
            no_ui: Disable terminal UI
        """
        self.config = None
        self.dispatcher = None
        self.results_manager = None
        self.ui = None if no_ui else AutoTestTUI()
        self.logger = get_logger(__name__)
        self._shutdown = False
        
        # Setup signal handlers
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # Load configuration
        if config_path:
            self._load_config(config_path)
            
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals"""
        self.logger.info(f"Received signal {signum}, initiating shutdown...")
        self._shutdown = True
        if self.dispatcher:
            asyncio.create_task(self.dispatcher.cancel_all())
        if self.ui:
            self.ui.stop()
            
    def _load_config(self, config_path: str):
        """Load configuration from file"""
        try:
            self.config = Config.from_file(config_path)
            self.logger.info(f"Configuration loaded from {config_path}")
        except ValidationError as e:
            self.logger.error(f"Configuration validation failed: {e}")
            sys.exit(1)
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}")
            sys.exit(1)
            
    async def run(self, targets: List[str], options: Dict[str, Any]) -> int:
        """Run AutoTest against specified targets
        
        Args:
            targets: List of target specifications
            options: Command-line options
            
        Returns:
            Exit code (0 for success, non-zero for failure)
        """
        start_time = time.time()
        exit_code = 0
        
        try:
            # Initialize UI if enabled
            if self.ui:
                self.ui.start()
                self.ui.log(f"AutoTest v{__version__} starting...")
                
            # Validate and parse targets
            if self.ui:
                self.ui.add_task("Target Validation")
                self.ui.update_task("Target Validation", status=TaskStatus.RUNNING)
                
            parsed_targets = []
            for target_spec in targets:
                try:
                    parsed = parse_targets(target_spec)
                    validated = validate_targets(parsed)
                    parsed_targets.extend(validated)
                except Exception as e:
                    self.logger.error(f"Invalid target {target_spec}: {e}")
                    if self.ui:
                        self.ui.update_task("Target Validation", status=TaskStatus.FAILED, 
                                          message=str(e))
                    return 1
                    
            if self.ui:
                self.ui.complete_task("Target Validation", 
                                    message=f"{len(parsed_targets)} targets validated")
                self.ui.set_progress(0, len(parsed_targets))
                
            self.logger.info(f"Processing {len(parsed_targets)} targets")
            
            # Initialize results manager
            output_dir = Path(options.get('output', 'autotest_results'))
            self.results_manager = ResultsManager(output_dir)
            
            # Initialize dispatcher
            self.dispatcher = Dispatcher(
                config=self.config,
                results_manager=self.results_manager,
                max_concurrent=options.get('threads', 10),
                ui=self.ui
            )
            
            # Process targets
            results = await self._process_targets(parsed_targets, options)
            
            # Generate reports
            if self.ui:
                self.ui.add_task("Report Generation")
                self.ui.update_task("Report Generation", status=TaskStatus.RUNNING)
                
            await self._generate_reports(results, options)
            
            if self.ui:
                self.ui.complete_task("Report Generation")
                
            # Summary
            elapsed = time.time() - start_time
            self._print_summary(results, elapsed)
            
        except KeyboardInterrupt:
            self.logger.info("Interrupted by user")
            exit_code = 130
        except Exception as e:
            self.logger.error(f"Fatal error: {e}", exc_info=True)
            exit_code = 1
        finally:
            # Cleanup
            if self.ui:
                self.ui.stop()
                
        return exit_code
        
    async def _process_targets(self, targets: List[str], options: Dict[str, Any]) -> Dict[str, Any]:
        """Process all targets
        
        Args:
            targets: List of validated targets
            options: Processing options
            
        Returns:
            Results dictionary
        """
        results = {
            'targets': {},
            'summary': {
                'total': len(targets),
                'completed': 0,
                'failed': 0,
                'vulnerabilities': {
                    'critical': 0,
                    'high': 0,
                    'medium': 0,
                    'low': 0,
                    'info': 0
                }
            }
        }
        
        # Process each target
        for i, target in enumerate(targets):
            if self._shutdown:
                break
                
            if self.ui:
                self.ui.set_current_target(target)
                self.ui.log(f"Starting scan of {target}")
                
            try:
                # Run modules against target
                target_results = await self.dispatcher.process_target(target, options)
                
                # Store results
                results['targets'][target] = target_results
                results['summary']['completed'] += 1
                
                # Update vulnerability counts
                self._update_vuln_counts(results['summary']['vulnerabilities'], 
                                       target_results)
                
                if self.ui:
                    self.ui.set_progress(i + 1, len(targets))
                    self.ui.log(f"Completed scan of {target}")
                    
            except Exception as e:
                self.logger.error(f"Failed to process {target}: {e}")
                results['summary']['failed'] += 1
                results['targets'][target] = {'error': str(e)}
                
                if self.ui:
                    self.ui.log(f"Failed to scan {target}: {e}")
                    
        return results
        
    def _update_vuln_counts(self, summary: Dict[str, int], target_results: Dict[str, Any]):
        """Update vulnerability counts from target results"""
        # This would parse the results from various tools and categorize vulnerabilities
        # For now, this is a placeholder
        pass
        
    async def _generate_reports(self, results: Dict[str, Any], options: Dict[str, Any]):
        """Generate output reports
        
        Args:
            results: Scan results
            options: Report options
        """
        formats = options.get('format', ['json', 'html'])
        if isinstance(formats, str):
            formats = [formats]
            
        for fmt in formats:
            try:
                if fmt == 'json':
                    await self.results_manager.save_json_report(results)
                elif fmt == 'html':
                    await self.results_manager.save_html_report(results)
                elif fmt == 'xml':
                    await self.results_manager.save_xml_report(results)
                else:
                    self.logger.warning(f"Unknown report format: {fmt}")
            except Exception as e:
                self.logger.error(f"Failed to generate {fmt} report: {e}")
                
    def _print_summary(self, results: Dict[str, Any], elapsed: float):
        """Print scan summary"""
        summary = results['summary']
        
        print("\n" + "="*60)
        print("SCAN SUMMARY")
        print("="*60)
        print(f"Total Targets: {summary['total']}")
        print(f"Completed: {summary['completed']}")
        print(f"Failed: {summary['failed']}")
        print(f"Elapsed Time: {elapsed:.2f} seconds")
        
        print("\nVulnerabilities Found:")
        for severity, count in summary['vulnerabilities'].items():
            if count > 0:
                print(f"  {severity.upper()}: {count}")
                
        print("\nResults saved to:", self.results_manager.output_dir)
        print("="*60)


def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description="AutoTest - Automated Network Penetration Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s 192.168.1.0/24
  %(prog)s 10.0.0.1-10.0.0.50
  %(prog)s example.com
  %(prog)s targets.txt -c config.yaml
  %(prog)s 192.168.1.1 --quick --format html
        """
    )
    
    parser.add_argument(
        'targets',
        nargs='+',
        help='Target hosts/networks (IP, CIDR, range, hostname, or file)'
    )
    
    parser.add_argument(
        '-c', '--config',
        help='Configuration file (default: autotest.yaml)'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='autotest_results',
        help='Output directory (default: autotest_results)'
    )
    
    parser.add_argument(
        '-f', '--format',
        nargs='+',
        choices=['json', 'html', 'xml'],
        default=['json', 'html'],
        help='Output format(s) (default: json html)'
    )
    
    parser.add_argument(
        '-t', '--threads',
        type=int,
        default=10,
        help='Maximum concurrent tasks (default: 10)'
    )
    
    parser.add_argument(
        '--quick',
        action='store_true',
        help='Quick scan (skip time-intensive modules)'
    )
    
    parser.add_argument(
        '--stealth',
        action='store_true',
        help='Stealth mode (slower, less detectable)'
    )
    
    parser.add_argument(
        '--no-ui',
        action='store_true',
        help='Disable terminal UI'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='count',
        default=0,
        help='Increase verbosity (-v, -vv, -vvv)'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version=f'%(prog)s {__version__}'
    )
    
    # Module selection
    module_group = parser.add_argument_group('module selection')
    module_group.add_argument(
        '--enable',
        nargs='+',
        help='Enable specific modules'
    )
    module_group.add_argument(
        '--disable',
        nargs='+',
        help='Disable specific modules'
    )
    module_group.add_argument(
        '--list-modules',
        action='store_true',
        help='List available modules and exit'
    )
    
    return parser.parse_args()


def main():
    """Main entry point"""
    args = parse_arguments()
    
    # Setup logging
    log_level = logging.WARNING - (args.verbose * 10)
    setup_logging(level=log_level)
    
    # Handle special actions
    if args.list_modules:
        # Would list available modules
        print("Available modules:")
        print("  - nmap: Network discovery and port scanning")
        print("  - nuclei: Vulnerability scanning")
        print("  - metasploit: Exploitation framework")
        print("  - nikto: Web server scanner")
        print("  - dirb: Directory/file brute forcer")
        return 0
        
    # Prepare options
    options = {
        'output': args.output,
        'format': args.format,
        'threads': args.threads,
        'quick': args.quick,
        'stealth': args.stealth,
        'enable_modules': args.enable,
        'disable_modules': args.disable,
    }
    
    # Load targets from files if needed
    targets = []
    for target in args.targets:
        if os.path.isfile(target):
            with open(target, 'r') as f:
                targets.extend(line.strip() for line in f if line.strip())
        else:
            targets.append(target)
            
    # Create and run AutoTest
    app = AutoTest(config_path=args.config, no_ui=args.no_ui)
    
    # Run async main
    exit_code = asyncio.run(app.run(targets, options))
    
    return exit_code


if __name__ == '__main__':
    sys.exit(main())