#!/usr/bin/env python3
"""
Tool installer script for AutoTest - installs required external tools.
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path
import platform
import logging

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ToolInstaller:
    """Handles installation of required tools."""
    
    def __init__(self):
        """Initialize tool installer."""
        self.system = platform.system().lower()
        self.distro = self._get_linux_distro()
    
    def _get_linux_distro(self) -> str:
        """Get Linux distribution information."""
        if self.system != 'linux':
            return ''
        
        try:
            # Try to read from os-release
            with open('/etc/os-release', 'r') as f:
                for line in f:
                    if line.startswith('ID='):
                        return line.split('=')[1].strip().strip('"')
        except:
            pass
        
        # Fallback methods
        if shutil.which('apt-get'):
            return 'debian'
        elif shutil.which('yum') or shutil.which('dnf'):
            return 'rhel'
        elif shutil.which('pacman'):
            return 'arch'
        
        return 'unknown'
    
    def check_tool(self, command: str) -> bool:
        """Check if a tool is installed."""
        # For simple existence check, just see if the command is available
        tool_name = command.split()[0]
        if shutil.which(tool_name):
            return True
        
        # Fallback to running the command
        try:
            result = subprocess.run(
                command.split(),
                capture_output=True,
                text=True,
                timeout=5
            )
            # Some tools return non-zero for --version (e.g., masscan)
            # Check if we got any output instead
            return result.returncode == 0 or bool(result.stdout or result.stderr)
        except:
            return False
    
    def run_command(self, command: list, use_sudo: bool = False) -> bool:
        """Run a command with optional sudo."""
        if use_sudo and os.geteuid() != 0:
            command = ['sudo'] + command
        
        try:
            logger.info(f"Running: {' '.join(command)}")
            result = subprocess.run(command, check=True)
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed with exit code {e.returncode}")
            return False
        except Exception as e:
            logger.error(f"Error running command: {e}")
            return False
    
    def install_system_tools(self) -> bool:
        """Install system tools based on distribution."""
        if self.system != 'linux':
            logger.error("AutoTest currently only supports Linux systems")
            return False
        
        logger.info(f"Detected distribution: {self.distro}")
        
        # Update package lists first
        if self.distro in ['debian', 'ubuntu', 'kali']:
            if not self.run_command(['apt-get', 'update'], use_sudo=True):
                logger.warning("Failed to update package lists")
        
        # Install tools
        success = True
        
        # Install masscan and nmap
        tools_to_install = ['masscan', 'nmap']
        
        for tool in tools_to_install:
            if self.check_tool(f"{tool} --version"):
                logger.info(f"[OK] {tool} is already installed")
                continue
            
            logger.info(f"Installing {tool}...")
            
            if self.distro in ['debian', 'ubuntu', 'kali']:
                if not self.run_command(['apt-get', 'install', '-y', tool], use_sudo=True):
                    logger.error(f"Failed to install {tool}")
                    success = False
            elif self.distro in ['rhel', 'centos', 'fedora']:
                pkg_manager = 'dnf' if shutil.which('dnf') else 'yum'
                if not self.run_command([pkg_manager, 'install', '-y', tool], use_sudo=True):
                    logger.error(f"Failed to install {tool}")
                    success = False
            elif self.distro == 'arch':
                if not self.run_command(['pacman', '-S', '--noconfirm', tool], use_sudo=True):
                    logger.error(f"Failed to install {tool}")
                    success = False
            else:
                logger.error(f"Unsupported distribution for automatic {tool} installation")
                success = False
        
        return success
    
    def install_netexec(self) -> bool:
        """Install NetExec using pipx."""
        if self.check_tool("netexec --version"):
            logger.info("[OK] NetExec is already installed")
            return True
        
        logger.info("Installing NetExec...")
        
        # Check if pipx is available
        if not shutil.which('pipx'):
            logger.info("pipx not found, installing...")
            if self.distro in ['debian', 'ubuntu', 'kali']:
                if not self.run_command(['apt-get', 'install', '-y', 'pipx'], use_sudo=True):
                    # Fallback to pip install
                    if not self.run_command(['pip3', 'install', '--user', 'pipx']):
                        logger.error("Failed to install pipx")
                        return False
            else:
                if not self.run_command(['pip3', 'install', '--user', 'pipx']):
                    logger.error("Failed to install pipx")
                    return False
        
        # Install NetExec
        if not self.run_command(['pipx', 'install', 'git+https://github.com/Pennyw0rth/NetExec']):
            logger.error("Failed to install NetExec")
            return False
        
        return True
    
    def check_all_tools(self) -> dict:
        """Check status of all required tools."""
        tools = {
            'masscan': 'masscan --version',
            'nmap': 'nmap --version',
            'netexec': 'netexec --version'
        }
        
        status = {}
        for tool, check_cmd in tools.items():
            status[tool] = self.check_tool(check_cmd)
        
        return status
    
    def run_installation(self) -> bool:
        """Run the complete installation process."""
        logger.info("Starting AutoTest tool installation...")
        logger.info(f"System: {self.system}")
        logger.info(f"Distribution: {self.distro}")
        
        # Check current status
        logger.info("\nChecking current tool status:")
        initial_status = self.check_all_tools()
        
        for tool, installed in initial_status.items():
            status = "[OK]" if installed else "[X]"
            logger.info(f"{status} {tool}")
        
        # Install missing tools
        success = True
        
        if not self.install_system_tools():
            success = False
        
        if not self.install_netexec():
            success = False
        
        # Final status check
        logger.info("\nFinal tool status:")
        final_status = self.check_all_tools()
        
        all_installed = True
        for tool, installed in final_status.items():
            status = "[OK]" if installed else "[X]"
            logger.info(f"{status} {tool}")
            if not installed:
                all_installed = False
        
        if all_installed:
            logger.info("\n[SUCCESS] All tools installed successfully!")
            logger.info("You can now run: python3 autotest.py <targets>")
        else:
            logger.warning("\n[WARNING] Some tools failed to install.")
            logger.warning("Please install missing tools manually.")
        
        return success and all_installed


def main():
    """Main function."""
    print("""
+-------------------------------------------+
|          AutoTest Tool Installer          |
|                                           |
|  This script will install:                |
|  * masscan (fast port scanner)            |
|  * nmap (network mapper)                  |
|  * netexec (network service enumeration)  |
+-------------------------------------------+
""")
    
    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help']:
        print("Usage: python3 install_tools.py")
        print("       sudo python3 install_tools.py")
        print("")
        print("This script will automatically detect your Linux distribution")
        print("and install the required tools for AutoTest.")
        return 0
    
    installer = ToolInstaller()
    success = installer.run_installation()
    
    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())