#!/usr/bin/env python3
"""
Install and configure required tools for AutoTest.

This script:
1. Checks for required tools
2. Installs missing tools via pip
3. Ensures installed tools are accessible on Windows
4. Handles PATH configuration
"""

import os
import sys
import subprocess
import platform
import json
import shutil
from pathlib import Path
from typing import Dict, List, Tuple, Optional

# Tool definitions with install commands
TOOLS = {
    # Discovery tools
    "nmap": {
        "install": {
            "windows": "Download from https://nmap.org/download.html",
            "linux": "sudo apt-get install nmap",
            "darwin": "brew install nmap"
        },
        "check_command": ["nmap", "--version"],
        "type": "binary"
    },
    "masscan": {
        "install": {
            "windows": "Download from https://github.com/robertdavidgraham/masscan/releases",
            "linux": "sudo apt-get install masscan",
            "darwin": "brew install masscan"
        },
        "check_command": ["masscan", "--version"],
        "type": "binary"
    },
    
    # Python tools
    "sslyze": {
        "install": {
            "all": "pip install sslyze"
        },
        "check_command": ["sslyze", "--help"],
        "python_module": "sslyze",
        "type": "python"
    },
    "netexec": {
        "install": {
            "all": "pip install netexec"
        },
        "check_command": ["netexec", "--help"],
        "python_module": "netexec",
        "type": "python"
    },
    
    # Other tools
    "hydra": {
        "install": {
            "windows": "Download from https://github.com/vanhauser-thc/thc-hydra",
            "linux": "sudo apt-get install hydra",
            "darwin": "brew install hydra"
        },
        "check_command": ["hydra", "-h"],
        "type": "binary"
    },
    "onesixtyone": {
        "install": {
            "windows": "Build from https://github.com/trailofbits/onesixtyone",
            "linux": "sudo apt-get install onesixtyone",
            "darwin": "brew install onesixtyone"
        },
        "check_command": ["onesixtyone"],
        "type": "binary"
    }
}


def get_python_scripts_dir() -> Optional[Path]:
    """Get the Scripts directory where pip installs executables."""
    # Method 1: Get from site packages
    try:
        import site
        user_base = site.USER_BASE
        if platform.system() == "Windows":
            scripts_dir = Path(user_base) / "Scripts"
        else:
            scripts_dir = Path(user_base) / "bin"
        
        if scripts_dir.exists():
            return scripts_dir
    except:
        pass
    
    # Method 2: Get from pip show
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "show", "pip"],
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if line.startswith("Location:"):
                    location = line.split(":", 1)[1].strip()
                    # Go up to the Python directory and find Scripts
                    base_path = Path(location).parent
                    if platform.system() == "Windows":
                        scripts_dir = base_path / "Scripts"
                    else:
                        scripts_dir = base_path / "bin"
                    
                    if scripts_dir.exists():
                        return scripts_dir
    except:
        pass
    
    # Method 3: Check common locations
    if platform.system() == "Windows":
        # Check for Microsoft Store Python
        local_packages = Path.home() / "AppData" / "Local" / "Packages"
        if local_packages.exists():
            for item in local_packages.iterdir():
                if item.name.startswith("PythonSoftwareFoundation.Python"):
                    scripts_dir = item / "LocalCache" / "local-packages" / "Python311" / "Scripts"
                    if scripts_dir.exists():
                        return scripts_dir
    
    return None


def is_in_path(directory: Path) -> bool:
    """Check if a directory is in the system PATH."""
    path_dirs = os.environ.get("PATH", "").split(os.pathsep)
    return str(directory) in path_dirs or str(directory).lower() in [p.lower() for p in path_dirs]


def add_to_path_windows(directory: Path) -> bool:
    """Add a directory to the user PATH on Windows."""
    try:
        import winreg
        
        # Open the Environment key
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Environment",
            0,
            winreg.KEY_ALL_ACCESS
        )
        
        try:
            # Get current PATH
            current_path, _ = winreg.QueryValueEx(key, "Path")
        except WindowsError:
            current_path = ""
        
        # Check if already in PATH
        if str(directory) not in current_path:
            # Add to PATH
            new_path = current_path + os.pathsep + str(directory) if current_path else str(directory)
            winreg.SetValueEx(key, "Path", 0, winreg.REG_EXPAND_SZ, new_path)
            print(f"[+] Added {directory} to user PATH")
            print("    Note: You may need to restart your terminal for changes to take effect")
            
            # Broadcast environment change
            try:
                import ctypes
                from ctypes import wintypes
                
                HWND_BROADCAST = 0xFFFF
                WM_SETTINGCHANGE = 0x001A
                
                result = ctypes.c_long()
                ctypes.windll.user32.SendMessageTimeoutW(
                    HWND_BROADCAST,
                    WM_SETTINGCHANGE,
                    0,
                    "Environment",
                    2,  # SMTO_ABORTIFHUNG
                    5000,
                    ctypes.byref(result)
                )
            except:
                pass
                
            return True
        else:
            print(f"[*] {directory} is already in PATH")
            return True
            
        winreg.CloseKey(key)
        
    except Exception as e:
        print(f"[-] Failed to add to PATH: {e}")
        return False


def check_tool(tool_name: str, tool_info: Dict) -> Tuple[bool, Optional[str]]:
    """Check if a tool is available and return its path."""
    # Check if it's a Python module first
    if tool_info.get("type") == "python" and "python_module" in tool_info:
        # Try as Python module
        try:
            result = subprocess.run(
                [sys.executable, "-m", tool_info["python_module"], "--help"],
                capture_output=True,
                timeout=5
            )
            if result.returncode == 0:
                return True, f"{sys.executable} -m {tool_info['python_module']}"
        except:
            pass
    
    # Check normal command
    check_cmd = tool_info.get("check_command", [tool_name])
    
    # Try with full path if in Scripts directory
    scripts_dir = get_python_scripts_dir()
    if scripts_dir and tool_info.get("type") == "python":
        tool_path = scripts_dir / f"{tool_name}.exe" if platform.system() == "Windows" else scripts_dir / tool_name
        if tool_path.exists():
            return True, str(tool_path)
    
    # Try regular command
    try:
        result = subprocess.run(
            check_cmd,
            capture_output=True,
            timeout=5
        )
        if result.returncode == 0 or result.returncode == 1:  # Some tools return 1 for help
            path = shutil.which(check_cmd[0])
            return True, path
    except:
        pass
    
    return False, None


def install_tool(tool_name: str, tool_info: Dict) -> bool:
    """Install a tool."""
    print(f"\n[*] Installing {tool_name}...")
    
    install_info = tool_info.get("install", {})
    system = platform.system().lower()
    
    # Get install command
    install_cmd = install_info.get("all", install_info.get(system))
    
    if not install_cmd:
        print(f"[-] No install command available for {tool_name} on {system}")
        return False
    
    if install_cmd.startswith("Download from"):
        print(f"[!] Manual installation required: {install_cmd}")
        return False
    
    # For pip installs, use the current Python
    if "pip install" in install_cmd:
        install_cmd = install_cmd.replace("pip install", f"{sys.executable} -m pip install")
    
    print(f"    Running: {install_cmd}")
    
    try:
        # Run the install command
        if platform.system() == "Windows":
            # Don't use shell=True on Windows with pip
            if "pip install" in install_cmd or "-m pip" in install_cmd:
                result = subprocess.run(install_cmd.split(), capture_output=True, text=True)
            else:
                result = subprocess.run(install_cmd, shell=True, capture_output=True, text=True)
        else:
            result = subprocess.run(install_cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            print(f"[+] Successfully installed {tool_name}")
            return True
        else:
            print(f"[-] Failed to install {tool_name}")
            if result.stderr:
                print(f"    Error: {result.stderr}")
            return False
            
    except Exception as e:
        print(f"[-] Error installing {tool_name}: {e}")
        return False


def create_wrapper_script(tool_name: str, python_module: str, scripts_dir: Path) -> bool:
    """Create a wrapper batch script for a Python tool on Windows."""
    if platform.system() != "Windows":
        return False
        
    wrapper_path = scripts_dir / f"{tool_name}.bat"
    
    try:
        with open(wrapper_path, 'w') as f:
            f.write(f"@echo off\n")
            f.write(f'"{sys.executable}" -m {python_module} %*\n')
        
        print(f"[+] Created wrapper script: {wrapper_path}")
        return True
    except Exception as e:
        print(f"[-] Failed to create wrapper: {e}")
        return False


def check_tools() -> Tuple[bool, List[str]]:
    """Check if all required tools are available.
    
    Returns:
        Tuple of (all_available, missing_tools)
    """
    missing_tools = []
    
    for tool_name, tool_info in TOOLS.items():
        available, _ = check_tool(tool_name, tool_info)
        if not available:
            missing_tools.append(tool_name)
    
    return len(missing_tools) == 0, missing_tools


def main():
    """Main installation routine."""
    print("AutoTest Installation & Setup")
    print("=" * 50)
    
    # Detect Python scripts directory
    scripts_dir = get_python_scripts_dir()
    if scripts_dir:
        print(f"\nPython Scripts directory: {scripts_dir}")
        
        # Check if it's in PATH
        if not is_in_path(scripts_dir):
            print(f"[!] Scripts directory is NOT in PATH")
            
            if platform.system() == "Windows":
                response = input("\nAdd Scripts directory to PATH? (y/n): ")
                if response.lower() == 'y':
                    add_to_path_windows(scripts_dir)
        else:
            print(f"[+] Scripts directory is in PATH")
    
    # Check all tools
    print("\n\nChecking required tools...")
    print("-" * 50)
    
    missing_tools = []
    available_tools = []
    
    for tool_name, tool_info in TOOLS.items():
        available, path = check_tool(tool_name, tool_info)
        
        if available:
            print(f"[+] {tool_name:<15} Available at: {path}")
            available_tools.append(tool_name)
        else:
            print(f"[-] {tool_name:<15} Not found")
            missing_tools.append(tool_name)
    
    # Install missing tools
    if missing_tools:
        print(f"\n\nMissing tools: {', '.join(missing_tools)}")
        response = input("\nInstall missing tools? (y/n): ")
        
        if response.lower() == 'y':
            for tool_name in missing_tools:
                tool_info = TOOLS[tool_name]
                
                if install_tool(tool_name, tool_info):
                    # Check again after installation
                    available, path = check_tool(tool_name, tool_info)
                    
                    if available:
                        print(f"[+] {tool_name} is now available at: {path}")
                    elif tool_info.get("type") == "python" and scripts_dir:
                        # Try creating a wrapper script
                        python_module = tool_info.get("python_module", tool_name)
                        if create_wrapper_script(tool_name, python_module, scripts_dir):
                            available, path = check_tool(tool_name, tool_info)
                            if available:
                                print(f"[+] {tool_name} is now available via wrapper")
    
    # Final summary
    print("\n\nFinal Summary")
    print("=" * 50)
    
    for tool_name, tool_info in TOOLS.items():
        available, path = check_tool(tool_name, tool_info)
        status = "[OK] Available" if available else "[FAIL] Missing"
        print(f"{tool_name:<15} {status}")
    
    print("\n[*] Installation complete!")
    
    # Save tool paths for AutoTest
    tool_paths = {}
    for tool_name, tool_info in TOOLS.items():
        available, path = check_tool(tool_name, tool_info)
        if available and path:
            tool_paths[tool_name] = path
    
    with open("tool_paths.json", 'w') as f:
        json.dump(tool_paths, f, indent=2)
    print(f"\n[+] Tool paths saved to tool_paths.json")


if __name__ == "__main__":
    main()