#!/usr/bin/env python3
"""
Installation verification script for AutoTest.
This helps diagnose common issues.
"""

import sys
import os
import importlib
import subprocess

def check_python_version():
    """Check Python version."""
    print(f"Python version: {sys.version}")
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ required")
        return False
    print("✅ Python version OK")
    return True

def check_git_status():
    """Check git status and latest commit."""
    try:
        # Check current branch
        result = subprocess.run(['git', 'branch', '--show-current'], 
                              capture_output=True, text=True)
        print(f"Current branch: {result.stdout.strip()}")
        
        # Check latest commit
        result = subprocess.run(['git', 'log', '-1', '--oneline'], 
                              capture_output=True, text=True)
        print(f"Latest commit: {result.stdout.strip()}")
        
        # Check for uncommitted changes
        result = subprocess.run(['git', 'status', '--porcelain'], 
                              capture_output=True, text=True)
        if result.stdout:
            print("⚠️  Uncommitted changes detected")
        
        return True
    except Exception as e:
        print(f"❌ Git check failed: {e}")
        return False

def check_config_class():
    """Check Config class methods."""
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from core.config import Config
        
        print("\nConfig class methods:")
        methods = [m for m in dir(Config) if not m.startswith('_')]
        for method in sorted(methods):
            print(f"  - {method}")
        
        if hasattr(Config, 'save_runtime_config'):
            print("✅ save_runtime_config method exists")
        else:
            print("❌ save_runtime_config method missing")
            
        if hasattr(Config, 'validate'):
            print("✅ validate method exists")
        else:
            print("❌ validate method missing")
            
        return True
    except Exception as e:
        print(f"❌ Failed to check Config class: {e}")
        return False

def check_plugins():
    """Check plugin availability."""
    try:
        from plugins.services.smb import SMBPlugin
        from plugins.services.rdp import RDPPlugin
        from plugins.services.snmp import SNMPPlugin
        from plugins.services.ssh import SSHPlugin
        from plugins.services.ssl import SSLPlugin
        
        print("\n✅ All plugins importable")
        return True
    except Exception as e:
        print(f"❌ Plugin import failed: {e}")
        return False

def check_smart_file_detection():
    """Check if smart file detection exists."""
    try:
        with open('autotest.py', 'r') as f:
            content = f.read()
            
        if '_is_likely_file_path' in content:
            print("✅ Smart file detection function exists")
        else:
            print("❌ Smart file detection function missing")
            
        return True
    except Exception as e:
        print(f"❌ Failed to check autotest.py: {e}")
        return False

def main():
    """Run all checks."""
    print("AutoTest Installation Checker")
    print("=" * 40)
    
    # Change to script directory
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    all_ok = True
    
    # Run checks
    all_ok &= check_python_version()
    print()
    all_ok &= check_git_status()
    print()
    all_ok &= check_config_class()
    all_ok &= check_plugins()
    all_ok &= check_smart_file_detection()
    
    print("\n" + "=" * 40)
    if all_ok:
        print("✅ All checks passed!")
        print("\nIf you're still getting errors, try:")
        print("  1. git pull origin main")
        print("  2. Restart your Python interpreter")
        print("  3. Check file permissions")
    else:
        print("❌ Some checks failed")
        print("\nTry running:")
        print("  git pull origin main")
        print("  git status")
    
    return 0 if all_ok else 1

if __name__ == '__main__':
    sys.exit(main())