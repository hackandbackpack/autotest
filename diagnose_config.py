#!/usr/bin/env python3
"""
Diagnostic script to check why save_runtime_config might not be found.
"""

import sys
import os
import importlib
import inspect

def main():
    print("AutoTest Configuration Diagnostic Tool")
    print("=" * 50)
    
    # Check Python version
    print(f"\n1. Python Version: {sys.version}")
    
    # Check current working directory
    print(f"\n2. Current Directory: {os.getcwd()}")
    
    # Check if we can find the autotest directory
    autotest_path = os.path.join(os.getcwd(), 'autotest')
    print(f"\n3. AutoTest directory exists: {os.path.exists(autotest_path)}")
    
    # Try to import Config
    print("\n4. Attempting to import Config class...")
    try:
        # Add current directory to path
        if os.getcwd() not in sys.path:
            sys.path.insert(0, os.getcwd())
        
        # Try different import methods
        try:
            from autotest.core.config import Config
            print("   ✓ Successfully imported from autotest.core.config")
            config_module_path = inspect.getfile(Config)
            print(f"   Module location: {config_module_path}")
        except ImportError as e:
            print(f"   ✗ Failed to import from autotest.core.config: {e}")
            
            # Try direct import
            try:
                from core.config import Config
                print("   ✓ Successfully imported from core.config")
                config_module_path = inspect.getfile(Config)
                print(f"   Module location: {config_module_path}")
            except ImportError as e2:
                print(f"   ✗ Failed to import from core.config: {e2}")
                print("\n   ERROR: Cannot import Config class!")
                return
        
        # Check if save_runtime_config exists
        print("\n5. Checking for save_runtime_config method...")
        config_instance = Config()
        
        if hasattr(config_instance, 'save_runtime_config'):
            print("   ✓ save_runtime_config method EXISTS")
            print("   Method signature:", inspect.signature(config_instance.save_runtime_config))
        else:
            print("   ✗ save_runtime_config method NOT FOUND")
            print("   Available methods:")
            for method in dir(config_instance):
                if not method.startswith('_'):
                    print(f"     - {method}")
        
        # Check for .pyc files
        print("\n6. Checking for cached Python files...")
        cache_dirs = []
        for root, dirs, files in os.walk(os.getcwd()):
            if '__pycache__' in dirs:
                cache_dirs.append(os.path.join(root, '__pycache__'))
        
        if cache_dirs:
            print(f"   Found {len(cache_dirs)} __pycache__ directories")
            print("   Consider clearing these if you're having import issues:")
            for cache_dir in cache_dirs[:5]:  # Show first 5
                print(f"     - {cache_dir}")
            if len(cache_dirs) > 5:
                print(f"     ... and {len(cache_dirs) - 5} more")
        
        # Check file modification times
        print("\n7. Checking file modification times...")
        config_file = os.path.join(os.getcwd(), 'autotest', 'core', 'config.py')
        if os.path.exists(config_file):
            import datetime
            mtime = os.path.getmtime(config_file)
            mod_time = datetime.datetime.fromtimestamp(mtime)
            print(f"   core/config.py last modified: {mod_time}")
        
    except Exception as e:
        print(f"\nUnexpected error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "=" * 50)
    print("Diagnostic complete.")
    
    # Recommendations
    print("\nRecommendations:")
    print("1. Make sure you're in the correct directory (should contain 'autotest' folder)")
    print("2. Clear Python cache: find . -type d -name __pycache__ -exec rm -rf {} +")
    print("3. Ensure you have the latest code from the repository")
    print("4. Try running: python -c \"from autotest.core.config import Config; print(hasattr(Config(), 'save_runtime_config'))\"")

if __name__ == "__main__":
    main()