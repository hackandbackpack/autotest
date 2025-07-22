#!/usr/bin/env python3
"""Test script to verify JSON serialization fix."""

import sys
import os
import json
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath((__file__ if "__file__" in globals() else "."))))

from core.config import Config, PathEncoder

def test_path_encoder():
    """Test the PathEncoder works correctly."""
    print("Testing PathEncoder...")
    
    # Test data with Path objects
    test_data = {
        "string": "hello",
        "number": 42,
        "path": Path("/tmp/test"),
        "nested": {
            "another_path": Path("relative/path"),
            "list_with_path": [1, 2, Path("in_list")]
        }
    }
    
    try:
        # Try to serialize with custom encoder
        json_str = json.dumps(test_data, cls=PathEncoder, indent=2)
        print("[+] Successfully serialized with PathEncoder")
        print("Result:")
        print(json_str)
        
        # Verify paths were converted to strings
        parsed = json.loads(json_str)
        # Handle both Windows and Unix path separators
        assert isinstance(parsed["path"], str)
        assert isinstance(parsed["nested"]["another_path"], str)
        assert isinstance(parsed["nested"]["list_with_path"][2], str)
        print("\n[+] All Path objects correctly converted to strings")
        
    except Exception as e:
        print(f"[-] Error: {e}")
        return False
    
    return True

def test_config_save():
    """Test Config.save_runtime_config with Path object."""
    print("\nTesting Config.save_runtime_config...")
    
    try:
        config = Config()
        
        # Test with Path object
        output_dir = Path("test_output")
        config.save_runtime_config(output_dir)
        
        # Check if files were created
        runtime_config_files = list(output_dir.glob("runtime_config_*.json"))
        latest_config = output_dir / "latest_config.json"
        
        if runtime_config_files and latest_config.exists():
            print("[+] Successfully saved runtime config with Path object")
            
            # Verify content is valid JSON
            with open(latest_config, 'r') as f:
                data = json.load(f)
            print("[+] Saved config is valid JSON")
            
            # Cleanup
            import shutil
            shutil.rmtree(output_dir)
            print("[+] Cleaned up test files")
        else:
            print("[-] Config files not created")
            return False
            
    except Exception as e:
        print(f"[-] Error: {e}")
        return False
    
    return True

def main():
    """Run all tests."""
    print("JSON Serialization Fix Test")
    print("=" * 40)
    
    all_passed = True
    
    # Run tests
    all_passed &= test_path_encoder()
    all_passed &= test_config_save()
    
    print("\n" + "=" * 40)
    if all_passed:
        print("[+] All tests passed!")
    else:
        print("[-] Some tests failed")
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())