# NetExec Detection Fix Summary

## Problem
The current netexec detection method was failing because:
1. NetExec does not support the `--version` flag
2. When run without arguments, netexec shows help/usage output instead of version info
3. The detection was looking for version output that doesn't exist

## Solution
Updated the detection method in both RDP and SMB plugins to:
1. Run netexec without any arguments first (which shows help)
2. Check both stdout and stderr for netexec-specific indicators
3. Look for multiple indicators to confirm it's really netexec:
   - "netexec", "nxc", "crackmapexec"
   - "network protocol enumeration"
   - "pentesting"
4. Fallback to trying `-h` flag if the command times out
5. Require at least 2 indicators to avoid false positives

## Files Modified
- `/autotest/plugins/services/rdp.py` - Updated `_find_netexec()` and `_is_netexec_available()`
- `/autotest/plugins/services/smb.py` - Updated `_find_netexec()` and `check_required_tools()`

## Testing
Created test scripts to verify the detection approach:
- `test_netexec_detection.py` - Tests various detection methods
- `recommended_netexec_detection.py` - Shows the recommended approach

## Key Changes

### Old Detection (Failing)
```python
result = subprocess.run([cmd, "--version"], capture_output=True, text=True)
if result.returncode == 0:
    return cmd
```

### New Detection (Working)
```python
# Run without arguments - netexec shows help/usage
result = subprocess.run([cmd], capture_output=True, text=True, timeout=5)

# Check both stdout and stderr for netexec indicators
combined_output = (result.stdout + result.stderr).lower()

# Look for multiple indicators
indicators = ["netexec", "nxc", "network protocol enumeration", "pentesting"]
found_indicators = sum(1 for ind in indicators if ind in combined_output)

if found_indicators >= 2:
    return cmd
```

## Notes
- NetExec may be installed as `netexec`, `nxc`, `crackmapexec`, or `cme`
- The tool shows usage/help when run without arguments
- Some systems may have timeout issues, so we handle TimeoutExpired exceptions
- The detection now works even if netexec doesn't support traditional version flags