# OneSixtyOne SNMP Plugin Fix Summary

## Issue Analysis

The original SNMP plugin implementation had potential issues with the onesixtyone command line construction and output parsing.

## OneSixtyOne Command Line Syntax

### Correct Syntax
```bash
onesixtyone [options] <host>
```

### Command Line Options

- **`-c <communityfile>`** - File with community names to try
- **`-i <inputfile>`** - File with target hosts  
- **`-o <outputfile>`** - Output log file (outputs to both stdout AND file)
- **`-p <port>`** - Alternate destination SNMP port (default: 161)
- **`-d`** - Debug mode (use twice for more info)
- **`-s`** - Short mode, only print IP addresses
- **`-w n`** - Wait n milliseconds between packets (default: 10)
- **`-q`** - Quiet mode, don't print to stdout (use with -o)

### Key Findings

1. **Output Behavior**: OneSixtyOne outputs to BOTH stdout and the file specified with `-o`
2. **Port Specification**: Uses `-p` flag for non-default ports
3. **Target Position**: The target must be the LAST argument

## Fixed Implementation

### Key Changes Made:

1. **Command Construction**:
   ```python
   # Correct order:
   cmd = [tool_path]
   cmd.extend(["-c", community_list])
   cmd.extend(["-o", str(output_file)])
   if port != 161:
       cmd.extend(["-p", str(port)])
   cmd.append(target)  # Target must be last
   ```

2. **Output Parsing**:
   - Primary source: Parse stdout (not the output file)
   - Output format: `IP [community] system description`
   - Example: `192.168.1.1 [public] Linux router 2.6.18`

3. **Error Handling**:
   - Check stderr for errors
   - Handle timeout appropriately
   - Save both stdout and stderr for debugging

4. **Enhanced Logging**:
   - Save raw output with command details
   - Log summary of findings
   - Better debug information

## Usage Examples

### Basic Scan
```bash
onesixtyone -c communities.txt -o output.log 192.168.1.1
```

### Non-default Port
```bash
onesixtyone -c communities.txt -o output.log -p 1161 192.168.1.1
```

### Network Scan
```bash
onesixtyone -c communities.txt -o output.log 192.168.1.0/24
```

### Quiet Mode with Output
```bash
onesixtyone -q -c communities.txt -o output.log 192.168.1.1
```

## Output Format

OneSixtyOne outputs successful findings in this format:
```
IP [community] system description
```

Example output:
```
192.168.1.1 [public] Hardware: x86 Family 6 Model 8 Stepping 3 AT/AT COMPATIBLE - Software: Windows 2000 Version 5.0
192.168.1.2 [private] Linux router 2.6.18-92.1.22.el5 #1 SMP Tue Dec 16 12:03:43 EST 2008 i686
```

## Testing the Fix

To test the fixed plugin:

1. Ensure onesixtyone is installed:
   ```bash
   apt-get install onesixtyone
   ```

2. Run a test scan:
   ```python
   from autotest.plugins.services.snmp_fixed import SNMPPlugin
   
   plugin = SNMPPlugin()
   results = plugin.execute("192.168.1.1", port=161)
   ```

3. Check the output:
   - Look for findings in `results["findings"]`
   - Check raw output in the file specified in `results["raw_output"]`
   - Verify the command in `results["command"]`

## Common Issues and Solutions

1. **No output**: Check if SNMP service is running on target
2. **Timeout**: Increase timeout parameter or check network connectivity
3. **Permission denied**: Ensure you have permission to scan the target
4. **Tool not found**: Install onesixtyone package

## Recommendations

1. Use a comprehensive community string wordlist
2. Consider using SNMPv3 for better security
3. Restrict SNMP access to authorized management stations
4. Change default community strings immediately