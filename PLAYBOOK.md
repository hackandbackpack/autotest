# AutoTest Playbook System

AutoTest uses a YAML-based playbook system to define which security commands to run against discovered services. This allows you to customize the testing workflow to match your specific needs.

## How It Works

1. **Default Playbook**: AutoTest ships with a `playbook.yml` file containing standard security testing commands
2. **User Customization**: You can create your own version at `~/.autotest/playbook.yml` 
3. **Automatic Selection**: AutoTest automatically uses your custom playbook if it exists, otherwise uses the default

## Customizing Your Playbook

### Step 1: Create Your Custom Playbook
```bash
# Create the AutoTest config directory
mkdir -p ~/.autotest

# Copy the default playbook to customize
cp playbook.yml ~/.autotest/playbook.yml

# Edit your custom version
nano ~/.autotest/playbook.yml
```

### Step 2: Modify Commands
The playbook is organized by service types. Each service can have multiple commands:

```yaml
services:
  http:
    - name: "nikto-scan"
      command: "nikto -h {protocol}://{target}:{port} -output {output_dir}/nikto_{target}_{port}.txt"
      enabled: true
      priority: high
      timeout: 300
      description: "Web vulnerability scanner"
      
    - name: "custom-web-scan"
      command: "my-custom-tool --target {target} --port {port}"
      enabled: true
      priority: medium
      timeout: 600
      requires: ["my-custom-tool"]
      description: "My custom web security scanner"
```

### Step 3: Available Variables
You can use these variables in your commands:

- `{target}` - The target IP or hostname
- `{port}` - The port number being tested
- `{service}` - The detected service name (http, ssh, smb, etc.)
- `{protocol}` - Protocol (http/https for web services)
- `{output_dir}` - Directory where results should be saved
- `{timestamp}` - Current timestamp
- `{scan_id}` - Unique identifier for this scan

## Command Options

Each command can include these options:

- **name**: Unique identifier for the command
- **command**: The actual command to execute (with variable substitution)
- **enabled**: `true`/`false` to enable or disable the command
- **priority**: `high`/`medium`/`low` for execution priority
- **timeout**: Maximum seconds to wait for completion
- **requires**: List of tools that must be available (e.g., `["nmap", "gobuster"]`)
- **auth_required**: `true` if command requires `--auth-test` flag to be enabled
- **description**: Human-readable description of what the command does

## Adding New Services

You can add commands for new services by adding them to the `services` section:

```yaml
services:
  # ... existing services ...
  
  custom-service:
    - name: "custom-scanner"
      command: "my-scanner -t {target} -p {port} -o {output_dir}/results.txt"
      enabled: true
      priority: medium
      timeout: 300
      description: "Custom service scanner"
```

## Running Multiple Tools

You can run the same tool multiple times with different options:

```yaml
services:
  http:
    - name: "nikto-quick"
      command: "nikto -h {protocol}://{target}:{port} -Tuning 1,2,3"
      enabled: true
      priority: high
      timeout: 300
      
    - name: "nikto-comprehensive"
      command: "nikto -h {protocol}://{target}:{port} -Tuning 1,2,3,4,5,6,7,8,9"
      enabled: true
      priority: medium
      timeout: 900
```

## Deduplication

AutoTest automatically deduplicates similar findings from multiple tools while preserving the raw output from each tool. The deduplication behavior can be configured in the `post_process` section:

```yaml
post_process:
  deduplication:
    enabled: true
    fields: ["vulnerability", "endpoint"]
    merge_strategy: "highest_severity"
```

## Testing Your Playbook

After creating your custom playbook, you can test it:

```bash
# Run a quick scan to test your playbook
python autotest.py 192.168.1.100

# Check the logs to see which commands are being executed
tail -f output/scan_*/autotest.log
```

## Best Practices

1. **Start Small**: Begin with the default playbook and gradually add your custom commands
2. **Test Commands**: Verify your custom commands work before adding them to the playbook
3. **Use Timeouts**: Set appropriate timeouts to prevent commands from hanging
4. **Document Changes**: Use the `description` field to document what each command does
5. **Version Control**: Consider keeping your custom playbook in version control
6. **Tool Availability**: Use the `requires` field to specify tool dependencies

## Example: Adding a Custom Web Scanner

```yaml
services:
  http:
    # ... existing commands ...
    
    - name: "dirb-scan"
      command: "dirb {protocol}://{target}:{port} /usr/share/wordlists/dirb/common.txt -o {output_dir}/dirb_{target}_{port}.txt"
      enabled: true
      priority: medium
      timeout: 600
      requires: ["dirb"]
      description: "Directory brute-force with DIRB"
      
    - name: "whatweb-aggressive"
      command: "whatweb -a 3 {protocol}://{target}:{port} --log-json {output_dir}/whatweb_aggressive_{target}_{port}.json"
      enabled: true
      priority: low
      timeout: 180
      requires: ["whatweb"]
      description: "Aggressive web technology fingerprinting"
```

This system gives you complete control over what security testing tools AutoTest runs while maintaining the automated discovery and result management features.