# Manual Binary Analysis Tool (aka 'mba')

A comprehensive security tool for analyzing binary files to detect potential malware indicators, with robust error handling, comprehensive logging, and contextual assessment capabilities.

## Features

- **Contextual IOC Detection**: Analyzes binaries for indicators of compromise (IOCs) with intelligent context-aware filtering
- **Security-First Design**: Built with input validation, path traversal protection, and subprocess security
- **Comprehensive Error Handling**: Graceful degradation with detailed error reporting and logging
- **Multiple Analysis Modes**: Basic, verbose, and deep analysis options
- **Export Capabilities**: JSON export for integration with other security tools
- **Configurable Limits**: Adjustable file size limits and timeouts for safe operation
- **Rich Logging**: Structured logging with configurable levels and audit trails

## Installation

### Prerequisites

1. **Python 3.7+**
2. **System utilities** (automatically checked):
   - `strings` - for string extraction from binaries
   - `file` - for file type identification
   - `readelf` / `objdump` - for binary analysis (optional)
   - `ldd` - for library dependency analysis (optional)

### Ubuntu/Debian Installation

```bash
# Install required system packages
sudo apt update
sudo apt install python3 python3-pip binutils file

# Clone or download the script
wget https://your-repo/enhanced_binary_analyzer.py
# or
git clone https://your-repo/enhanced-binary-analyzer.git
cd enhanced-binary-analyzer

# Make the script executable
chmod +x enhanced_binary_analyzer.py

# Optional: Create a symbolic link for global access
sudo ln -s $(pwd)/enhanced_binary_analyzer.py /usr/local/bin/binary-analyzer
```

### Red Hat/CentOS/Fedora Installation

```bash
# Install required system packages
sudo yum install python3 python3-pip binutils file
# or for newer versions:
sudo dnf install python3 python3-pip binutils file

# Follow the same steps as Ubuntu above
```

## Quick Start

### Basic Usage

```bash
# Analyze a single binary
python3 enhanced_binary_analyzer.py /path/to/binary

# Analyze multiple binaries
python3 enhanced_binary_analyzer.py binary1 binary2 binary3

# Verbose analysis with all details
python3 enhanced_binary_analyzer.py -v /path/to/binary
```

### Example Output

Here's an example of analyzing the Cloudflare CFSSL binary:

```bash
ubuntu@server:~/cfssl/bin$ python3 mba.py cfssl
```

**Output:**
```
2025-06-25 19:11:43,989 - __main__ - INFO - 🔍 Starting enhanced binary analysis...
🔍 Enhanced Binary Analysis Tool
==================================================
2025-06-25 19:11:43,990 - __main__ - INFO - File validation passed: /home/ubuntu/cfssl/bin/cfssl (14669472 bytes)
2025-06-25 19:11:43,990 - __main__ - INFO - Starting analysis of: /home/ubuntu/cfssl/bin/cfssl

--- Binary Information ---
File: cfssl
Size: 14,669,472 bytes
SHA256: 57b1e2344cea86d352bf54ab4d2291b003409e05827892bd68326892fab1a9e5
Type: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked
ELF Binary: Yes
Go Binary: No

✅ LEGITIMATE FINDINGS (SAFE)
  URLs (21):
    - https://cdnjs.cloudflare.com/ajax/libs/mithril/0.2.5/mithril.min.js: Matches known benign pattern
    - https://en.wikipedia.org/wiki/Fermat%27s_factorization_method: Matches known benign pattern
    - https://protobuf.dev/reference/go/faq#namespace-conflictCA: Matches known benign pattern
    ... and 18 more (use --verbose to see all)
  
  Shell Commands (1):
    - exec: Matches legitimate pattern: exec\.[A-Za-z]+
  
  Permission Changes (2):
    - dd: Matches legitimate pattern: add
    - ps: Matches legitimate pattern: push
  
  Domains (617):
    - convert.go: Matches known benign pattern
    - prime.go: Matches known benign pattern
    ... and 614 more (use --verbose to see all)
  
  Network (1):
    - connect: Matches legitimate pattern: net\.Conn

--- Summary ---
Categorized as safe: 642
Categorized as suspicious: 0
Categorized as malicious: 0
Needing further review: 987
Risk Assessment: Low - Many potential matches but likely false positives

==================================================
=== Final Report ===
✅ No malware indicators detected in 1 successfully analyzed files

=== Recommendations ===
1. Binaries appear clean based on analysis
2. Verify integrity by comparing with official releases
3. Keep monitoring for new threat intelligence
```

This example shows a **clean analysis** of a legitimate binary where:
- 642 items were categorized as safe (legitimate patterns)
- 0 suspicious or malicious indicators were found
- 987 items need review but are likely false positives
- The tool correctly identified this as a low-risk, clean binary

### Advanced Usage

```bash
# Deep analysis with debug logging
python3 enhanced_binary_analyzer.py --deep-analysis --log-level DEBUG suspicious_file

# Export results to JSON
python3 enhanced_binary_analyzer.py --export-report analysis_results.json /path/to/binary

# Analyze with custom file size limit (50MB)
python3 enhanced_binary_analyzer.py --max-file-size 52428800 large_binary

# Analyze all binaries in a directory
find /usr/bin -type f -executable | head -10 | xargs python3 enhanced_binary_analyzer.py
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `files` | One or more files to analyze (required) |
| `-v, --verbose` | Show detailed output including filtered items |
| `--deep-analysis` | Perform in-depth analysis with context examination |
| `--export-report FILE` | Export results to specified JSON file |
| `--log-level LEVEL` | Set logging level (DEBUG, INFO, WARNING, ERROR) |
| `--max-file-size SIZE` | Maximum file size to analyze in bytes (default: 100MB) |
| `-h, --help` | Show help message and exit |

## Understanding the Output

### Risk Assessment Levels

- **✅ Minimal**: No suspicious indicators detected
- **⚠️ Low**: Potentially suspicious items but likely false positives
- **⚠️ Medium**: Suspicious indicators found, requires review
- **🚨 High**: Probable malicious indicators detected

### Finding Categories

#### Safe Findings (✅)
Items categorized as legitimate based on:
- Known benign patterns (URLs, version numbers, etc.)
- Legitimate context (standard library usage)
- RFC-compliant network addresses

#### Suspicious Findings (⚠️)
Items requiring manual review:
- Network activity with hardcoded IPs
- File operations in temporary directories
- Potential cryptomining references

#### Malicious Findings (🚨)
Items matching known malware patterns:
- Sysrv.GA trojan indicators
- Suspicious process names
- Known malicious domains/IPs

## Configuration

### Environment Variables

```bash
# Set default log level
export BINARY_ANALYZER_LOG_LEVEL=DEBUG

# Set custom temporary directory
export TMPDIR=/secure/temp/path
```

### Custom Pattern Files

You can extend the analysis by modifying the pattern lists in the script:

- `BENIGN_PATTERNS`: Add known safe patterns to reduce false positives
- `MALWARE_INDICATORS`: Add known malicious patterns for detection
- `SUSPICIOUS_PATTERNS`: Add patterns that warrant investigation

## Security Considerations

### Safe Operation

- **Path Validation**: All file paths are validated to prevent path traversal attacks
- **Resource Limits**: File size and analysis time limits prevent resource exhaustion
- **Subprocess Security**: All external commands use absolute paths and input validation
- **Privilege Separation**: Runs with user privileges, no root access required

### Network Security

- **No Network Calls**: The tool operates entirely offline (except for VirusTotal URL generation)
- **Local Analysis Only**: All analysis is performed on local files
- **No Data Transmission**: No binary data is sent to external services

## Logging and Monitoring

### Log Files

- **Default Location**: `binary_analysis.log` in current directory
- **Log Rotation**: Implement log rotation for production use
- **Audit Trail**: All security events and analysis results are logged

### Log Levels

- **DEBUG**: Detailed operation information, IOC extraction details
- **INFO**: General progress and summary information
- **WARNING**: Non-critical issues (missing tools, minor errors)
- **ERROR**: Analysis failures and security violations

## Integration with Other Tools

### SIEM Integration

```bash
# Export to JSON for SIEM ingestion
python3 enhanced_binary_analyzer.py --export-report /var/log/security/binary_analysis.json /suspicious/files/*

# Parse results with jq
cat analysis_results.json | jq '.results[] | select(.malicious_count > 0)'
```

### Automation Scripts

```bash
#!/bin/bash
# Example: Automated scanning script

SCAN_DIR="/incoming/files"
RESULTS_DIR="/var/log/security"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

for file in "$SCAN_DIR"/*; do
    if [ -f "$file" ]; then
        python3 enhanced_binary_analyzer.py \
            --export-report "$RESULTS_DIR/scan_${TIMESTAMP}.json" \
            --log-level INFO \
            "$file"
    fi
done
```

## Troubleshooting

### Common Issues

#### Permission Denied
```bash
# Ensure file is readable
chmod +r /path/to/binary

# Check file ownership
ls -la /path/to/binary
```

#### Missing System Tools
```bash
# Install missing utilities
sudo apt install binutils file

# Check available tools
which strings file readelf objdump ldd
```

#### Memory/Performance Issues
```bash
# Reduce file size limit
python3 enhanced_binary_analyzer.py --max-file-size 10485760 large_file

# Use basic analysis mode (skip --deep-analysis)
python3 enhanced_binary_analyzer.py /path/to/binary
```

### Debug Mode

Enable debug logging for troubleshooting:

```bash
python3 enhanced_binary_analyzer.py --log-level DEBUG -v suspicious_file
```

## Known Limitations

- **Binary Format Support**: Optimized for ELF binaries, limited support for other formats
- **Language Detection**: Best results with Go binaries, C/C++ binaries
- **String Encoding**: Uses Latin-1 encoding for broad compatibility
- **Performance**: Large binaries (>100MB) may require extended analysis time

## Contributing

### Adding Detection Patterns

1. **Benign Patterns**: Add to `BENIGN_PATTERNS` list to reduce false positives
2. **Malware Indicators**: Add to `MALWARE_INDICATORS` for known threats
3. **Context Patterns**: Extend `LEGITIMATE_CONTEXTS` for better classification

### Reporting Issues

When reporting issues, please include:
- Operating system and version
- Python version
- Command used
- Complete error message
- Sample file (if not sensitive)

## License

This tool is provided as-is for security research and analysis purposes. Please ensure compliance with your organization's security policies and applicable laws when analyzing binaries.

## Security Disclosure

If you discover security vulnerabilities in this tool, please report them responsibly by:
1. Not disclosing the vulnerability publicly
2. Providing detailed reproduction steps
3. Allowing reasonable time for fixes

## Changelog

### Version 2.0.0
- ✅ Added comprehensive security controls
- ✅ Implemented robust error handling
- ✅ Added structured logging with multiple levels
- ✅ Introduced JSON export functionality
- ✅ Added configurable resource limits
- ✅ Improved context-aware analysis
- ✅ Enhanced malware detection patterns

### Version 1.0.0
- Initial release with basic IOC detection
- Context-aware false positive reduction
- Support for multiple binary formats

---

**⚠️ Disclaimer**: This tool is for legitimate security analysis purposes only. Users are responsible for ensuring they have proper authorization to analyze any binaries and must comply with applicable laws and regulations.
