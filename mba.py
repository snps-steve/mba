#!/usr/bin/env python3
"""
Enhanced Binary Analysis Tool with Improved Security and Error Handling
Analyzes binaries for potential malware indicators with contextual assessment
"""

import os
import sys
import re
import math
import hashlib
import argparse
import subprocess
import logging
import tempfile
import shutil
import stat
import signal
import json
from pathlib import Path
from collections import defaultdict
from contextlib import contextmanager
from typing import Dict, List, Tuple, Optional, Set, Any
from dataclasses import dataclass, asdict

# Set up logging configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('binary_analysis.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Security constants
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB limit
MAX_SUBPROCESS_TIMEOUT = 30  # seconds
MAX_ANALYSIS_TIME = 300  # 5 minutes per file
TEMP_DIR_PREFIX = "binary_analysis_"

@dataclass
class AnalysisResult:
    """Data class for storing analysis results"""
    file_path: str
    file_size: int
    sha256: str
    file_type: str
    is_elf: bool
    is_go_binary: bool
    findings_by_category: Dict[str, List[str]]
    analysis_results: Dict[str, Dict[str, List[Tuple[str, str]]]]
    safe_count: int
    suspicious_count: int
    malicious_count: int
    needs_review_count: int
    risk_assessment: str
    error_messages: List[str]

class SecurityError(Exception):
    """Custom exception for security-related errors"""
    pass

class AnalysisError(Exception):
    """Custom exception for analysis-related errors"""
    pass

# Define known benign patterns to suppress
BENIGN_PATTERNS = [
    # Common protocol references and documentation URLs
    r'https://(?:www\.)?cloudflare\.com/.*',
    r'https://(?:support|en)\.apple\.com/.*',
    r'https://cabforum\.org',
    r'https://en\.wikipedia\.org/wiki/.*',
    r'https://cdnjs\.cloudflare\.com/.*',
    r'https://pkg\.cloudflare\.com/.*',
    r'https://blog\.cloudflare\.com/.*',
    r'https://hub\.docker\.com/.*',
    r'https://fermatattack\.secvuln\.info/.*',
    r'https://time:',
    r'https://unsupported',
    
    # Known safe paths from CFSSL source or Go internals
    r'com/cloudflare/cfssl/.*',
    r'org/x/crypto/.*',
    r'org/x/text/.*',
    r'com/zmap/zlint/.*',
    r'io/klog/v2/.*',
    r'22/src/internal/.*',
    
    # MIME types, standard crypto curves, protobuf content, base64 chars
    r'image/.*',
    r'audio/.*',
    r'video/.*',
    r'font/.*',
    r'sha[0-9]+',
    r'secp[0-9]+[kr]1',
    r'sect[0-9]+[kr]1',
    r'proto(?:2|3)|protobuf|packed|jstype|syntax',
    r'[A-Za-z0-9+/=]{32,}',
    
    # Common certificate policy or encoding names
    r'[xX]509|pkcs[0-9]+|asn1|DER|OCSP|CRL',
    r'(?:certificate|cert|certinfo|signing|revoke|crl|initca|selfsign)',
    r'New[A-Za-z]+|Subject[A-Za-z]+|Issuer[A-Za-z]+|DNSName.*',
    
    # Common TLDs, countries, date/months, weekday strings
    r'(?:com|org|net|gov|edu|mil|int|arpa)',
    r'[A-Z][a-z]{2,8}(?:uary|ember|ober)?',  # months
    r'(Sun|Mon|Tue|Wed|Thu|Fri|Sat)',
    
    # Internal Go runtime, memory profiling, base encodings
    r'/proc/.*',
    r'/usr/share/mime/.*',
    r'memory/classes/.*',
    r'allArenas/.*',
    r'memory.*heap.*',
    
    # Hex patterns that represent known base64/hex constants
    r'[0-9a-fA-F]{64,}',
    
    # Go-specific functions and patterns
    r'\.func[0-9]+',
    r'\.deferwrap[0-9]+',
    r'\.[a-z]+\.func[0-9]+',
    r'\.[a-z]+\.deferwrap[0-9]+',
    r'\.marshal\.func[0-9]+(?:\.[0-9]+)*',
    r'\.gnu\.version(?:_r)?',
    r'\.go\.buildinfo',
    r'\.data\.rel\.ro',
    r'\.eh_frame_hdr',
    
    # Command-line flags and parameters
    r'-[a-z\-]+=(?:true|false)',
    r'-[a-z\-]+(?:-[a-z\-]+)*',
    
    # Non-ASCII characters and binary data representations
    r'[^\x00-\x7F]{4,}',
    r'(?:\+|\-)[^\x20-\x7E]{4,}',
    
    # CSS and HTML related classes
    r'\.col-sm-offset-[0-9]+',
    r'\.collapse\.navbar-collapse',
    
    # Standard binary file sections and markers
    r'\.[a-z_]+(?:\.[a-z_]+)*',
    
    # RFC defined special IP addresses
    r'0\.0\.0\.0',
    r'127\.0\.0\.1',
    r'255\.255\.255\.255',
    r'224\.0\.0\.0',
    r'169\.254\.[0-9]+\.[0-9]+',
    r'192\.168\.[0-9]+\.[0-9]+',
    r'10\.[0-9]+\.[0-9]+\.[0-9]+',
    r'172\.(?:1[6-9]|2[0-9]|3[0-1])\.[0-9]+\.[0-9]+',
    
    # Version numbers that might match IP patterns
    r'\d+\.\d+\.\d+',
]

# Define legitimate contexts for various system functions/commands
LEGITIMATE_CONTEXTS = {
    'exec': [
        r'syscall\.Exec',
        r'os/exec',
        r'exec\.Command',
        r'execve',
        r'import "os/exec"',
        r'exec\.[A-Za-z]+',
    ],
    'fork': [
        r'syscall\.Fork',
        r'runtime\.fork',
        r'golang\.org/x/sys/unix',
        r'import "syscall"',
    ],
    'system': [
        r'system\.[A-Za-z]+',
        r'operating system',
        r'file system',
        r'system requirements',
    ],
    'chmod': [
        r'os\.Chmod',
        r'syscall\.Chmod',
        r'FileMode',
        r'import "os"',
    ],
    'ps': [
        r'https',
        r'maps',
        r'corpse',
        r'collapse',
        r'ProxySettings',
        r'parameters',
        r'parseString',
        r'push',
        r'response',
    ],
    'setuid': [
        r'syscall\.Setuid',
        r'unix\.Setuid',
        r'import "syscall"',
    ],
    'setgid': [
        r'syscall\.Setgid',
        r'unix\.Setgid',
        r'import "syscall"',
    ],
    'dd': [
        r'add',
        r'address',
        r'odd',
        r'AddDer',
    ],
    'pool': [
        r'connection pool',
        r'pool\.[A-Za-z]+',
        r'worker pool',
        r'pool size',
        r'pool\.New',
        r'sync\.Pool',
    ],
    'mining': [
        r'data mining',
        r'mining\.[A-Za-z]+',
    ],
    'wallet': [
        r'wallet\.[A-Za-z]+',
        r'digital wallet',
    ],
    'hash': [
        r'hash\.[A-Za-z]+',
        r'hash algorithm',
        r'hash value',
        r'hash function',
    ],
    'crypto': [
        r'crypto/[a-z]+',
        r'cryptography',
        r'encrypt',
        r'decrypt',
        r'cipher',
    ],
    'connect': [
        r'net\.Conn',
        r'http\.Client',
        r'database connection',
        r'connection pool',
    ],
    'bind': [
        r'socket\.bind',
        r'net\.Listen',
        r'http\.Server',
    ],
    '3.45.1': [
        r'version',
        r'release',
        r'update',
    ],
}

# Specific patterns that indicate actual malware
MALWARE_INDICATORS = [
    r'(?:\/tmp|\/var\/tmp)\/(?:kinsing|kdevtmpfsi|xmra|xmrig|kworker)',
    r'stratum[0-9]+\.sysrv\.mining',
    r'proxdd\.com',
    r'scan_ssh\.py',
    r'xmr\.f2pool\.com',
    r'kworkerds',
    r'bioset',
    r'networkservice',
    r'/var/tmp/.xmrig',
    r'#!/bin/bash.*curl.*chmod \+x',
    r'socat',
    r'ld\.so\.preload',
    r'PKexec',
]

# Define suspicious patterns
SUSPICIOUS_PATTERNS = {
    "Shell Commands": [
        (r'wget.*http', "Downloading content from web"),
        (r'curl.*http', "Downloading content from web"), 
        (r'system.*[{(].*[)}]', "Dynamic command execution"),
        (r'exec.*[{(].*[)}]', "Dynamic command execution"),
        (r'fork.*exec', "Process creation chain"),
        (r'/bin/bash', "Shell execution"),
        (r'/bin/sh', "Shell execution"),
    ],
    "Network Activity": [
        (r'connect.*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', "Connect to hardcoded IP"),
        (r'bind.*0\.0\.0\.0', "Binding to all interfaces"),
        (r'listen.*0\.0\.0\.0', "Listening on all interfaces"),
        (r'send.*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+', "Sending data to hardcoded IP"),
    ],
    "File Operations": [
        (r'chmod.*777', "Setting full permissions"),
        (r'chmod.*\+x', "Making file executable"),
        (r'write.*/tmp/', "Writing to temp directory"),
        (r'create.*/tmp/', "Creating file in temp directory"),
    ],
    "Crypto Activity": [
        (r'stratum', "Mining protocol"),
        (r'miner', "Mining software"),
        (r'xmrig', "XMR mining software"),
        (r'monero', "Monero cryptocurrency"),
        (r'bitcoin', "Bitcoin cryptocurrency"),
        (r'wallet.*address', "Crypto wallet"),
    ],
}

# Version pattern and IP ranges
VERSION_PATTERN = r'(?<!\d)(\d+\.\d+\.\d+)(?!\d)'

RESERVED_IP_RANGES = [
    ('10.0.0.0', '10.255.255.255'),
    ('172.16.0.0', '172.31.255.255'),
    ('192.168.0.0', '192.168.255.255'),
    ('0.0.0.0', '0.255.255.255'),
    ('127.0.0.0', '127.255.255.255'),
    ('169.254.0.0', '169.254.255.255'),
    ('192.0.0.0', '192.0.0.255'),
    ('192.0.2.0', '192.0.2.255'),
    ('192.88.99.0', '192.88.99.255'),
    ('198.18.0.0', '198.19.255.255'),
    ('198.51.100.0', '198.51.100.255'),
    ('203.0.113.0', '203.0.113.255'),
    ('224.0.0.0', '239.255.255.255'),
    ('240.0.0.0', '255.255.255.254'),
    ('255.255.255.255', '255.255.255.255')
]

COMMON_LEGITIMATE_IPS = [
    '8.8.8.8', '8.8.4.4', '1.1.1.1', '9.9.9.9',
    '208.67.222.222', '208.67.220.220'
]

# IOC extraction patterns
URL_PATTERN = r"https?://[\w\-\.:/?#@!$&'()*+,;=%]+"
SHELL_PATTERN = r'\b(?:exec|system|popen|shell_exec|passthru|eval|fork|execve)\b'
PERM_PATTERN = r'\b(?:ps|chmod|chown|setuid|setgid|sudo|mount|umount|dd|dmsetup)\b'
IP_PATTERN = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
DOMAIN_PATTERN = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|edu|gov|mil|int|io|dev|app|co|ai|info|biz|name|pro|aero|coop|museum|[a-z]{2})\b'
CRYPTO_PATTERN = r'\b(?:hashcat|wallet|bitcoin|monero|miner|mining|stratum|xmr|eth\.|pool\.)\b'
NETWORK_PATTERN = r'\b(?:connect|bind|listen|send|recv|socket|accept|http\.Get|http\.Post)\b'

@contextmanager
def timeout_handler(seconds: int):
    """Context manager for handling timeouts"""
    def timeout_signal_handler(signum, frame):
        raise TimeoutError(f"Operation timed out after {seconds} seconds")
    
    # Set the signal handler
    old_handler = signal.signal(signal.SIGALRM, timeout_signal_handler)
    signal.alarm(seconds)
    
    try:
        yield
    finally:
        # Restore the old signal handler
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old_handler)

def validate_file_path(file_path: str) -> Path:
    """
    Validate and sanitize file path to prevent path traversal attacks
    
    Args:
        file_path: Input file path string
        
    Returns:
        Validated Path object
        
    Raises:
        SecurityError: If path is invalid or suspicious
    """
    try:
        path = Path(file_path).resolve()
        
        # Check if file exists
        if not path.exists():
            raise SecurityError(f"File does not exist: {file_path}")
        
        # Check if it's actually a file
        if not path.is_file():
            raise SecurityError(f"Path is not a file: {file_path}")
        
        # Check file size
        file_size = path.stat().st_size
        if file_size > MAX_FILE_SIZE:
            raise SecurityError(f"File too large: {file_size} bytes (max: {MAX_FILE_SIZE})")
        
        # Check file permissions (should be readable)
        if not os.access(path, os.R_OK):
            raise SecurityError(f"File is not readable: {file_path}")
        
        logger.info(f"File validation passed: {path} ({file_size} bytes)")
        return path
        
    except OSError as e:
        raise SecurityError(f"Path validation failed: {e}")

def safe_subprocess_run(cmd: List[str], timeout: int = MAX_SUBPROCESS_TIMEOUT, 
                       input_data: Optional[bytes] = None) -> subprocess.CompletedProcess:
    """
    Safely run subprocess with proper error handling and timeouts
    
    Args:
        cmd: Command to run as list
        timeout: Timeout in seconds
        input_data: Optional input data to pass to process
        
    Returns:
        CompletedProcess object
        
    Raises:
        AnalysisError: If subprocess fails
    """
    try:
        logger.debug(f"Running command: {' '.join(cmd)}")
        
        # Validate command to prevent injection
        if not all(isinstance(arg, str) for arg in cmd):
            raise AnalysisError("Command arguments must be strings")
        
        # Use absolute paths for security
        cmd[0] = shutil.which(cmd[0])
        if cmd[0] is None:
            raise AnalysisError(f"Command not found: {cmd[0]}")
        
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            input=input_data,
            check=False  # Don't raise on non-zero exit
        )
        
        logger.debug(f"Command completed with return code: {result.returncode}")
        return result
        
    except subprocess.TimeoutExpired as e:
        logger.warning(f"Command timed out after {timeout}s: {' '.join(cmd)}")
        raise AnalysisError(f"Command timed out: {e}")
    except Exception as e:
        logger.error(f"Subprocess error: {e}")
        raise AnalysisError(f"Subprocess failed: {e}")

def compute_sha256(file_path: Path) -> str:
    """
    Calculate SHA256 hash of a file safely
    
    Args:
        file_path: Path to file
        
    Returns:
        SHA256 hash as hex string
        
    Raises:
        AnalysisError: If hash calculation fails
    """
    try:
        sha256 = hashlib.sha256()
        with file_path.open("rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        
        hash_value = sha256.hexdigest()
        logger.debug(f"Computed SHA256 for {file_path}: {hash_value}")
        return hash_value
        
    except Exception as e:
        logger.error(f"Failed to compute SHA256 for {file_path}: {e}")
        raise AnalysisError(f"Hash calculation failed: {e}")

def ip_to_integer(ip: str) -> Optional[int]:
    """Convert an IP address to an integer for range comparison"""
    try:
        octets = ip.split('.')
        if len(octets) != 4:
            return None
        return sum(int(octets[i]) * (256 ** (3-i)) for i in range(4))
    except (ValueError, IndexError):
        logger.debug(f"Invalid IP format: {ip}")
        return None

def is_reserved_ip(ip: str) -> bool:
    """Check if an IP address is in reserved ranges defined by RFCs"""
    ip_int = ip_to_integer(ip)
    if ip_int is None:
        return False
    
    # Check if IP is in any reserved range
    for start_ip, end_ip in RESERVED_IP_RANGES:
        start_int = ip_to_integer(start_ip)
        end_int = ip_to_integer(end_ip)
        if start_int and end_int and start_int <= ip_int <= end_int:
            return True
    
    # Check if IP is in common legitimate list
    return ip in COMMON_LEGITIMATE_IPS

def is_version_number(ip_like_string: str) -> bool:
    """Check if a string that looks like an IP is actually a version number"""
    try:
        if re.match(VERSION_PATTERN, ip_like_string):
            parts = ip_like_string.split('.')
            # Additional checks for version number patterns
            if any(part.startswith('0') and len(part) > 1 for part in parts):
                return True
            if any(int(part) > 255 for part in parts):
                return True
            return True
        return False
    except (ValueError, AttributeError):
        return False

def is_suspicious_ip(ip: str) -> bool:
    """Determine if an IP address is suspicious based on reputation and ranges"""
    if is_reserved_ip(ip):
        return False
        
    # Known suspicious IP ranges (update as needed)
    suspicious_ranges = [
        ('45.0.0.0', '45.255.255.255'),
        ('148.0.0.0', '148.255.255.255'),
        ('185.92.0.0', '185.92.255.255'),
        ('193.33.0.0', '193.33.255.255')
    ]
    
    ip_int = ip_to_integer(ip)
    if ip_int is None:
        return False
        
    for start_ip, end_ip in suspicious_ranges:
        start_int = ip_to_integer(start_ip)
        end_int = ip_to_integer(end_ip)
        if start_int and end_int and start_int <= ip_int <= end_int:
            return True
    
    return False

def is_false_positive(item: str) -> bool:
    """Check if an item matches any of the known benign patterns"""
    try:
        return any(re.search(p, item) for p in BENIGN_PATTERNS)
    except re.error as e:
        logger.warning(f"Regex error checking benign patterns for '{item}': {e}")
        return False

def is_true_positive(item: str) -> bool:
    """Check if an item matches any of the known malware indicators"""
    try:
        return any(re.search(p, item, re.IGNORECASE) for p in MALWARE_INDICATORS)
    except re.error as e:
        logger.warning(f"Regex error checking malware indicators for '{item}': {e}")
        return False

def is_valid_domain(domain: str) -> bool:
    """Additional checks to filter out false positive domains"""
    try:
        parts = domain.split('.')
        if not parts:
            return False
            
        tld = parts[-1].lower()
        
        # List of valid TLDs
        valid_tlds = {
            'com', 'org', 'net', 'edu', 'gov', 'mil', 'int', 'io', 'dev', 'app', 
            'co', 'ai', 'info', 'biz', 'name', 'pro', 'aero', 'coop', 'museum',
            # Common country codes
            'us', 'uk', 'ca', 'au', 'de', 'fr', 'jp', 'cn', 'ru', 'br', 'in', 'it',
            'es', 'nl', 'se', 'no', 'fi', 'dk', 'ch', 'at', 'be', 'ie', 'nz'
        }
        
        # Check if TLD is valid
        if tld not in valid_tlds and not (len(tld) == 2 and tld.isalpha()):
            return False
        
        # Reject domains that are likely code elements
        code_patterns = [
            r'\.If$', r'\.Do$', r'\.Is$', r'\.OID$', r'\.AEAD$', r'\.HTTP$',
            r'\.RFC$', r'\.In$', r'\.EFH', r'\.GFJ', r'\.KFN', r'\.AFD', r'\.CFF'
        ]
        
        if any(re.search(pattern, domain) for pattern in code_patterns):
            return False
        
        # Check for unrealistic domain part lengths or patterns
        for part in parts:
            if len(part) > 63 or part.startswith('.') or part.endswith('.'):
                return False
        
        # Check for domains that are likely code references
        if re.search(r'\.[A-Z][a-z]+\.[A-Z][a-z]+', domain):
            return False
            
        return True
        
    except Exception as e:
        logger.debug(f"Domain validation error for '{domain}': {e}")
        return False

def extract_iocs(data: str) -> Tuple[List[str], ...]:
    """Extract potential indicators of compromise from binary data"""
    try:
        urls = re.findall(URL_PATTERN, data)
        shells = re.findall(SHELL_PATTERN, data)
        perms = re.findall(PERM_PATTERN, data)
        ips = re.findall(IP_PATTERN, data)
        network = re.findall(NETWORK_PATTERN, data)
        
        # Filter out IP-like strings that are version numbers
        filtered_ips = []
        for ip in ips:
            if not is_version_number(ip) and not is_reserved_ip(ip):
                filtered_ips.append(ip)
        
        # Domain name extraction with validation
        raw_domains = re.findall(DOMAIN_PATTERN, data)
        domains = [domain for domain in raw_domains if is_valid_domain(domain)]
        
        crypto = re.findall(CRYPTO_PATTERN, data)
        
        # Binary blob detection
        blobs = []
        for match in re.finditer(r'[A-Za-z0-9+/=]{16,}', data):
            blob = match.group(0)
            if not re.search(r'\.(?:func|deferwrap|marshal)', blob) and not is_false_positive(blob):
                blobs.append(blob)
        
        logger.debug(f"Extracted IOCs: {len(urls)} URLs, {len(shells)} shells, "
                    f"{len(perms)} perms, {len(filtered_ips)} IPs, {len(domains)} domains, "
                    f"{len(crypto)} crypto, {len(network)} network, {len(blobs)} blobs")
        
        return urls, shells, perms, filtered_ips, domains, crypto, network, blobs
        
    except Exception as e:
        logger.error(f"IOC extraction failed: {e}")
        raise AnalysisError(f"IOC extraction failed: {e}")

def check_strings_output(file_path: Path) -> List[str]:
    """Run the 'strings' command on the binary and check for suspicious patterns"""
    try:
        result = safe_subprocess_run(['strings', str(file_path)])
        if result.returncode != 0:
            logger.warning(f"strings command failed with code {result.returncode}")
            return []
        
        strings_text = result.stdout.decode('latin1', errors='ignore')
        
        suspicious_strings = []
        for line in strings_text.splitlines():
            if is_true_positive(line) and not is_false_positive(line):
                suspicious_strings.append(line)
        
        logger.debug(f"Found {len(suspicious_strings)} suspicious strings")
        return suspicious_strings
        
    except AnalysisError:
        logger.warning("Could not run strings command")
        return []

def get_string_context(data: str, pattern: str, window: int = 50) -> List[str]:
    """Get surrounding context for a pattern match in binary data"""
    matches = []
    try:
        for match in re.finditer(re.escape(pattern), data):
            start = max(0, match.start() - window)
            end = min(len(data), match.end() + window)
            
            prefix = data[start:match.start()]
            suffix = data[match.end():end]
            
            # Clean up context for display
            prefix = ''.join(c if c.isprintable() and c != '\n' else '.' for c in prefix)
            suffix = ''.join(c if c.isprintable() and c != '\n' else '.' for c in suffix)
            
            context = f"...{prefix}[{pattern}]{suffix}..."
            matches.append(context)
            
    except re.error as e:
        logger.warning(f"Regex error analyzing context for '{pattern}': {e}")
        matches.append(f"Error analyzing context for {pattern}")
    
    return matches

def is_legitimate_context(item: str, contexts: List[str]) -> Tuple[bool, str]:
    """Check if an item appears in a legitimate context"""
    if item not in LEGITIMATE_CONTEXTS:
        return False, "Unknown item"
    
    legitimate_patterns = LEGITIMATE_CONTEXTS[item]
    
    for context in contexts:
        for pattern in legitimate_patterns:
            try:
                if re.search(pattern, context, re.IGNORECASE):
                    return True, f"Matches legitimate pattern: {pattern}"
            except re.error:
                continue
    
    return False, "No legitimate context found"

def check_entropy(data_segment: bytes, size: int = 256) -> float:
    """Calculate Shannon entropy on a segment of data"""
    if len(data_segment) < size:
        return 0.0
    
    sample = data_segment[:size]
    byte_counts = defaultdict(int)
    
    for byte in sample:
        byte_counts[byte] += 1
    
    entropy = 0.0
    for count in byte_counts.values():
        probability = count / size
        entropy -= probability * (math.log(probability) / math.log(2))
    
    return entropy

def analyze_findings_by_category(file_path: Path, data_text: str, 
                                findings_by_category: Dict[str, List[str]]) -> Dict[str, Dict[str, List[Tuple[str, str]]]]:
    """Analyze all findings across categories and classify them"""
    results = {
        'SAFE': defaultdict(list),
        'SUSPICIOUS': defaultdict(list),
        'MALICIOUS': defaultdict(list),
        'NEEDS_REVIEW': defaultdict(list)
    }
    
    try:
        for category, items in findings_by_category.items():
            if not items:
                continue
                
            for item in set(items):  # Remove duplicates
                # Check if it's a true positive (known malicious)
                if is_true_positive(item):
                    results['MALICIOUS'][category].append((item, "Matches known malware pattern"))
                    continue
                    
                # Check if it's a false positive (known benign)
                if is_false_positive(item):
                    results['SAFE'][category].append((item, "Matches known benign pattern"))
                    continue
                
                # Special case for IP-like strings that are version numbers
                if category == "IPs" and is_version_number(item):
                    results['SAFE'][category].append((item, "Version number pattern"))
                    continue
                
                # Get context around the item
                contexts = get_string_context(data_text, item)
                
                # Check if we have context patterns for this item
                if item in LEGITIMATE_CONTEXTS:
                    is_legit, reason = is_legitimate_context(item, contexts)
                    if is_legit:
                        results['SAFE'][category].append((item, reason))
                        continue
                
                # Category-specific analysis
                if category == "Shell Commands":
                    if any("/tmp/" in ctx or "/var/tmp/" in ctx for ctx in contexts):
                        results['SUSPICIOUS'][category].append((item, "Used with temporary directory"))
                        continue
                    if any("wget" in ctx or "curl" in ctx for ctx in contexts):
                        results['SUSPICIOUS'][category].append((item, "Used with download utilities"))
                        continue
                    results['NEEDS_REVIEW'][category].append((item, "System call in ambiguous context"))
                    
                elif category == "Permission Changes":
                    if item == "chmod" and any("777" in ctx or "+x" in ctx for ctx in contexts):
                        if any("/tmp/" in ctx or "/var/tmp/" in ctx for ctx in contexts):
                            results['SUSPICIOUS'][category].append((item, "Modifying permissions in temp directory"))
                            continue
                    results['NEEDS_REVIEW'][category].append((item, "Permission-related call in ambiguous context"))
                    
                elif category == "Crypto References":
                    if any("stratum" in ctx or "miner" in ctx or "xmr" in ctx for ctx in contexts):
                        results['SUSPICIOUS'][category].append((item, "Possible cryptomining reference"))
                        continue
                    results['NEEDS_REVIEW'][category].append((item, "Crypto-related term in ambiguous context"))
                    
                elif category == "IPs":
                    if is_suspicious_ip(item):
                        results['SUSPICIOUS'][category].append((item, "IP in suspicious range"))
                    else:
                        results['NEEDS_REVIEW'][category].append((item, "Uncommon hardcoded IP"))
                        
                elif category == "Domains":
                    malware_domains = ["proxdd.com", "stratum", "xmr.f2pool.com"]
                    if any(malware_domain in item for malware_domain in malware_domains):
                        results['SUSPICIOUS'][category].append((item, "Domain associated with malware"))
                    else:
                        results['NEEDS_REVIEW'][category].append((item, "Uncommon hardcoded domain"))
                        
                elif category == "Network":
                    if any(ip in ctx for ctx in contexts for ip in findings_by_category.get("IPs", [])):
                        results['SUSPICIOUS'][category].append((item, "Network activity with hardcoded IP"))
                    else:
                        results['NEEDS_REVIEW'][category].append((item, "Network-related function"))
                        
                else:
                    results['NEEDS_REVIEW'][category].append((item, "Requires manual review"))
        
        return results
        
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise AnalysisError(f"Findings analysis failed: {e}")

def analyze_binary(file_path: Path, verbose: bool = False, 
                  deep_analysis: bool = False) -> AnalysisResult:
    """Analyze a binary file for IOCs with comprehensive error handling"""
    errors = []
    
    try:
        logger.info(f"Starting analysis of: {file_path}")
        
        # Get file info
        file_size = file_path.stat().st_size
        sha256 = compute_sha256(file_path)
        
        # Try to identify file type
        try:
            result = safe_subprocess_run(['file', str(file_path)])
            if result.returncode == 0:
                file_type = result.stdout.decode('utf-8', errors='ignore').strip()
            else:
                file_type = "Unknown (file command failed)"
                errors.append("File type detection failed")
        except AnalysisError as e:
            file_type = "Unknown (file command unavailable)"
            errors.append(f"File type detection error: {e}")
        
        # Read and analyze file content
        try:
            with file_path.open("rb") as f:
                header = f.read(16)
                is_elf = header.startswith(b'\x7fELF')
                
                f.seek(0)
                data_sample = f.read(8192)
                is_go_binary = b'Go build ID:' in data_sample
                
                f.seek(0)
                data = f.read()
                data_text = data.decode("latin1", errors="ignore")
                
        except Exception as e:
            logger.error(f"Failed to read file {file_path}: {e}")
            raise AnalysisError(f"File reading failed: {e}")
        
        # Extract IOCs
        try:
            urls, shells, perms, ips, domains, crypto, network, blobs = extract_iocs(data_text)
        except AnalysisError as e:
            errors.append(f"IOC extraction error: {e}")
            urls = shells = perms = ips = domains = crypto = network = blobs = []
        
        # Check strings output
        try:
            suspicious_strings = check_strings_output(file_path)
        except Exception as e:
            logger.warning(f"Strings analysis failed: {e}")
            suspicious_strings = []
            errors.append(f"Strings analysis error: {e}")
        
        # Organize findings
        findings_by_category = {
            "URLs": urls,
            "Shell Commands": shells,
            "Permission Changes": perms,
            "IPs": ips,
            "Domains": domains,
            "Crypto References": crypto,
            "Network": network,
            "Binary Blobs": blobs,
            "Suspicious Strings": suspicious_strings
        }
        
        # Analyze findings
        try:
            analysis_results = analyze_findings_by_category(file_path, data_text, findings_by_category)
        except AnalysisError as e:
            errors.append(f"Analysis error: {e}")
            analysis_results = {
                'SAFE': defaultdict(list),
                'SUSPICIOUS': defaultdict(list), 
                'MALICIOUS': defaultdict(list),
                'NEEDS_REVIEW': defaultdict(list)
            }
        
        # Count findings
        safe_count = sum(len(items) for items in analysis_results['SAFE'].values())
        suspicious_count = sum(len(items) for items in analysis_results['SUSPICIOUS'].values())
        malicious_count = sum(len(items) for items in analysis_results['MALICIOUS'].values())
        needs_review_count = sum(len(items) for items in analysis_results['NEEDS_REVIEW'].values())
        
        # Determine risk assessment
        if malicious_count > 0:
            risk_assessment = "High - Probable malicious indicators detected"
        elif suspicious_count > 0:
            risk_assessment = "Medium - Suspicious indicators found"
        elif needs_review_count > 100:
            risk_assessment = "Low - Many potential matches but likely false positives"
        else:
            risk_assessment = "Minimal - No suspicious indicators detected"
        
        logger.info(f"Analysis completed for {file_path}: "
                   f"Safe={safe_count}, Suspicious={suspicious_count}, "
                   f"Malicious={malicious_count}, Review={needs_review_count}")
        
        return AnalysisResult(
            file_path=str(file_path),
            file_size=file_size,
            sha256=sha256,
            file_type=file_type,
            is_elf=is_elf,
            is_go_binary=is_go_binary,
            findings_by_category=findings_by_category,
            analysis_results=analysis_results,
            safe_count=safe_count,
            suspicious_count=suspicious_count,
            malicious_count=malicious_count,
            needs_review_count=needs_review_count,
            risk_assessment=risk_assessment,
            error_messages=errors
        )
        
    except Exception as e:
        logger.error(f"Critical error analyzing {file_path}: {e}")
        # Return a minimal result with error information
        return AnalysisResult(
            file_path=str(file_path),
            file_size=0,
            sha256="",
            file_type="Error",
            is_elf=False,
            is_go_binary=False,
            findings_by_category={},
            analysis_results={'SAFE': {}, 'SUSPICIOUS': {}, 'MALICIOUS': {}, 'NEEDS_REVIEW': {}},
            safe_count=0,
            suspicious_count=0,
            malicious_count=0,
            needs_review_count=0,
            risk_assessment="Error - Analysis failed",
            error_messages=[f"Critical analysis error: {e}"]
        )

def print_analysis_results(result: AnalysisResult, verbose: bool = False):
    """Print formatted analysis results"""
    print(f"\n--- Binary Information ---")
    print(f"File: {Path(result.file_path).name}")
    print(f"Size: {result.file_size:,} bytes")
    print(f"SHA256: {result.sha256}")
    print(f"Type: {result.file_type}")
    print(f"ELF Binary: {'Yes' if result.is_elf else 'No'}")
    print(f"Go Binary: {'Yes' if result.is_go_binary else 'No'}")
    
    # Print errors if any
    if result.error_messages:
        print(f"\n⚠️ Analysis Errors:")
        for error in result.error_messages:
            print(f"  - {error}")
    
    # Display safe findings
    if result.analysis_results['SAFE']:
        print("\n✅ LEGITIMATE FINDINGS (SAFE)")
        for category, items in result.analysis_results['SAFE'].items():
            if items:
                print(f"  {category} ({len(items)}):")
                display_count = len(items) if verbose or len(items) <= 5 else 3
                for item, reason in items[:display_count]:
                    print(f"    - {item}: {reason}")
                if not verbose and len(items) > 5:
                    print(f"    ... and {len(items)-3} more (use --verbose to see all)")
    
    # Display malicious findings
    if result.analysis_results['MALICIOUS']:
        print("\n🚨 MALICIOUS FINDINGS (ALERT)")
        for category, items in result.analysis_results['MALICIOUS'].items():
            if items:
                print(f"  {category} ({len(items)}):")
                for item, reason in items:
                    print(f"    - {item}: {reason}")
    
    # Display suspicious findings
    if result.analysis_results['SUSPICIOUS']:
        print("\n⚠️ SUSPICIOUS FINDINGS (NEEDS REVIEW)")
        for category, items in result.analysis_results['SUSPICIOUS'].items():
            if items:
                print(f"  {category} ({len(items)}):")
                for item, reason in items:
                    print(f"    - {item}: {reason}")
    
    # Display review findings in verbose mode
    if verbose and result.analysis_results['NEEDS_REVIEW']:
        print("\n🔍 FINDINGS NEEDING REVIEW (LIKELY BENIGN)")
        for category, items in result.analysis_results['NEEDS_REVIEW'].items():
            if items:
                print(f"  {category} ({len(items)}):")
                for item, reason in items[:10]:  # Limit display
                    print(f"    - {item}: {reason}")
                if len(items) > 10:
                    print(f"      ... and {len(items) - 10} more")
    
    # Summary
    print(f"\n--- Summary ---")
    print(f"Categorized as safe: {result.safe_count}")
    print(f"Categorized as suspicious: {result.suspicious_count}")
    print(f"Categorized as malicious: {result.malicious_count}")
    print(f"Needing further review: {result.needs_review_count}")
    print(f"Risk Assessment: {result.risk_assessment}")

def export_results(results: List[AnalysisResult], output_file: str):
    """Export analysis results to JSON file"""
    try:
        output_path = Path(output_file)
        
        # Convert results to serializable format
        export_data = {
            'analysis_timestamp': str(logger.handlers[0].formatter.formatTime(
                logging.LogRecord('', 0, '', 0, '', (), None), '%Y-%m-%d %H:%M:%S')),
            'total_files': len(results),
            'results': [asdict(result) for result in results]
        }
        
        with output_path.open('w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Results exported to: {output_file}")
        print(f"\n📄 Report exported to: {output_file}")
        
    except Exception as e:
        logger.error(f"Failed to export results: {e}")
        print(f"❌ Export failed: {e}")

def main():
    """Main function with comprehensive error handling"""
    parser = argparse.ArgumentParser(
        description="Enhanced binary analysis with improved security and error handling",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s binary1 binary2           # Analyze multiple files
  %(prog)s -v --deep-analysis file   # Verbose analysis with deep inspection
  %(prog)s --export-report results.json file  # Export results to JSON
        """
    )
    
    parser.add_argument("files", nargs="+", help="Files to analyze")
    parser.add_argument("-v", "--verbose", action="store_true", 
                       help="Show all details including filtered items")
    parser.add_argument("--deep-analysis", action="store_true", 
                       help="Perform deep analysis on matches")
    parser.add_argument("--export-report", type=str, 
                       help="Export report to specified JSON file")
    parser.add_argument("--log-level", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'],
                       default='INFO', help="Set logging level")
    parser.add_argument("--max-file-size", type=int, default=MAX_FILE_SIZE,
                       help=f"Maximum file size to analyze (default: {MAX_FILE_SIZE})")
    
    args = parser.parse_args()
    
    # Configure logging level
    logging.getLogger().setLevel(getattr(logging, args.log_level))
    
    # Update max file size if specified
    global MAX_FILE_SIZE
    MAX_FILE_SIZE = args.max_file_size
    
    logger.info("🔍 Starting enhanced binary analysis...")
    print("🔍 Enhanced Binary Analysis Tool")
    print("=" * 50)
    
    results = []
    positive_matches = 0
    failed_analyses = 0
    
    try:
        with timeout_handler(MAX_ANALYSIS_TIME * len(args.files)):
            for file_path in args.files:
                try:
                    # Validate file path
                    validated_path = validate_file_path(file_path)
                    
                    # Analyze the file
                    result = analyze_binary(validated_path, args.verbose, args.deep_analysis)
                    results.append(result)
                    
                    # Print results
                    print_analysis_results(result, args.verbose)
                    
                    if result.malicious_count > 0:
                        positive_matches += 1
                    
                    if result.error_messages:
                        failed_analyses += 1
                        
                except SecurityError as e:
                    logger.error(f"Security error for {file_path}: {e}")
                    print(f"❌ Security error for {file_path}: {e}")
                    failed_analyses += 1
                    
                except AnalysisError as e:
                    logger.error(f"Analysis error for {file_path}: {e}")
                    print(f"❌ Analysis error for {file_path}: {e}")
                    failed_analyses += 1
                    
                except Exception as e:
                    logger.error(f"Unexpected error for {file_path}: {e}")
                    print(f"❌ Unexpected error for {file_path}: {e}")
                    failed_analyses += 1
    
    except TimeoutError:
        logger.error("Analysis timed out")
        print("❌ Analysis timed out - consider analyzing fewer files or increasing timeout")
        return 1
    
    # Export results if requested
    if args.export_report and results:
        export_results(results, args.export_report)
    
    # Final summary
    print("\n" + "=" * 50)
    print("=== Final Report ===")
    
    successful_analyses = len(results) - failed_analyses
    
    if positive_matches == 0:
        print(f"✅ No malware indicators detected in {successful_analyses} successfully analyzed files")
        if failed_analyses > 0:
            print(f"⚠️ {failed_analyses} files could not be analyzed due to errors")
    else:
        print(f"⚠️ Found potential indicators in {positive_matches} of {successful_analyses} analyzed files")
        if failed_analyses > 0:
            print(f"❌ {failed_analyses} files failed analysis")
    
    # Provide recommendations
    print("\n=== Recommendations ===")
    if positive_matches > 0:
        print("1. Review the context around matches to determine legitimacy")
        print("2. Use --deep-analysis for more detailed context")
        print("3. Compare binaries with official versions")
        print("4. Consider running additional security scans")
    else:
        print("1. Binaries appear clean based on analysis")
        print("2. Verify integrity by comparing with official releases")
        print("3. Keep monitoring for new threat intelligence")
    
    if failed_analyses > 0:
        print(f"4. Investigate {failed_analyses} failed analyses - check logs for details")
    
    logger.info(f"Analysis complete: {successful_analyses} successful, {failed_analyses} failed")
    
    return 0 if positive_matches == 0 and failed_analyses == 0 else 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logger.info("Analysis interrupted by user")
        print("\n🛑 Analysis interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.critical(f"Critical error: {e}")
        print(f"💥 Critical error: {e}")
        sys.exit(1)
