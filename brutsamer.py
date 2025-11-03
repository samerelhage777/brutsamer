#!/usr/bin/env python3

import argparse
import sys
import os
import copy
import requests
import time
import logging
import json
import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, unquote, parse_qs, urlencode
from typing import Dict, List, Callable, Optional, Tuple, Any
import urllib3
from difflib import SequenceMatcher
import signal
import random
from datetime import datetime

# Disable SSL warnings and verify
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Color codes for output
class colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    END = '\033[0m'
    BOLD = '\033[1m'

# Shortcuts
good = f"{colors.GREEN}[+]{colors.END}"
bad = f"{colors.RED}[-]{colors.END}"
info = f"{colors.BLUE}[*]{colors.END}"
green = colors.GREEN
red = colors.RED
blue = colors.BLUE
yellow = colors.YELLOW
end = colors.END

# Global variables for progress tracking and result saving
scan_results = []
scan_start_time = 0
total_requests = 0
completed_requests = 0
is_scanning = False
lock = threading.Lock()
reflected_payloads = []  # Store reflected payloads in real-time

# Payload file mappings
PAYLOAD_FILES = {
    'xss': 'payloads/xss_payloads.txt',
    'sqli': 'payloads/sqli_payloads.txt',
    'command': 'payloads/command_injection_payloads.txt',
    'path_traversal': 'payloads/path_traversal_payloads.txt',
    'ssrf': 'payloads/ssrf_payloads.txt',
    'xxe': 'payloads/xxe_payloads.txt',
    'ssti': 'payloads/ssti_payloads.txt',
    'ldap': 'payloads/ldap_payloads.txt',
    'basic': 'payloads/basic_fuzz_payloads.txt',
    'quick': 'payloads/quick_test.txt'
}

# Vulnerability remediation guidance
REMEDIATION_GUIDE = {
    'xss': {
        'title': 'Cross-Site Scripting (XSS)',
        'description': 'XSS allows attackers to inject malicious scripts into web pages viewed by other users.',
        'remediation': [
            'Implement proper output encoding/escaping',
            'Use Content Security Policy (CSP) headers',
            'Validate and sanitize all user input',
            'Use HTTPOnly flag for cookies',
            'Implement X-XSS-Protection headers'
        ],
        'severity': 'High',
        'impact': 'Session hijacking, credential theft, defacement'
    },
    'sqli': {
        'title': 'SQL Injection',
        'description': 'SQL injection allows attackers to execute arbitrary SQL commands on the database.',
        'remediation': [
            'Use parameterized queries/prepared statements',
            'Implement proper input validation',
            'Use ORM frameworks with built-in protection',
            'Apply principle of least privilege to database accounts',
            'Regularly update and patch database systems'
        ],
        'severity': 'Critical',
        'impact': 'Data breach, data manipulation, full system compromise'
    },
    'command': {
        'title': 'Command Injection',
        'description': 'Command injection allows attackers to execute arbitrary system commands on the server.',
        'remediation': [
            'Avoid using user input in system commands',
            'Use safe APIs that don\'t invoke command interpreters',
            'Implement strict input validation with whitelisting',
            'Run applications with minimal privileges',
            'Use parameterized command execution libraries'
        ],
        'severity': 'Critical',
        'impact': 'Full server compromise, data theft, system manipulation'
    },
    'path_traversal': {
        'title': 'Path Traversal',
        'description': 'Path traversal allows attackers to access files and directories outside the web root.',
        'remediation': [
            'Validate user input against whitelisted values',
            'Use chroot jails or containerization',
            'Implement proper access controls',
            'Sanitize file paths and normalize them',
            'Run web server with minimal file system permissions'
        ],
        'severity': 'High',
        'impact': 'Sensitive file disclosure, system information leakage'
    },
    'ssrf': {
        'title': 'Server-Side Request Forgery (SSRF)',
        'description': 'SSRF allows attackers to make requests to internal resources from the server.',
        'remediation': [
            'Validate and sanitize all URL inputs',
            'Use whitelists for allowed domains and protocols',
            'Implement network segmentation',
            'Disable URL schemes like file://, gopher://, dict://',
            'Use authentication for internal services'
        ],
        'severity': 'High',
        'impact': 'Internal network scanning, service enumeration, data exfiltration'
    },
    'xxe': {
        'title': 'XML External Entity (XXE)',
        'description': 'XXE allows attackers to interfere with XML processing and access local files.',
        'remediation': [
            'Disable external entity processing in XML parsers',
            'Use JSON instead of XML where possible',
            'Implement input validation for XML data',
            'Use SAX parsers instead of DOM parsers',
            'Keep XML processors updated and patched'
        ],
        'severity': 'High',
        'impact': 'File disclosure, denial of service, internal port scanning'
    },
    'ssti': {
        'title': 'Server-Side Template Injection (SSTI)',
        'description': 'SSTI allows attackers to inject template code that executes on the server.',
        'remediation': [
            'Use logic-less templating engines',
            'Sandbox template execution environments',
            'Validate and sanitize all template inputs',
            'Avoid user input in template rendering',
            'Implement strict input validation'
        ],
        'severity': 'High',
        'impact': 'Remote code execution, data theft, server compromise'
    },
    'ldap': {
        'title': 'LDAP Injection',
        'description': 'LDAP injection allows attackers to modify LDAP queries and access unauthorized data.',
        'remediation': [
            'Use parameterized LDAP queries',
            'Escape special LDAP characters',
            'Implement proper input validation',
            'Use LDAP libraries with built-in protection',
            'Apply least privilege to LDAP service accounts'
        ],
        'severity': 'Medium',
        'impact': 'Unauthorized data access, authentication bypass'
    },
    'basic': {
        'title': 'Input Reflection Vulnerability',
        'description': 'User input is reflected in the response without proper sanitization, which can lead to various attacks.',
        'remediation': [
            'Implement comprehensive input validation',
            'Use output encoding/escaping',
            'Validate data on both client and server side',
            'Use security libraries for input sanitization',
            'Implement Content Security Policy (CSP)'
        ],
        'severity': 'Medium',
        'impact': 'Cross-site scripting, information disclosure, injection attacks'
    }
}

# Common parameters for different page types
COMMON_PARAMETERS = {
    'contact': ['name', 'email', 'subject', 'message', 'phone', 'company', 'comments', 'inquiry_type', 'topic'],
    'login': ['username', 'password', 'email', 'user', 'pass', 'login', 'submit', 'remember'],
    'search': ['q', 'query', 'search', 'keyword', 'term', 's'],
    'register': ['username', 'password', 'email', 'confirm_password', 'first_name', 'last_name', 'agree'],
    'comment': ['comment', 'message', 'text', 'content', 'author', 'email', 'website'],
    'subscribe': ['email', 'newsletter', 'subscribe', 'mail'],
    'generic': ['id', 'page', 'view', 'action', 'type', 'category', 'file', 'url', 'code']
}

# User Agents for rotation
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (X11; Linux i686; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0'
]

def get_random_user_agent():
    """Get a random user agent"""
    return random.choice(USER_AGENTS)

def load_payloads_from_file(file_path: str) -> List[str]:
    """Load payloads from a text file"""
    payloads = []
    try:
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):  # Skip empty lines and comments
                        payloads.append(line)
            print(f"{good} Loaded {len(payloads)} payloads from {file_path}")
        else:
            print(f"{bad} Payload file not found: {file_path}")
    except Exception as e:
        print(f"{bad} Error loading payloads from {file_path}: {e}")
    
    return payloads

def renew_tor_circuit():
    """Renew Tor circuit to get new IP address using stem library"""
    try:
        from stem import Signal
        from stem.control import Controller
        
        with Controller.from_port(port=9051) as controller:
            controller.authenticate()  # Empty password for default Tor
            controller.signal(Signal.NEWNYM)
            return True
    except ImportError:
        print(f"{bad} Stem library not installed. Install with: pip install stem")
        return False
    except Exception as e:
        print(f"{bad} Failed to renew Tor circuit: {e}")
        return False

def check_tor_connection(proxy_url: str = "socks5://127.0.0.1:9050") -> Tuple[bool, str]:
    """Check if Tor connection is working and return IP"""
    try:
        response = requests.get(
            'http://httpbin.org/ip',
            proxies={'http': proxy_url, 'https': proxy_url},
            timeout=30
        )
        if response.status_code == 200:
            ip_data = response.json()
            current_ip = ip_data.get('origin', 'Unknown')
            return True, current_ip
        return False, "Unknown"
    except Exception as e:
        return False, "Unknown"

def get_current_ip(proxy_url: str = None) -> str:
    """Get current public IP address"""
    try:
        proxies = {'http': proxy_url, 'https': proxy_url} if proxy_url else None
        response = requests.get('http://httpbin.org/ip', proxies=proxies, timeout=10)
        if response.status_code == 200:
            return response.json().get('origin', 'Unknown')
        return 'Unknown'
    except:
        return 'Unknown'

def get_suggested_params(url: str) -> List[str]:
    """Suggest parameters based on URL path"""
    path = urlparse(url).path.lower()
    
    if any(word in path for word in ['contact', 'support', 'help', 'feedback']):
        return COMMON_PARAMETERS['contact']
    elif any(word in path for word in ['login', 'signin', 'auth', 'sign-in']):
        return COMMON_PARAMETERS['login']
    elif any(word in path for word in ['search', 'find', 'query']):
        return COMMON_PARAMETERS['search']
    elif any(word in path for word in ['register', 'signup', 'create', 'sign-up']):
        return COMMON_PARAMETERS['register']
    elif any(word in path for word in ['comment', 'review', 'feedback']):
        return COMMON_PARAMETERS['comment']
    elif any(word in path for word in ['subscribe', 'newsletter', 'mailing']):
        return COMMON_PARAMETERS['subscribe']
    else:
        all_params = []
        for category in COMMON_PARAMETERS.values():
            all_params.extend(category)
        return list(set(all_params))[:8]

def get_vulnerability_type(payload: str) -> str:
    """Determine vulnerability type based on payload content"""
    payload_lower = payload.lower()
    
    if any(xss_indicator in payload_lower for xss_indicator in ['<script>', 'javascript:', 'onerror=', 'onload=', 'alert(']):
        return 'xss'
    elif any(sqli_indicator in payload_lower for sqli_indicator in ["' or '1'='1", "union select", "'--", "';", "1=1"]):
        return 'sqli'
    elif any(cmd_indicator in payload_lower for cmd_indicator in [';whoami', '|id', '&cat', '`id`', '$(whoami)']):
        return 'command'
    elif any(path_indicator in payload_lower for path_indicator in ['../', '..\\', '/etc/passwd', 'c:\\windows']):
        return 'path_traversal'
    elif any(ssrf_indicator in payload_lower for ssrf_indicator in ['http://localhost', '127.0.0.1', 'file://', 'gopher://']):
        return 'ssrf'
    elif any(xxe_indicator in payload_lower for xxe_indicator in ['<!entity', '<?xml', '&xxe;', 'documents']):
        return 'xxe'
    elif any(ssti_indicator in payload_lower for ssti_indicator in ['{{7*7}}', '${7*7}', '<%=', '*{', '#{']):
        return 'ssti'
    elif any(ldap_indicator in payload_lower for ldap_indicator in ['*)(&', 'cn=*', 'ou=*']):
        return 'ldap'
    else:
        return 'basic'

def get_remediation_guide(vuln_type: str) -> Dict:
    """Get remediation guidance for a vulnerability type"""
    return REMEDIATION_GUIDE.get(vuln_type, {
        'title': 'Unknown Vulnerability',
        'description': 'No specific remediation guidance available.',
        'remediation': ['Implement general input validation and output encoding'],
        'severity': 'Unknown',
        'impact': 'Unknown'
    })

def analyze_reflection_context(response_text: str, payload: str, encoded_payload: str) -> List[Dict]:
    """Analyze how the payload is reflected in the response and return detailed context"""
    contexts = []
    
    search_text = encoded_payload if encoded_payload != payload else payload
    start_idx = 0
    
    while True:
        idx = response_text.find(search_text, start_idx)
        if idx == -1:
            break
        
        context_start = max(0, idx - 50)
        context_end = min(len(response_text), idx + len(search_text) + 50)
        context = response_text[context_start:context_end].replace('\n', ' ').replace('\r', ' ')
        
        context_before = response_text[max(0, idx-20):idx]
        context_after = response_text[idx + len(search_text):idx + len(search_text) + 20]
        
        context_type = "unknown"
        
        # Detect reflection context
        if any(tag in context_before for tag in ['<script>', '<style>', '<div', '<span', '<p']):
            context_type = "HTML tag content"
        elif any(tag in context_before for tag in ['href="', 'src="', 'action="']):
            context_type = "HTML attribute"
        elif any(tag in context_before for tag in ['onload=', 'onerror=', 'onclick=']):
            context_type = "JavaScript event handler"
        elif '<script>' in context_before and '</script>' not in context_before:
            context_type = "JavaScript code"
        elif any(char in context_before for char in ['"', "'"]):
            context_type = "Quoted string"
        elif any(tag in context_before for tag in ['<?', '<%']):
            context_type = "Server-side code"
        elif any(tag in context_before for tag in ['<input', '<textarea', '<pre>']):
            context_type = "Form element"
        elif context_before.strip() == '' and context_after.strip() == '':
            context_type = "Direct output"
        else:
            # Try to detect more specific contexts
            if 'value="' in context_before or "value='" in context_before:
                context_type = "Input value"
            elif 'content="' in context_before:
                context_type = "Meta tag content"
            elif 'alt="' in context_before:
                context_type = "Image alt text"
        
        contexts.append({
            'position': idx,
            'context': context,
            'type': context_type,
            'before': context_before,
            'after': context_after,
            'reflected_payload': search_text
        })
        
        start_idx = idx + len(search_text)
    
    return contexts

def save_reflected_payloads(filename: str = "reflected-payloads.txt"):
    """Save reflected payloads to a separate file in real-time"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("REFLECTED PAYLOADS - LIVE RESULTS\n")
            f.write("=" * 60 + "\n")
            f.write(f"Last Updated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Target URL: {getattr(save_reflected_payloads, 'target_url', 'N/A')}\n")
            f.write(f"Scan Type: {getattr(save_reflected_payloads, 'scan_type', 'N/A')}\n")
            f.write(f"Total Found: {len(reflected_payloads)}\n\n")
            
            if reflected_payloads:
                f.write("REFLECTED PAYLOADS WITH REMEDIATION:\n")
                f.write("=" * 60 + "\n")
                
                # Group by parameter
                results_by_param = {}
                for result in reflected_payloads:
                    param = result['parameter']
                    if param not in results_by_param:
                        results_by_param[param] = []
                    results_by_param[param].append(result)
                
                for param, results in results_by_param.items():
                    f.write(f"\n{'='*50}\n")
                    f.write(f"PARAMETER: {param}\n")
                    f.write(f"{'='*50}\n")
                    f.write(f"Reflected payloads: {len(results)}\n\n")
                    
                    for i, result in enumerate(results, 1):
                        details = result['details']
                        vuln_type = get_vulnerability_type(result['payload'])
                        remediation = get_remediation_guide(vuln_type)
                        
                        f.write(f"{i}. PAYLOAD USED: {result['payload']}\n")
                        f.write(f"   Status: {details['status_code']}\n")
                        f.write(f"   Reflections: {details['reflection_count']}\n")
                        f.write(f"   Response Length: {details['response_length']} bytes\n")
                        
                        if details.get('request_ip'):
                            f.write(f"   Request IP: {details['request_ip']}\n")
                        
                        # Reflection Analysis
                        if details.get('reflection_points'):
                            f.write(f"   Reflection Contexts:\n")
                            for j, point in enumerate(details['reflection_points'][:3], 1):
                                f.write(f"     {j}. Type: {point['type']}\n")
                                f.write(f"        Context: ...{point['before']}[{point['reflected_payload']}]{point['after']}...\n")
                        
                        # Vulnerability Information
                        f.write(f"   Vulnerability: {remediation['title']}\n")
                        f.write(f"   Severity: {remediation['severity']}\n")
                        f.write(f"   Impact: {remediation['impact']}\n")
                        
                        # Remediation Steps
                        f.write(f"   Remediation:\n")
                        for j, step in enumerate(remediation['remediation'], 1):
                            f.write(f"     {j}. {step}\n")
                        
                        f.write(f"\n")
            else:
                f.write("No reflected payloads found yet.\n")
        
        print(f"{info} Reflected payloads saved to: {filename}")
    except Exception as e:
        print(f"{bad} Failed to save reflected payloads: {e}")

def save_results_to_file(filename: str = "result-brutsamer.txt"):
    """Save scan results to file"""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write("BRUTSAMER SCAN RESULTS\n")
            f.write("=" * 60 + "\n")
            f.write(f"Scan Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Target URL: {getattr(save_results_to_file, 'target_url', 'N/A')}\n")
            f.write(f"Scan Type: {getattr(save_results_to_file, 'scan_type', 'N/A')}\n")
            f.write(f"Total Requests: {total_requests}\n")
            f.write(f"Completed: {completed_requests}\n")
            f.write(f"Successful Reflections: {len(scan_results)}\n")
            f.write(f"Using Tor: {getattr(save_results_to_file, 'using_tor', 'No')}\n")
            
            if getattr(save_results_to_file, 'using_tor', False):
                f.write(f"Tor IP: {getattr(save_results_to_file, 'tor_ip', 'Unknown')}\n")
            
            f.write("\nVULNERABILITY SUMMARY:\n")
            f.write("=" * 60 + "\n")
            
            if scan_results:
                # Count vulnerabilities by type
                vuln_counts = {}
                for result in scan_results:
                    vuln_type = get_vulnerability_type(result['payload'])
                    vuln_counts[vuln_type] = vuln_counts.get(vuln_type, 0) + 1
                
                f.write("\nVulnerability Distribution:\n")
                for vuln_type, count in vuln_counts.items():
                    remediation = get_remediation_guide(vuln_type)
                    f.write(f"  {remediation['title']}: {count} instances (Severity: {remediation['severity']})\n")
                
                f.write("\nDETAILED FINDINGS:\n")
                f.write("=" * 60 + "\n")
                
                # Group by parameter
                results_by_param = {}
                for result in scan_results:
                    param = result['parameter']
                    if param not in results_by_param:
                        results_by_param[param] = []
                    results_by_param[param].append(result)
                
                for param, results in results_by_param.items():
                    f.write(f"\n{'='*50}\n")
                    f.write(f"PARAMETER: {param}\n")
                    f.write(f"{'='*50}\n")
                    f.write(f"Reflected payloads: {len(results)}\n\n")
                    
                    for i, result in enumerate(results, 1):
                        details = result['details']
                        vuln_type = get_vulnerability_type(result['payload'])
                        remediation = get_remediation_guide(vuln_type)
                        
                        f.write(f"{i}. PAYLOAD USED: {result['payload']}\n")
                        f.write(f"   Status: {details['status_code']}\n")
                        f.write(f"   Reflections: {details['reflection_count']}\n")
                        f.write(f"   Response Length: {details['response_length']} bytes\n")
                        
                        if details.get('request_ip'):
                            f.write(f"   Request IP: {details['request_ip']}\n")
                        
                        # Reflection Analysis
                        if details.get('reflection_points'):
                            f.write(f"   Reflection Contexts:\n")
                            for j, point in enumerate(details['reflection_points'][:3], 1):
                                f.write(f"     {j}. Type: {point['type']}\n")
                                f.write(f"        Context: ...{point['before']}[{point['reflected_payload']}]{point['after']}...\n")
                        
                        # Vulnerability Information
                        f.write(f"   Vulnerability: {remediation['title']}\n")
                        f.write(f"   Severity: {remediation['severity']}\n")
                        f.write(f"   Impact: {remediation['impact']}\n")
                        f.write(f"   Description: {remediation['description']}\n")
                        
                        # Remediation Steps
                        f.write(f"   Remediation Steps:\n")
                        for j, step in enumerate(remediation['remediation'], 1):
                            f.write(f"     {j}. {step}\n")
                        
                        f.write(f"\n")
            else:
                f.write("No payload reflections found.\n")
        
        print(f"\n{info} Results automatically saved to: {filename}")
    except Exception as e:
        print(f"{bad} Failed to save results: {e}")

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print(f"\n{yellow}[!] Scan interrupted by user{end}")
    if is_scanning:
        print(f"{info} Saving current results...")
        save_results_to_file()
        if reflected_payloads:
            save_reflected_payloads()
    sys.exit(0)

# Register signal handler
signal.signal(signal.SIGINT, signal_handler)

class ProgressTracker:
    def __init__(self, total: int, proxy_url: str = None, use_tor: bool = False):
        self.total = total
        self.completed = 0
        self.start_time = time.time()
        self.lock = threading.Lock()
        self.last_print = 0
        self.last_reflected_count = 0
        self.proxy_url = proxy_url
        self.use_tor = use_tor
        self.current_ip = "Unknown"
        self.ip_checked = False
        self.last_ip_change = 0
        self.ip_change_interval = 5  # Change IP every 5 seconds
        self.ip_rotation_enabled = False
        
    def update_ip(self):
        """Update the current IP address and rotate if needed"""
        current_time = time.time()
        
        # Check if it's time to change IP
        if self.use_tor and (current_time - self.last_ip_change >= self.ip_change_interval):
            print(f"\n{info} Rotating Tor circuit for new IP...")
            if renew_tor_circuit():
                time.sleep(2)  # Wait for circuit to establish
                self.last_ip_change = current_time
                self.ip_rotation_enabled = True
            else:
                print(f"{bad} Failed to rotate Tor circuit")
        
        try:
            # Use a simpler IP check service
            proxies = {'http': self.proxy_url, 'https': self.proxy_url}
            response = requests.get('https://api.ipify.org?format=json', proxies=proxies, timeout=5)
            if response.status_code == 200:
                new_ip = response.json().get('ip', 'Unknown')
                if new_ip != self.current_ip and new_ip != "Unknown":
                    self.current_ip = new_ip
                    if self.use_tor and self.ip_rotation_enabled:
                        print(f"{good} New Tor IP: {self.current_ip}")
            else:
                # Fallback to httpbin
                response = requests.get('http://httpbin.org/ip', proxies=proxies, timeout=5)
                if response.status_code == 200:
                    new_ip = response.json().get('origin', 'Unknown')
                    if new_ip != self.current_ip and new_ip != "Unknown":
                        self.current_ip = new_ip
                        if self.use_tor and self.ip_rotation_enabled:
                            print(f"{good} New Tor IP: {self.current_ip}")
            self.ip_checked = True
        except:
            try:
                # Final fallback
                proxies = {'http': self.proxy_url, 'https': self.proxy_url}
                response = requests.get('http://icanhazip.com', proxies=proxies, timeout=3)
                if response.status_code == 200:
                    new_ip = response.text.strip()
                    if new_ip != self.current_ip and new_ip != "Unknown":
                        self.current_ip = new_ip
                        if self.use_tor and self.ip_rotation_enabled:
                            print(f"{good} New Tor IP: {self.current_ip}")
                self.ip_checked = True
            except:
                self.ip_checked = True
    
    def update(self, increment: int = 1):
        with self.lock:
            self.completed += increment
            
            # Update IP on first call and periodically for Tor
            if not self.ip_checked or (self.use_tor and time.time() - self.last_ip_change >= self.ip_change_interval):
                self.update_ip()
            
            # Print progress immediately for each update
            current_time = time.time()
            if current_time - self.last_print >= 0.1:  # Update every 0.1 seconds for smooth progress
                self.print_progress()
                self.last_print = current_time
    
    def print_progress(self):
        elapsed = time.time() - self.start_time
        percent = (self.completed / self.total) * 100 if self.total > 0 else 0
        
        # Calculate ETA
        if self.completed > 0:
            eta = (elapsed / self.completed) * (self.total - self.completed)
            if eta > 3600:
                eta_str = f"ETA: {eta/3600:.1f}h"
            elif eta > 60:
                eta_str = f"ETA: {eta/60:.1f}m"
            else:
                eta_str = f"ETA: {eta:.1f}s"
        else:
            eta_str = "ETA: Calculating..."
        
        # Show reflected count
        reflected_count = len(reflected_payloads)
        reflected_str = f" | Reflections: {reflected_count}" if reflected_count > 0 else ""
        
        # Progress bar
        bar_length = 30
        filled_length = int(bar_length * self.completed // self.total) if self.total > 0 else 0
        bar = '█' * filled_length + '░' * (bar_length - filled_length)
        
        # Show scanning status with IP
        status = "🟢 SCANNING"
        ip_str = f" | IP: {self.current_ip}" if self.current_ip != "Unknown" else ""
        
        # Format the progress line exactly as requested
        progress_line = f"{info} {status}{ip_str} | Progress: [{bar}] {percent:.1f}% ({self.completed}/{self.total}) | {eta_str}{reflected_str}"
        
        # Use carriage return to update the same line
        print(f"\r{progress_line}", end='', flush=True)
    
    def finish(self):
        print()  # New line after progress bar

# Logging setup
def setup_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    logger.setLevel(logging.ERROR)
    return logger

logger = setup_logger(__name__)

class ResponseComparator:
    def __init__(self):
        self.baseline_response = None
        self.baseline_hash = None
        self.baseline_length = 0
        self.baseline_content = ""
    
    def set_baseline(self, response_text: str):
        """Set the baseline response for comparison"""
        self.baseline_content = response_text
        self.baseline_length = len(response_text)
        self.baseline_hash = hashlib.md5(response_text.encode('utf-8')).hexdigest()
        print(f"{info} Baseline set: {self.baseline_length} bytes")
    
    def compare_responses(self, test_response: str, payload: str) -> Dict[str, Any]:
        """Compare test response with baseline"""
        if not self.baseline_content:
            return {
                'size_changed': False,
                'content_changed': False,
                'similarity_score': 1.0,
                'changes_detected': [],
                'size_difference': 0,
                'baseline_available': False
            }
        
        comparison = {
            'size_changed': False,
            'content_changed': False,
            'similarity_score': 0,
            'changes_detected': [],
            'size_difference': 0,
            'baseline_available': True
        }
        
        size_diff = len(test_response) - self.baseline_length
        comparison['size_difference'] = size_diff
        comparison['size_changed'] = abs(size_diff) > 5
        
        similarity = SequenceMatcher(None, self.baseline_content, test_response).ratio()
        comparison['similarity_score'] = similarity
        comparison['content_changed'] = similarity < 0.99
        
        return comparison

# Global comparator
comparator = ResponseComparator()

# HTTP Requester with IP tracking
def get_request_ip(proxy_url: str = None) -> str:
    """Get the IP address for the current request"""
    try:
        proxies = {'http': proxy_url, 'https': proxy_url} if proxy_url else None
        response = requests.get('http://httpbin.org/ip', proxies=proxies, timeout=10)
        return response.json().get('origin', 'Unknown')
    except:
        return 'Unknown'

def get_baseline_response(url: str, headers: Dict, GET: bool, timeout: float, proxy_url: str = None) -> str:
    """Get the baseline response without any parameters"""
    try:
        session = requests.Session()
        session.verify = False
        
        # Increase timeout for Tor
        if proxy_url:
            session.proxies = {'http': proxy_url, 'https': proxy_url}
            timeout = min(timeout * 3, 60)
        
        if GET:
            response = session.get(url, headers=headers, timeout=timeout)
        else:
            response = session.post(url, data={}, headers=headers, timeout=timeout)
        
        if response.status_code == 200:
            return response.text
        else:
            print(f"{bad} Baseline status: {response.status_code}")
            return ""
    except Exception as e:
        print(f"{bad} Baseline error: {e}")
        return ""

def requester(url: str, params: Dict, headers: Dict, GET: bool, delay: float, timeout: float, proxy_url: str = None, show_ip: bool = False) -> Tuple[Any, str]:
    """Make HTTP request and return response + IP address"""
    if delay > 0:
        time.sleep(delay)
    
    request_ip = "Unknown"
    
    try:
        session = requests.Session()
        session.verify = False
        
        # Rotate User-Agent for each request if using Tor
        if proxy_url:
            headers = headers.copy()
            headers['User-Agent'] = get_random_user_agent()
            # Increase timeout for Tor requests
            timeout = min(timeout * 2, 30)
        
        if proxy_url:
            session.proxies = {'http': proxy_url, 'https': proxy_url}
        
        # Get IP before request if showing IP
        if show_ip and proxy_url:
            request_ip = get_request_ip(proxy_url)
        
        if GET:
            response = session.get(url, params=params, headers=headers, timeout=timeout)
        else:
            response = session.post(url, data=params, headers=headers, timeout=timeout)
        
        return response, request_ip
        
    except requests.RequestException as e:
        return None, request_ip

# URL Utilities
def getUrl(target: str, GET: bool) -> str:
    parsed = urlparse(target)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

def getParams(target: str, paramData: str, GET: bool, auto_params: bool = False, url_only: bool = False) -> Dict[str, str]:
    params = {}
    
    if url_only:
        # For URL-only scanning, extract existing parameters
        parsed = urlparse(target)
        query_params = parse_qs(parsed.query)
        for key, values in query_params.items():
            params[key] = values[0] if values else "test"
    elif GET:
        parsed = urlparse(target)
        query_params = parse_qs(parsed.query)
        for key, values in query_params.items():
            params[key] = values[0] if values else "test"
    elif paramData:
        pairs = paramData.split('&')
        for pair in pairs:
            if '=' in pair:
                key, value = pair.split('=', 1)
                params[key] = value
    
    if not params and auto_params and not url_only:
        suggested = get_suggested_params(target)
        for param in suggested:
            params[param] = "test"
        print(f"{info} Auto-detected parameters: {', '.join(suggested)}")
    
    return params

def validate_params(params: Dict, url: str, url_only: bool = False) -> None:
    if not params:
        if url_only:
            print(f"{bad} No URL parameters found in: {url}")
            print(f"{info} The URL should contain parameters like: https://example.com/page?param=value")
        else:
            suggested = get_suggested_params(url)
            print(f"{bad} No parameters to test.")
            print(f"{info} Suggested parameters for this URL: {', '.join(suggested)}")
            print(f"{info} Use --data 'name=test&email=test@test.com' for POST parameters")
            print(f"{info} Or use --auto-params to auto-detect parameters")
            print(f"{info} Or use --fu for URL parameter scanning")
        raise ValueError("No parameters to test")

def process_payload(paramName: str, payload: str, encoding: Optional[Callable]) -> str:
    if encoding:
        return encoding(unquote(payload))
    return payload

def test_payload_wrapper(args):
    """Wrapper function for threading"""
    url, params, headers, GET, delay, timeout, paramName, payload, encoding, progress_tracker, proxy_url, show_ip = args
    
    result = test_payload(url, params, headers, GET, delay, timeout, paramName, payload, encoding, proxy_url, show_ip)
    
    # Update progress
    if progress_tracker:
        progress_tracker.update()
    
    return result, paramName, payload

def test_payload(url: str, params: Dict, headers: Dict, GET: bool, 
                delay: float, timeout: float, paramName: str, 
                payload: str, encoding: Optional[Callable], proxy_url: str = None, show_ip: bool = False) -> Tuple[bool, Dict]:
    params_copy = copy.deepcopy(params)
    processed_payload = process_payload(paramName, payload, encoding)
    params_copy[paramName] = processed_payload
    
    response, request_ip = requester(url, params_copy, headers, GET, delay, timeout, proxy_url, show_ip)
    
    if response is None:
        return False, {}
    
    if response.status_code >= 400:
        return False, {}
    
    response_text = response.text
    status_code = response.status_code
    
    search_payload = encoding(payload) if encoding else payload
    
    payload_found = search_payload in response_text
    
    if payload_found:
        comparison = comparator.compare_responses(response_text, search_payload)
        reflection_points = analyze_reflection_context(response_text, payload, search_payload)
        
        result_info = {
            'reflected': True,
            'status_code': status_code,
            'reflection_count': len(reflection_points),
            'reflection_points': reflection_points,
            'payload_sent': processed_payload,
            'payload_original': payload,
            'response_length': len(response_text),
            'baseline_comparison': comparison,
            'size_changed': comparison['size_changed'],
            'content_changed': comparison['content_changed'],
            'similarity_score': comparison['similarity_score'],
            'baseline_available': comparison['baseline_available'],
            'request_ip': request_ip if show_ip else None,
            'full_response_preview': response_text[:500] + "..." if len(response_text) > 500 else response_text
        }
        
        return True, result_info
    else:
        return False, {}

def display_reflection_details(param_name: str, payload: str, details: Dict):
    """Display detailed reflection information including the actual reflected content"""
    vuln_type = get_vulnerability_type(payload)
    remediation = get_remediation_guide(vuln_type)
    
    print(f"\n{green}{'='*80}{end}")
    print(f"{green}[!] INPUT REFLECTION DETECTED{end}")
    print(f"{green}{'='*80}{end}")
    
    # Clear payload information
    print(f"{yellow}🔍 PAYLOAD THAT CAUSED REFLECTION:{end}")
    print(f"{yellow}{'-'*50}{end}")
    print(f"{green}Parameter:{end} {param_name}")
    print(f"{green}Payload Used:{end} {red}{payload}{end}")
    print(f"{green}Payload Sent:{end} {details['payload_sent']}")
    print(f"{green}Status Code:{end} {details['status_code']}")
    print(f"{green}Response Length:{end} {details['response_length']} bytes")
    print(f"{green}Reflection Points Found:{end} {details['reflection_count']}")
    
    if details.get('request_ip'):
        print(f"{green}Request IP:{end} {details['request_ip']}")
    
    # Show detailed reflection contexts
    if details.get('reflection_points'):
        print(f"\n{blue}[*] HOW THE PAYLOAD WAS REFLECTED:{end}")
        print(f"{blue}{'-'*50}{end}")
        for i, point in enumerate(details['reflection_points'][:5], 1):  # Show first 5 reflection points
            print(f"{i}. {point['type']}")
            print(f"   Position in response: {point['position']}")
            print(f"   Context: ...{point['before']}{red}[{point['reflected_payload']}]{end}{point['after']}...")
            print()
    
    # Show response preview
    print(f"{blue}[*] RESPONSE PREVIEW (first 500 chars):{end}")
    print(f"{blue}{'-'*50}{end}")
    print(details.get('full_response_preview', 'N/A'))
    
    # Vulnerability Information
    print(f"\n{blue}[*] VULNERABILITY ANALYSIS:{end}")
    print(f"{blue}{'-'*50}{end}")
    print(f"Type: {remediation['title']}")
    print(f"Severity: {remediation['severity']}")
    print(f"Impact: {remediation['impact']}")
    print(f"Description: {remediation['description']}")
    
    # Remediation Steps
    print(f"\n{blue}[*] REMEDIATION GUIDANCE:{end}")
    print(f"{blue}{'-'*50}{end}")
    for i, step in enumerate(remediation['remediation'], 1):
        print(f"{i}. {step}")
    
    # Exploitation Potential
    print(f"\n{blue}[*] EXPLOITATION POTENTIAL:{end}")
    print(f"{blue}{'-'*50}{end}")
    if vuln_type == 'xss':
        print("✓ Can execute JavaScript in victim's browser")
        print("✓ Can steal cookies and session tokens")
        print("✓ Can perform actions on behalf of the user")
        print("✓ Can deface the website")
    elif vuln_type == 'sqli':
        print("✓ Can extract database information")
        print("✓ Can bypass authentication")
        print("✓ Can modify database contents")
        print("✓ Can potentially execute system commands")
    elif vuln_type == 'command':
        print("✓ Can execute system commands on the server")
        print("✓ Can read/write files on the server")
        print("✓ Can potentially gain full server control")
    else:
        print("✓ Input validation bypass possible")
        print("✓ Potential for further exploitation")
        print("✓ Information disclosure risk")
    
    print(f"{green}{'='*80}{end}\n")

def get_payloads_for_scan(scan_type: str) -> List[str]:
    """Get appropriate payloads based on scan type"""
    if scan_type == "xss":
        return load_payloads_from_file(PAYLOAD_FILES['xss'])
    elif scan_type == "sqli":
        return load_payloads_from_file(PAYLOAD_FILES['sqli'])
    elif scan_type == "command":
        return load_payloads_from_file(PAYLOAD_FILES['command'])
    elif scan_type == "path_traversal":
        return load_payloads_from_file(PAYLOAD_FILES['path_traversal'])
    elif scan_type == "ssrf":
        return load_payloads_from_file(PAYLOAD_FILES['ssrf'])
    elif scan_type == "xxe":
        return load_payloads_from_file(PAYLOAD_FILES['xxe'])
    elif scan_type == "ssti":
        return load_payloads_from_file(PAYLOAD_FILES['ssti'])
    elif scan_type == "ldap":
        return load_payloads_from_file(PAYLOAD_FILES['ldap'])
    elif scan_type == "quick":
        return load_payloads_from_file(PAYLOAD_FILES['quick'])
    elif scan_type == "basic":
        return load_payloads_from_file(PAYLOAD_FILES['basic'])
    else:  # all - comprehensive scanning
        all_payloads = []
        # Load payloads from all files except quick test
        for vuln_type, file_path in PAYLOAD_FILES.items():
            if vuln_type != 'quick':
                payloads = load_payloads_from_file(file_path)
                # Take first 5 payloads from each type for comprehensive scan
                all_payloads.extend(payloads[:5])
        return all_payloads

def scan_website(url: str, params: Dict, headers: Dict, GET: bool, 
                 threads: int, delay: float, timeout: float, 
                 proxy_url: str = None, show_ip: bool = False,
                 scan_type: str = "all", use_tor: bool = False) -> List[Dict]:
    """Main scanning function"""
    global is_scanning, total_requests, completed_requests, scan_results, reflected_payloads
    
    is_scanning = True
    scan_results = []
    reflected_payloads = []
    
    print(f"{info} Starting {scan_type.upper()} scan...")
    
    # Get payloads based on scan type
    payloads = get_payloads_for_scan(scan_type)
    
    if not payloads:
        print(f"{bad} No payloads loaded for {scan_type} scan type")
        return []
    
    print(f"{info} Using {len(payloads)} payloads for {scan_type} scanning")
    
    # Get baseline response
    print(f"{info} Getting baseline response...")
    baseline = get_baseline_response(url, headers, GET, timeout, proxy_url)
    if baseline:
        comparator.set_baseline(baseline)
    
    # Prepare tasks
    tasks = []
    param_names = list(params.keys())
    
    for param_name in param_names:
        for payload in payloads:
            tasks.append((
                url, params, headers, GET, delay, timeout,
                param_name, payload, None, None, proxy_url, show_ip
            ))
    
    total_requests = len(tasks)
    completed_requests = 0
    
    print(f"{info} Total requests to make: {total_requests}")
    print(f"{info} Starting scan with {threads} threads...\n")
    
    # Start progress tracker with proxy URL for IP display and Tor rotation
    progress_tracker = ProgressTracker(total_requests, proxy_url, use_tor)
    
    # Update tasks with progress tracker
    tasks_with_progress = []
    for task in tasks:
        url, params, headers, GET, delay, timeout, param_name, payload, encoding, _, proxy_url, show_ip = task
        tasks_with_progress.append((
            url, params, headers, GET, delay, timeout,
            param_name, payload, encoding, progress_tracker, proxy_url, show_ip
        ))
    
    # Execute scan with threading
    with ThreadPoolExecutor(max_workers=threads) as executor:
        future_to_task = {
            executor.submit(test_payload_wrapper, task): task 
            for task in tasks_with_progress
        }
        
        for future in as_completed(future_to_task):
            try:
                (reflected, details), param_name, payload = future.result()
                
                if reflected:
                    result = {
                        'parameter': param_name,
                        'payload': payload,
                        'details': details
                    }
                    
                    with lock:
                        scan_results.append(result)
                        reflected_payloads.append(result)
                    
                    # Clear the progress line and show reflection result
                    print()  # New line
                    print(f"\n{good} INPUT REFLECTION FOUND!")
                    print(f"   Parameter: {param_name}")
                    print(f"   Payload Used: {red}{payload}{end}")
                    print(f"   Status: {details['status_code']}")
                    print(f"   Reflection Points: {details['reflection_count']}")
                    
                    # Show detailed reflection analysis
                    display_reflection_details(param_name, payload, details)
                    
                    # Save results immediately
                    save_results_to_file()
                    save_reflected_payloads()
                
            except Exception as e:
                print(f"\n{bad} Error in thread: {e}")
    
    progress_tracker.finish()
    is_scanning = False
    
    return scan_results

def main():
    parser = argparse.ArgumentParser(description='BRUTSAMER - Advanced Web Vulnerability Scanner')
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('--data', help='POST data')
    parser.add_argument('--headers', help='Custom headers (JSON format)')
    parser.add_argument('--fu', action='store_true', help='URL-only scanning (no --data needed)')
    parser.add_argument('--auto-params', action='store_true', help='Auto-detect parameters')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Number of threads (default: 10)')
    parser.add_argument('--delay', type=float, default=0, help='Delay between requests (seconds)')
    parser.add_argument('--timeout', type=float, default=10, help='Request timeout (seconds)')
    parser.add_argument('--tor', action='store_true', help='Use Tor proxy (socks5://127.0.0.1:9050)')
    parser.add_argument('--proxy', help='Custom proxy (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--show-ip', action='store_true', help='Show request IP address')
    
    # Vulnerability-specific scanning
    parser.add_argument('--fxss', action='store_true', help='Fast XSS scanning')
    parser.add_argument('--fsqli', action='store_true', help='Fast SQLi scanning')
    parser.add_argument('--fcmd', action='store_true', help='Fast Command Injection scanning')
    parser.add_argument('--fpath', action='store_true', help='Fast Path Traversal scanning')
    parser.add_argument('--fssrf', action='store_true', help='Fast SSRF scanning')
    parser.add_argument('--fxxe', action='store_true', help='Fast XXE scanning')
    parser.add_argument('--fssti', action='store_true', help='Fast SSTI scanning')
    parser.add_argument('--fldap', action='store_true', help='Fast LDAP Injection scanning')
    parser.add_argument('--fbasic', action='store_true', help='Fast Basic Fuzzing')
    parser.add_argument('--fquick', action='store_true', help='Quick Test (few payloads)')
    parser.add_argument('--fall', action='store_true', help='Comprehensive all vulnerability scanning')
    
    args = parser.parse_args()
    
    # Set global variables for saving results
    save_results_to_file.target_url = args.url
    save_reflected_payloads.target_url = args.url
    save_results_to_file.using_tor = args.tor or args.proxy
    save_reflected_payloads.using_tor = args.tor or args.proxy
    
    # Determine scan type for reporting
    scan_type = "all"  # Default
    if args.fxss:
        scan_type = "xss"
    elif args.fsqli:
        scan_type = "sqli"
    elif args.fcmd:
        scan_type = "command"
    elif args.fpath:
        scan_type = "path_traversal"
    elif args.fssrf:
        scan_type = "ssrf"
    elif args.fxxe:
        scan_type = "xxe"
    elif args.fssti:
        scan_type = "ssti"
    elif args.fldap:
        scan_type = "ldap"
    elif args.fbasic:
        scan_type = "basic"
    elif args.fquick:
        scan_type = "quick"
    elif args.fall:
        scan_type = "all"
    
    save_results_to_file.scan_type = scan_type.upper()
    save_reflected_payloads.scan_type = scan_type.upper()
    
    try:
        # Initialize scanning
        global is_scanning, total_requests, completed_requests
        is_scanning = True
        
        print(f"\n{colors.BOLD}{colors.CYAN}BRUTSAMER - Advanced Web Vulnerability Scanner{colors.END}")
        print(f"{colors.CYAN}{'='*60}{colors.END}")
        print(f"{info} Target: {args.url}")
        print(f"{info} Scan Type: {scan_type.upper()}")
        print(f"{info} Threads: {args.threads}")
        print(f"{info} Auto-params: {'Yes' if args.auto_params else 'No'}")
        
        # Tor/proxy setup
        proxy_url = None
        current_ip = "Unknown"
        use_tor = False
        
        if args.tor:
            proxy_url = "socks5://127.0.0.1:9050"
            use_tor = True
            print(f"{info} Using Tor proxy with IP rotation every 5 seconds")
            
            # First check if Tor is running and get initial IP
            tor_working, current_ip = check_tor_connection(proxy_url)
            if tor_working:
                print(f"{good} Tor connection active - Initial IP: {current_ip}")
                save_results_to_file.tor_ip = current_ip
                save_reflected_payloads.tor_ip = current_ip
                
                # Check if stem is available for IP rotation
                try:
                    from stem import Signal
                    from stem.control import Controller
                    print(f"{good} Stem library available - IP rotation enabled")
                except ImportError:
                    print(f"{bad} Stem library not installed - IP rotation disabled")
                    print(f"{info} Install stem for IP rotation: pip install stem")
            else:
                print(f"{bad} Tor connection failed - check if Tor is running")
                print(f"{info} Try: sudo systemctl start tor")
                print(f"{info} Or install Tor: sudo apt install tor")
                return
        elif args.proxy:
            proxy_url = args.proxy
            print(f"{info} Using proxy: {args.proxy}")
            current_ip = get_current_ip(proxy_url)
            print(f"{info} Proxy IP: {current_ip}")
        
        # Get target URL and parameters
        GET = not args.data
        url = getUrl(args.url, GET)
        params = getParams(args.url, args.data, GET, args.auto_params, args.fu)
        
        # Validate we have parameters to test
        validate_params(params, url, args.fu)
        
        print(f"{info} Parameters to test: {', '.join(params.keys())}")
        print(f"{info} Request method: {'GET' if GET else 'POST'}")
        
        # Setup headers
        headers = {
            'User-Agent': get_random_user_agent(),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close'
        }
        
        # Add custom headers if provided
        if args.headers:
            try:
                custom_headers = json.loads(args.headers)
                headers.update(custom_headers)
                print(f"{info} Custom headers loaded: {len(custom_headers)} headers")
            except json.JSONDecodeError:
                print(f"{bad} Invalid JSON in headers")
                return
        
        # Start the scan
        start_time = time.time()
        results = scan_website(
            url=url,
            params=params,
            headers=headers,
            GET=GET,
            threads=args.threads,
            delay=args.delay,
            timeout=args.timeout,
            proxy_url=proxy_url,
            show_ip=args.show_ip,
            scan_type=scan_type,
            use_tor=use_tor
        )
        
        # Display final results
        elapsed_time = time.time() - start_time
        print(f"\n{info} Scan completed in {elapsed_time:.2f} seconds")
        print(f"{info} Total requests: {total_requests}")
        print(f"{info} Reflections found: {len(results)}")
        
        if results:
            print(f"\n{good} Input reflections detected! Check result-brutsamer.txt for details")
            
            # Show summary by vulnerability type
            vuln_counts = {}
            for result in results:
                vuln_type = get_vulnerability_type(result['payload'])
                vuln_counts[vuln_type] = vuln_counts.get(vuln_type, 0) + 1
            
            print(f"\n{info} Vulnerability Summary:")
            for vuln_type, count in vuln_counts.items():
                remediation = get_remediation_guide(vuln_type)
                print(f"  {remediation['title']}: {count} instances")
        else:
            print(f"{bad} No input reflections found")
        
        # Save final results
        save_results_to_file()
        if reflected_payloads:
            save_reflected_payloads()
        
    except Exception as e:
        print(f"{bad} Error: {e}")
        is_scanning = False

if __name__ == "__main__":
    main()
