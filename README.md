markdown
# BRUTSAMER - Advanced Web Vulnerability Scanner

![Python](https://img.shields.io/badge/Python-3.6+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)

BRUTSAMER is a comprehensive web vulnerability scanner designed to detect various security vulnerabilities through input reflection analysis.

## Features

- **Multiple Vulnerability Detection**: XSS, SQLi, Command Injection, Path Traversal, SSRF, XXE, SSTI, LDAP Injection
- **Tor Support**: Anonymous scanning with automatic IP rotation
- **Smart Parameter Detection**: Auto-detects parameters based on URL context
- **Real-time Results**: Live progress tracking and immediate result saving
- **Comprehensive Reporting**: Detailed vulnerability analysis with remediation guidance
- **Threaded Scanning**: High-performance concurrent scanning

## Installation

1. Clone the repository:
```bash
git clone https://github.com/samerelhage777/brutsamer.git
cd brutsamer
Install dependencies:

bash
pip install -r requirements.txt
(Optional) For Tor support:

bash
# On Ubuntu/Debian
sudo apt install tor
sudo systemctl start tor

# Or install from source
Usage
Basic Scanning
bash
python3 brutsamer.py -u "https://example.com/page?param=value"
POST Request Scanning
bash
python3 brutsamer.py -u "https://example.com/login" --data "username=test&password=test"
URL Parameter Scanning
bash
python3 brutsamer.py -u "https://example.com/page?param=value" --fu
Tor Anonymous Scanning
bash
python3 brutsamer.py -u "https://example.com" --tor --show-ip
Specific Vulnerability Scanning
bash
# XSS Scanning
python3 brutsamer.py -u "https://example.com" --fxss

# SQL Injection Scanning
python3 brutsamer.py -u "https://example.com" --fsqli

# Comprehensive Scanning
python3 brutsamer.py -u "https://example.com" --fall
Advanced Options
bash
python3 brutsamer.py -u "https://example.com" \
  --threads 20 \
  --delay 0.5 \
  --timeout 15 \
  --tor \
  --show-ip \
  --headers '{"X-API-Key": "your-key"}'
Scan Types
--fxss: Fast XSS scanning

--fsqli: Fast SQL injection scanning

--fcmd: Fast command injection scanning

--fpath: Fast path traversal scanning

--fssrf: Fast SSRF scanning

--fxxe: Fast XXE scanning

--fssti: Fast SSTI scanning

--fldap: Fast LDAP injection scanning

--fbasic: Fast basic fuzzing

--fquick: Quick test with minimal payloads

--fall: Comprehensive all-vulnerability scanning

Output Files
result-brutsamer.txt: Complete scan results with remediation guidance

reflected-payloads.txt: Real-time reflected payloads with context analysis

Legal Disclaimer
This tool is intended for security testing and educational purposes only. Only use on systems you own or have explicit permission to test. The developers are not responsible for any misuse or damage caused by this tool.

Contributing
Fork the repository

Create a feature branch

Commit your changes

Push to the branch

Create a Pull Request

License
MIT License - see LICENSE file for details

text

## Step 2: Initialize and Push to GitHub

### 1. Initialize Git repository:
```bash
# Create the directory structure
mkdir brutsamer
cd brutsamer
mkdir payloads

# Move your script to brutsamer.py
# Create the other files mentioned above

# Initialize git
git init
2. Add files and make initial commit:
bash
git add .
git commit -m "Initial commit: BRUTSAMER web vulnerability scanner"
3. Create GitHub repository:
Go to https://github.com

Click "New repository"

Name it "brutsamer"

Don't initialize with README (we already created one)

4. Push to GitHub:
bash
git remote add origin https://github.com/YOUR_USERNAME/brutsamer.git
git branch -M main
git push -u origin main
Step 3: Create Sample Payload Files
Since your code references payload files, create basic versions in the payloads/ directory:

payloads/xss_payloads.txt:
txt
<script>alert('XSS')</script>
"><script>alert('XSS')</script>
'><script>alert('XSS')</script>
javascript:alert('XSS')
" onmouseover="alert('XSS')
' onmouseover="alert('XSS')
<img src=x onerror=alert('XSS')>
<svg onload=alert('XSS')>
payloads/sqli_payloads.txt:
txt
' OR '1'='1
' UNION SELECT 1,2,3--
' AND 1=1--
' AND 1=2--
' ORDER BY 1--
payloads/quick_test.txt:
txt
test123
<script>alert(1)</script>
' OR '1'='1
;whoami
../../etc/passwd
{{7*7}}
Create similar basic payload files for the other vulnerability types.

Step 4: Final Repository Structure
Your final GitHub repository should look like:

text
brutsamer/
├── .gitignore
├── README.md
├── requirements.txt
├── brutsamer.py
└── payloads/
    ├── xss_payloads.txt
    ├── sqli_payloads.txt
    ├── command_injection_payloads.txt
    ├── path_traversal_payloads.txt
    ├── ssrf_payloads.txt
    ├── xxe_payloads.txt
    ├── ssti_payloads.txt
    ├── ldap_payloads.txt
    ├── basic_fuzz_payloads.txt
    └── quick_test.txt
Step 5: Additional Enhancements (Optional)
Consider adding these files for a more professional repository:

LICENSE (MIT License):
text
MIT License

Copyright (c) 2024 BRUTSAMER

Permission is hereby granted...
CONTRIBUTING.md:
markdown
# Contributing to BRUTSAMER
...
Important Notes:
Legal Compliance: Ensure your README includes proper disclaimers about ethical usage

Payload Safety: The payload files should contain only safe, non-destructive payloads

Code Quality: Consider adding type hints and docstrings for better maintainability

Security: Review the code for any potential security issues in the scanner itself

Your code is now ready to be published! The repository includes everything needed for users to understand, install, and use your vulnerability scanner.
