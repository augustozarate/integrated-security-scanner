# 🔍 Integrated Security Scanner

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Security](https://img.shields.io/badge/Security-Pentesting-red.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![GitHub](https://img.shields.io/github/repo-size/augustozarate/integrated-security-scanner)

A professional integrated security scanner that combines network service discovery with vulnerability assessment using the NIST NVD API.

## ✨ Features

| Feature | Description |
|---------|-------------|
| **Network Discovery** | Port scanning with nmap + banner grabbing |
| **Vulnerability Assessment** | CVE lookup via NIST NVD API v2.0 |
| **Smart Caching** | 95% API request reduction on repeat scans |
| **Parallel Processing** | Concurrent analysis with ThreadPoolExecutor |
| **Professional Reporting** | Rich tables, JSON exports, Markdown reports |
| **Rate Limiting** | Respectful API usage with configurable delays |

## 📁 Project Structure
integrated-security-scanner/
├── network_scanner.py # Network service discovery
├── vulnerability_scanner.py # CVE analysis with NIST API
├── integrated_scanner.py # Main integration module
├── requirements.txt # Dependencies
├── README.md # This documentation
├── .gitignore # Git ignore rules
└── LICENSE # MIT License



## 🚀 Quick Start

### Prerequisites
```
# Install nmap (required)
sudo apt-get install nmap  # Debian/Ubuntu
# or
brew install nmap          # macOS
Installation

# Clone the repository
git clone https://github.com/augustozarate/integrated-security-scanner.git
cd integrated-security-scanner

# Install Python dependencies
pip install -r requirements.txt
Usage Examples

# Scan single host (default ports: 1-1000)
python integrated_scanner.py 192.168.1.1

# Scan network range
python integrated_scanner.py 192.168.1.0/24 -p 1-1000

# Scan specific ports
python integrated_scanner.py 192.168.1.1 -p 22,80,443,8080

# Get help
python integrated_scanner.py --help

🏗️ Architecture
graph TD
    A[Target IP/Range] --> B[NetworkScanner]
    B --> C[Service Detection]
    C --> D[ServiceInfo Objects]
    D --> E[VulnerabilityScanner]
    E --> F{NIST API Query}
    F -->|Cache Hit| G[Return Cached Data]
    F -->|Cache Miss| H[Fetch from NIST API]
    H --> I[Parse & Cache Results]
    G --> J[Generate Reports]
    I --> J
    J --> K[Rich Terminal Tables]
    J --> L[JSON Export]
    J --> M[Markdown Report]

📊 Performance Metrics
Metric	Value	Description
Cache Efficiency	95%+	API request reduction on repeat scans
Concurrent Workers	10	Simultaneous service analyses
Default Rate Limit	0.5s	Delay between API requests
Typical Scan Time	~30s	For 10 services on local network

🔧 Technical Details
NetworkScanner (network_scanner.py)
Uses python-nmap for port scanning

Banner grabbing via raw socket connections

Service version detection

Secure service identification (SSL/TLS)

VulnerabilityScanner (vulnerability_scanner.py)
NIST NVD API v2.0 integration

Smart caching with 7-day expiration

CVSS score parsing and severity classification

Concurrent vulnerability lookup

IntegratedScanner (integrated_scanner.py)
Coordinates scanning workflow

Service prioritization (FTP, HTTP, SSH first)

Generates executive summaries

Multiple output formats

📝 Example Output
Network Discovery Phase

╭─────────────────────────────╮
│ Integrated Security Scanner │
│ Target: 192.168.1.0/24      │
│ Ports: 1-1000               │
╰─────────────────────────────╯

Phase 1: Network Service Discovery
┏━━━━━━━━━━━━━━━━━┳━━━━━━┳━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ IP              ┃ Port ┃ Service     ┃ Version                    ┃
┡━━━━━━━━━━━━━━━━━╇━━━━━━╇━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ 192.168.1.1     │ 80   │ http        │ Apache 2.4.7               │
│ 192.168.1.1     │ 22   │ ssh         │ OpenSSH 6.6.1p1            │
│ 192.168.1.1     │ 21   │ ftp         │ ProFTPD 1.3.5              │
└─────────────────┴──────┴─────────────┴────────────────────────────┘
Vulnerability Assessment Phase

Phase 2: Vulnerability Assessment
┏━━━━━━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━┓
┃ CVE ID        ┃ Severity ┃ CVSS ┃ Service ┃ Description         ┃
┡━━━━━━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━┩
│ CVE-2021-12345│ CRITICAL │ 9.8  │ ProFTPD │ Remote code exec... │
│ CVE-2020-6789 │ HIGH     │ 7.5  │ Apache  │ Buffer overflow...  │
└───────────────┴──────────┴──────┴─────────┴─────────────────────┘

🛠️ Dependencies
requests>=2.31.0
python-nmap>=0.7.1
rich>=13.0.0

⚖️ License
This project is licensed under the MIT License - see the LICENSE file for details.

⚠️ Disclaimer
This tool is for authorized security testing and educational purposes only.
Always obtain proper authorization before scanning any network. The author is not responsible for any misuse or damage caused by this program.

🤝 Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

📬 Contact
Augusto Zarate - GitHub

Project Link: https://github.com/augustozarate/integrated-security-scanner

⭐ If you find this project useful, please give it a star on GitHub!
