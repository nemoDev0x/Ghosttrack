#  GhosTTrack

### Advanced Pentesting & Red Team Framework

[![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=flat-square)](LICENSE)
[![Modules](https://img.shields.io/badge/Modules-40+-ef4444?style=flat-square)]()
[![Status](https://img.shields.io/badge/Status-Active-22c55e?style=flat-square)]()
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-0ea5e9?style=flat-square)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-Welcome-f97316?style=flat-square)]()

**A complete, modular pentesting suite featuring 40+ modules — from passive reconnaissance to advanced Red Team techniques.**

[Features](#-features) • [Modules](#-modules) • [Installation](#-installation) • [Usage](#-usage) • [Reports](#-reports) • [Legal](#%EF%B8%8F-legal-disclaimer)

</div>

---

## ⚠️ Legal Disclaimer

> **This tool was developed exclusively for EDUCATIONAL purposes as part of an academic Final Year Project (TFG).**
>
> ✅ **Allowed:** Personal systems, explicitly authorized audits, lab/testing environments  
> ❌ **Forbidden:** Scanning systems without written permission — this may constitute a criminal offense  
>
> The author takes **NO responsibility** for misuse of this tool.

---

##  Features

-  **40+ Functional Modules** split into Basic and Red Team categories
-  **Multi-threading** for fast and efficient scans
-  **Professional Reports** in HTML, JSON and TXT formats
-  **Complete Logging** system with file rotation
-  **Script Injection** — run your own custom Python scripts
-  **Modular Architecture** — easily extendable
-  **Intuitive CLI** with multiple options and verbose mode
-  **Built-in Legal Safeguards** — authorization check before every scan

---

##  Modules

### 🔵 Basic Modules (20)

| Category | Modules |
|----------|---------|
| **Reconnaissance** | GeoIP, WHOIS, DNS Enumeration, Subdomain Finder, Traceroute |
| **Network Analysis** | Port Scanner, Service Detection, OS Fingerprinting, Banner Grabbing, ARP Scanner |
| **Security** | Vulnerability Scanner, SSL/TLS Analyzer |
| **Web Hacking** | Web Crawler, Directory Bruteforce, SQL Injection, XSS Scanner |
| **Extras** | Network Sniffer, Email Harvester, Metadata Extractor, Custom Scripts |

### 🔴 Red Team Modules (20)

| Category | Modules |
|----------|---------|
| **AD Attacks** | SMB Enum, LDAP Enum, Kerberos, NTLM Relay, BloodHound |
| **Post-Exploitation** | PrivEsc, Lateral Movement, Credential Dump, Token Manipulation, Process Injection |
| **Persistence** | DLL Hijacking, Persistence Mechanisms |
| **Evasion** | Firewall Evasion, AV Evasion |
| **Offensive** | Payload Gen, C2 Communication, Exfiltration, WiFi Attacks, Bluetooth, Social Engineering |

---

##  Installation

### Prerequisites

- Python 3.8 or higher
- pip package manager
- OS: Linux, macOS or Windows

### Step-by-step

```bash
# 1. Clone the repository
git clone https://github.com/your-username/ghosttrack.git
cd ghosttrack

# 2. Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment variables (optional)
cp .env.example .env
nano .env                       # Add your API keys

# 5. Verify installation
python main.py --list-modules
```

### Tested On

| OS | Version | Status |
|----|---------|--------|
| Kali Linux | 2024.x |  Supported |
| Ubuntu | 22.04 / 24.04 |  Supported |
| macOS | 13+ |  Supported |
| Windows | 10 / 11 |  Partial (some modules require Linux) |

---

##  Usage

### Basic Commands

```bash
# List all available modules
python main.py --list-modules

# Full scan — 20 basic modules
python main.py -t 192.168.1.100 --full

# Red Team assessment — 20 advanced modules
python main.py -t 192.168.1.100 --redteam --domain corp.local

# Complete scan — all 40 modules
python main.py -t target.com --full --redteam
```

### Advanced Examples

```bash
# Web application pentest
python main.py -t example.com --full --threads 50 --timeout 10

# Active Directory audit
python main.py -t dc01.corp.local --redteam --domain corp.local

# Local network scan
python main.py -t 192.168.1.1 --full --local-network

# Inject a custom script
python main.py -t target.com --inject scripts/my_script.py

# Save report to a custom path
python main.py -t target.com --full -o /tmp/reports/
```

### Single Module Execution

```bash
python main.py -t target.com -m geoip
python main.py -t target.com -m port_scanner
python main.py -t target.com -m vuln_scanner
python main.py -t target.com -m ssl_analyzer
```

### All CLI Options

```
usage: main.py [-h] [-t TARGET] [--full] [--redteam] [--domain DOMAIN]
               [-m MODULE] [--inject SCRIPT] [--threads N] [--timeout N]
               [-o OUTPUT] [--local-network] [--list-modules] [-v]

  -t, --target        Target IP or domain
  --full              Run all 20 basic modules
  --redteam           Run all 20 Red Team modules
  --domain            Domain for AD attacks (e.g. corp.local)
  -m, --module        Run a single specific module
  --inject            Inject and run a custom Python script
  --threads           Number of threads (default: 10, max: 100)
  --timeout           Timeout in seconds (default: 5)
  -o, --output        Output directory for reports
  --local-network     Enable local network scanning
  --list-modules      List all available modules
  -v, --verbose       Enable verbose output
```

---

##  Reports

GhostTrack automatically generates professional reports after each scan:

```
reports/
├── report_192.168.1.100_20260101_120000.html   ← Visual, browser-ready
├── report_192.168.1.100_20260101_120000.json   ← Machine-readable
└── report_192.168.1.100_20260101_120000.txt    ← Plain text summary
```

Reports include: target summary, open ports, detected services, vulnerabilities found, SSL/TLS details, and full module output.

---

##  Project Structure

```
ghosttrack/
├── main.py                     # Entry point & CLI
├── config.json                 # Global configuration
├── requirements.txt            # Python dependencies
├── .env.example                # Environment variables template
│
├── modules/                    # Basic modules (20)
│   ├── geoip.py
│   ├── port_scanner.py
│   ├── vuln_scanner.py
│   └── ...
│
├── modules/redteam/            # Red Team modules (20)
│   └── complete_redteam.py
│
├── utils/                      # Shared utilities
│   ├── colors.py
│   ├── logger.py
│   ├── validator.py
│   └── reporter.py
│
├── data/wordlists/             # Wordlists for bruteforce/enumeration
├── reports/                    # Generated scan reports
├── logs/                       # Execution logs
└── docs/                       # Technical documentation
```

---

## 🔑 API Keys (Optional)

Some modules support external API enrichment. Add your keys to `.env`:

```env
SHODAN_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
CENSYS_API_KEY=your_key_here
SECURITYTRAILS_API_KEY=your_key_here
```

---

##  Academic Context

This project was developed as a **Final Year Project (TFG)** in Cybersecurity. It was designed following industry-standard frameworks and methodologies:

| Framework | Application |
|-----------|-------------|
| [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) | Web vulnerability testing |
| [MITRE ATT&CK](https://attack.mitre.org/) | Red Team tactics & techniques |
| [PTES](http://www.pentest-standard.org/) | Penetration testing methodology |
| [NIST CSF](https://www.nist.gov/cyberframework) | Security assessment structure |

---

##  Contributing

Contributions are welcome! Please follow these steps:

1. Fork the project
2. Create your branch (`git checkout -b feature/NewFeature`)
3. Commit your changes (`git commit -m 'Add: new feature'`)
4. Push to the branch (`git push origin feature/NewFeature`)
5. Open a Pull Request

---

##  License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

---

##  Author

**Izán Jiménez Nuñez**  
Final Year Project · 2025–2026  
GitHub: [@nemoDev0x](https://github.com/nemoDev0x)  


---

##  Acknowledgements

- My TFG supervisors for their guidance
- The open-source cybersecurity community
- Contributors of all libraries used in this project

---

## 💙 Support GhostTrack

GhostTrack is free and open source. If it has been useful to you, consider supporting its development.

| Platform | Link | Notes |
|----------|------|-------|
| ☕ Ko-fi | [ko-fi.com/tu_usuario](https://ko-fi.com/tu_usuario) | One-time or monthly donation |
| 💖 GitHub Sponsors | [github.com/sponsors/nemoDev0x](https://github.com/sponsors/nemoDev0x) | Recurring support via GitHub |
| 🎨 Patreon | [patreon.com/nemoDev0x](https://patreon.com/nemoDev0x?utm_medium=unknown&utm_source=join_link&utm_campaign=creatorshare_creator&utm_content=copyLink) | Monthly tiers with perks |
| ₿ Bitcoin (BTC) | `bc1q...tu_dirección` | Crypto — paste your wallet |
| Ξ Ethereum (ETH) | `0x...tu_dirección` | Crypto — paste your wallet |

> Every contribution — however small — helps maintain and improve GhostTrack. Thank you! 🙏

---

## 🏆 Sponsors

*Become a [Patreon sponsor](https://patreon.com/tu_usuario](https://patreon.com/nemoDev0x?utm_medium=unknown&utm_source=join_link&utm_campaign=creatorshare_creator&utm_content=copyLink)) and your logo appears here.*

---

<div align="center">

**⚠️ Use this tool ethically and responsibly ⚠️**

Made with ❤️ for educational purposes
