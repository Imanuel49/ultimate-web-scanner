# 🚀 Ultimate Web Vulnerability Scanner v5.2 Expert Edition

[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-Production%20Ready-brightgreen.svg)]()
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20MacOS%20%7C%20Windows%20%7C%20Android-lightgrey.svg)]()

> **Complete Bug Bounty Automation Toolkit** - Reconnaissance, Enumeration, dan 70+ Vulnerability Checks dalam satu tool yang powerful!

---

## 📦 Quick Start

```bash
# Clone repository  
git clone https://github.com/Imanuel49/ultimate-web-scanner.git
cd ultimate-web-scanner

# Install dependencies
pip install -r requirements.txt

# Run scanner
python scanner.py -t target.com
```

**⏱️ Total waktu: 2 menit untuk mulai hunting!**

---

## ✨ Fitur Utama v5.2

### 🔍 **Reconnaissance Module**
- ✅ Subdomain Enumeration (crt.sh + DNS brute-force)
- ✅ DNS Records Gathering (A, AAAA, MX, NS, TXT, CNAME, SOA)
- ✅ IP Address Resolution untuk semua hosts
- ✅ SSL/TLS Certificate Analysis + SAN extraction
- ✅ Technology Detection (Wappalyzer-style)
- ✅ Email Harvesting dari public sources
- ✅ Port Scanning (22 common ports)

### 🔎 **Enumeration Module**
- ✅ Directory Enumeration (Gobuster-style, 50+ paths)
- ✅ File Discovery (FFUF-style, 45+ files)
- ✅ Form Detection & Analysis
- ✅ API Endpoint Discovery
- ✅ Parameter Mining dari HTML & JavaScript
- ✅ Service Fingerprinting
- ✅ HTTP Security Headers Analysis

### 🛡️ **Vulnerability Scanner (70+ Checks)**
- SQL Injection (7+ payloads)
- XSS - Cross-Site Scripting (6+ payloads)
- LFI/RFI - Local/Remote File Inclusion
- Command Injection
- SSRF, XXE, CRLF Injection
- Open Redirect
- Security Headers Check

---

## 📊 Scanner Variants

Repository ini menyediakan **8 scanner variants**:

1. **`scanner.py`** ⭐ - Ultimate v5.2 (RECOMMENDED)
2. **`expert_web_scanner.py`** - Expert Web Scanner
3. **`ultimate_scanner_v5.1_expert.py`** - v5.1 Expert
4. **`ultimate_scanner_v5.py`** - v5 Standard
5. **`professional_scanner.py`** - Professional Edition
6. **`expert_validator_v51.py`** - Validator v5.1
7. **`expert_validator_v5.py`** - Validator v5
8. **`test_scanner.py`** - Test Suite

---

## 🎓 Usage

### Basic
```bash
python scanner.py -t target.com              # Full scan
python scanner.py -t target.com -m recon     # Recon only
python scanner.py -t target.com -m enum      # Enum only
python scanner.py -t target.com -m vuln      # Vuln only
```

### Verbose Levels
```bash
python scanner.py -t target.com -v 0    # Silent
python scanner.py -t target.com -v 1    # Normal (default)
python scanner.py -t target.com -v 2    # Verbose
python scanner.py -t target.com -v 3    # Debug
```

### Advanced
```bash
python scanner.py -t target.com -T 50 --timeout 5 -o report.json
```

---

## 📱 Platform Support

- ✅ Linux (Ubuntu, Kali, etc.)
- ✅ MacOS
- ✅ Windows (WSL)
- ✅ Android (Termux) - [Guide](INSTALL_TERMUX.md)
- ✅ Docker

---

## 📚 Documentation

- [QUICKSTART.md](QUICKSTART.md) - 5 minute setup
- [INSTALL_TERMUX.md](INSTALL_TERMUX.md) - Android guide
- Full docs in `/docs/` folder

---

## ⚠️ Legal Notice

**ALWAYS get proper authorization before scanning!**

✅ Authorized: Your systems, bug bounty programs, pentesting with permission
❌ Prohibited: Unauthorized access, illegal activities

Users are 100% responsible for their actions.

---

## 🤝 Contributing

Contributions welcome! Fork, create feature branch, submit PR.

---

## 📝 License

MIT License - See [LICENSE](LICENSE) file

---

## 🎯 Happy Bug Hunting!

**Remember: Always scan ethically and legally!** 🔒

⭐ Star this repo if you find it useful!

