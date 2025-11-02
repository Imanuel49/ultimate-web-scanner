# ⚡ Quick Start Guide - Scanner v5.2

## 🚀 Installation (5 menit)

### Prerequisites
- Python 3.7+
- pip

### Install
```bash
# 1. Extract ZIP
unzip scanner_v5.2_ultimate.zip
cd scanner_v5.2

# 2. Install dependencies
pip install -r requirements.txt

# 3. Test installation
python scanner.py --help
```

## 🎯 Common Use Cases

### 1. Quick Reconnaissance (2-5 menit)
```bash
python scanner.py -t target.com -m recon
```
**Output:** Subdomains, IPs, ports, technologies

### 2. Directory Enumeration (5-10 menit)
```bash
python scanner.py -t https://target.com -m enum -T 30
```
**Output:** Directories, files, forms, API endpoints

### 3. Vulnerability Scan (10-20 menit)
```bash
python scanner.py -t https://target.com -m vuln
```
**Output:** SQL injection, XSS, LFI, RFI, SSRF, etc.

### 4. Full Scan (20-30 menit)
```bash
python scanner.py -t https://target.com -v 2
```
**Output:** Complete recon + enum + vuln scan

## 📊 Verbose Levels

```bash
-v 0    # Silent - hanya hasil akhir
-v 1    # Normal - summary + findings (default)
-v 2    # Verbose - detail progress
-v 3    # Debug - semua request/response
```

## 💡 Pro Tips

### Faster Scans
```bash
# More threads
python scanner.py -t target.com -T 50

# Less timeout
python scanner.py -t target.com --timeout 5
```

### Save Results
```bash
# Export to JSON
python scanner.py -t target.com -o report.json

# Pretty print JSON
cat report.json | python -m json.tool
```

### Bug Bounty Workflow
```bash
# 1. Passive Recon
python scanner.py -t target.com -m recon -v 2 -o recon.json

# 2. Active Enum
python scanner.py -t target.com -m enum -T 40 -o enum.json

# 3. Vuln Discovery
python scanner.py -t target.com -m vuln -o vulns.json
```

## 🔥 One-Liners

```bash
# Quick scan
python scanner.py -t target.com

# Full verbose
python scanner.py -t target.com -v 2

# Fast scan
python scanner.py -t target.com -T 50 --timeout 5

# Save report
python scanner.py -t target.com -o report.json

# Recon only
python scanner.py -t target.com -m recon

# Enum only
python scanner.py -t target.com -m enum

# Vuln only
python scanner.py -t target.com -m vuln
```

## ⚠️ Legal Notice

**ALWAYS get proper authorization before testing!**

✅ Authorized pentesting
✅ Bug bounty programs
✅ Your own systems
✅ Educational purposes

❌ Unauthorized access
❌ Illegal activities

## 📚 Full Documentation

- Complete guide: `README.md`
- Termux install: `INSTALL_TERMUX.md`
- Module docs: `modules/`

## 🆘 Need Help?

```bash
# Show help
python scanner.py --help

# Test modules
python modules/recon_module.py target.com
python modules/enum_module.py target.com
```

---
**Ready to hunt bugs? Let's go! 🎯**
