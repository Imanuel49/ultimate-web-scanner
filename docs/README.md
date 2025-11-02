# 🔒 Professional Web Vulnerability Scanner v3.5

## Scanner Keamanan Web Profesional - Lengkap untuk Semua Website

Scanner ini adalah **tool profesional** untuk mendeteksi kerentanan keamanan di **SEMUA JENIS WEBSITE** (bukan hanya GitHub Repository).

---

## ✨ Fitur Lengkap (50+ Vulnerability Types)

### 🎯 v1.0.0 - Core Vulnerabilities

#### Injection Attacks
- ✅ **SQL Injection** (Error-based, Blind, Time-based, Union-based, Stacked queries)
- ✅ **Cross-Site Scripting (XSS)** (Reflected, Stored, DOM-based, All contexts)
- ✅ **Command Injection** (OS Command execution, Shell injection)
- ✅ **LDAP Injection** (LDAP query manipulation)
- ✅ **XML Injection** (XML structure manipulation)

#### File & Path Vulnerabilities
- ✅ **Local File Inclusion (LFI)** (Read local files, PHP wrappers)
- ✅ **Remote File Inclusion (RFI)** (Include remote files)
- ✅ **Path Traversal** (Directory traversal, File access)

#### Server-Side Attacks
- ✅ **SSRF (Server-Side Request Forgery)** (Internal network access)
- ✅ **XXE (XML External Entity)** (XML parser attacks)
- ✅ **Server-Side Template Injection (SSTI)** (Template engine exploitation)
- ✅ **Insecure Deserialization** (Object injection)

#### Web Application Attacks
- ✅ **CSRF (Cross-Site Request Forgery)** (State-changing requests)
- ✅ **Open Redirect** (Phishing via redirects)
- ✅ **CRLF Injection** (HTTP header injection)
- ✅ **Host Header Injection** (Host header manipulation)

#### Security Configuration
- ✅ **CORS Misconfiguration** (Cross-origin policy issues)
- ✅ **Security Headers Analysis** (Missing/weak headers)
- ✅ **SSL/TLS Check** (HTTPS implementation)
- ✅ **Sensitive Data Exposure** (Exposed files, configs)
- ✅ **Information Disclosure** (Debug info, error messages)

---

### 🚀 v1.1.0 - Advanced Modules

#### API Security Testing (OWASP API Top 10 2023)
- ✅ Broken Object Level Authorization (BOLA)
- ✅ Broken Authentication
- ✅ Broken Object Property Level Authorization
- ✅ Unrestricted Resource Consumption
- ✅ Broken Function Level Authorization
- ✅ Unrestricted Access to Sensitive Business Flows
- ✅ Server Side Request Forgery (SSRF)
- ✅ Security Misconfiguration
- ✅ Improper Inventory Management
- ✅ Unsafe Consumption of APIs

#### GraphQL Security
- ✅ **Introspection Enabled** (Schema discovery)
- ✅ **Depth Limit Bypass** (Nested query attacks)
- ✅ **Batch Attack Detection** (Query batching abuse)
- ✅ **Field Suggestion** (Error-based enumeration)
- ✅ **Authorization Issues** (Access control)

#### Business Logic Flaws
- ✅ **Price Manipulation** (E-commerce price bypass)
- ✅ **Workflow Bypass** (Process step skipping)
- ✅ **Race Conditions** (Concurrent request attacks)
- ✅ **Forced Browsing** (Direct object reference)
- ✅ **Parameter Pollution** (HTTP parameter pollution)

#### Authentication Testing
- ✅ **Session Management** (Session fixation, hijacking)
- ✅ **JWT Vulnerabilities** (None algorithm, weak secret)
- ✅ **OAuth Flaws** (Token leakage, CSRF)
- ✅ **MFA Bypass** (2FA circumvention)
- ✅ **Password Policy** (Weak policies)
- ✅ **Default Credentials** (Admin/admin, root/root)
- ✅ **Authentication Bypass** (Login page bypass)

#### File Upload Vulnerabilities
- ✅ **Unrestricted File Upload** (Malicious file upload)
- ✅ **Path Traversal in Upload** (Directory manipulation)
- ✅ **Type Bypass** (MIME type bypass)
- ✅ **Extension Bypass** (File extension tricks)
- ✅ **Content-Type Bypass** (Header manipulation)

---

### 🔥 v1.2.0 - Enterprise Features

#### WebSocket Testing
- ✅ **Origin Validation** (Cross-origin WebSocket hijacking)
- ✅ **Authentication Check** (WebSocket auth bypass)
- ✅ **Message Injection** (WebSocket command injection)
- ✅ **DoS Protection** (Connection flooding)

#### ML-Based Anomaly Detection
- ✅ **Behavioral Analysis** (Abnormal patterns)
- ✅ **Pattern Recognition** (Attack signatures)
- ✅ **Fuzzing Intelligence** (Smart payload generation)
- ✅ **False Positive Reduction** (ML-based filtering)

#### Interactive HTML Reports
- ✅ **Executive Summary** (High-level overview)
- ✅ **Detailed Findings** (Technical details)
- ✅ **Charts & Graphs** (Visual statistics)
- ✅ **Filtering Options** (Severity-based filtering)
- ✅ **Real-time Search** (Quick vulnerability lookup)
- ✅ **Export Options** (PDF, JSON, CSV)

#### Enhanced OSINT
- ✅ **Google Dorking** (Advanced search queries)
- ✅ **Breach Databases** (Leaked credentials check)
- ✅ **Certificate Transparency Logs** (SSL cert history)
- ✅ **GitHub Leaks** (Source code exposure)
- ✅ **Pastebin Search** (Data dumps)
- ✅ **DNS Enumeration** (Subdomain discovery)
- ✅ **WHOIS Lookup** (Domain information)

#### Advanced Payload Obfuscation (11+ Techniques)
- ✅ **Case Swapping** (CaSe MiXiNg)
- ✅ **URL Encoding** (Single & Double)
- ✅ **Unicode Encoding** (\u encoding)
- ✅ **Hex Encoding** (\x encoding)
- ✅ **Base64 Encoding** (b64 encoding)
- ✅ **Comment Injection** (/**/  injection)
- ✅ **Null Byte Injection** (%00)
- ✅ **Tab/Newline Insertion** (Whitespace manipulation)
- ✅ **Concatenation** (String splitting)
- ✅ **Alternative Encodings** (UTF-7, UTF-8 variations)
- ✅ **Mixed Techniques** (Combination attacks)

---

### 🎯 v1.3.0 - Additional Vulnerabilities

#### More Injection Types
- ✅ **NoSQL Injection** (MongoDB, CouchDB)
- ✅ **Expression Language Injection** (EL injection)
- ✅ **Object Injection** (PHP object injection)
- ✅ **Code Injection** (Eval injection)

#### Additional Web Vulnerabilities
- ✅ **Clickjacking** (UI redressing)
- ✅ **DOM-based Vulnerabilities** (DOM XSS)
- ✅ **WebSocket Hijacking** (WS CSRF)
- ✅ **Prototype Pollution** (JavaScript prototype)

#### Mobile & API Specific
- ✅ **Mass Assignment** (Parameter binding)
- ✅ **API Rate Limiting** (DoS protection)
- ✅ **Version Detection** (API versioning)

---

## 📖 Instalasi

### Untuk Termux:

```bash
# Install dependencies
pkg update && pkg upgrade -y
pkg install python -y
pip install requests beautifulsoup4 lxml urllib3

# Download scanner
# (download professional_scanner.py)

# Jalankan
python professional_scanner.py https://target.com
```

### Untuk Linux/Ubuntu:

```bash
# Install dependencies
sudo apt update
sudo apt install python3 python3-pip -y
pip3 install requests beautifulsoup4 lxml urllib3

# Download scanner
# (download professional_scanner.py)

chmod +x professional_scanner.py
python3 professional_scanner.py https://target.com
```

---

## 🚀 Cara Penggunaan

### Mode Scan

#### 1. Scan Normal (Cepat)
```bash
python professional_scanner.py https://target-website.com
```
- Test kerentanan umum
- Waktu: 5-10 menit
- Cocok untuk quick check

#### 2. Full Scan (Lengkap)
```bash
python professional_scanner.py https://target-website.com --full-scan
```
- Test semua vulnerability types
- Waktu: 15-30 menit
- Comprehensive testing

#### 3. Aggressive Mode (Sangat Detail)
```bash
python professional_scanner.py https://target-website.com --aggressive
```
- Test dengan banyak payload
- Blind SQL injection testing
- Waktu: 30-60 menit
- ⚠️ Bisa terdeteksi WAF/IDS

#### 4. dengan OSINT
```bash
python professional_scanner.py https://target-website.com --osint
```
- Includes Google dorking
- Breach database check
- GitHub leak detection

### Kombinasi Mode

```bash
# Full scan + OSINT
python professional_scanner.py https://target.com --full-scan --osint

# Aggressive + OSINT
python professional_scanner.py https://target.com --aggressive --osint

# Custom timeout
python professional_scanner.py https://target.com --timeout 15
```

---

## 📊 Output & Laporan

### Console Output

```
╔══════════════════════════════════════════════════════════════════════╗
║     🔒 PROFESSIONAL WEB VULNERABILITY SCANNER v3.5                  ║
║              Complete Security Testing Suite                        ║
╚══════════════════════════════════════════════════════════════════════╝

Target: https://target-website.com
Started: 2025-11-02 20:30:15
Scan Mode: Normal

[*] Initializing comprehensive security scan...

======================================================================
[PHASE 1] INFORMATION GATHERING & RECONNAISSANCE
======================================================================

  [+] Crawling target website...
    [✓] Found 25 URLs
  [+] Detecting technologies...
    [✓] Technology fingerprinting complete
  [+] Finding endpoints...
  [+] Discovering APIs...
  [+] Finding GraphQL...
  [+] Detecting WebSockets...

======================================================================
[PHASE 2] INJECTION VULNERABILITY TESTING
======================================================================

  [+] Testing SQL Injection (Error, Blind, Time-based)
    [!] SQL Injection (Error) found: id
  [+] Testing XSS (All Contexts)
    [!] XSS (HTML) found: search
  [+] Testing Command Injection
  [+] Testing LDAP Injection
  [+] Testing XML Injection
  [+] Testing Server-Side Template Injection (SSTI)
  [+] Testing CRLF Injection

======================================================================
[PHASE 3] ADVANCED VULNERABILITY TESTING
======================================================================

  [+] Testing Local File Inclusion (LFI)
    [!] LFI found: file
  [+] Testing Remote File Inclusion (RFI)
  [+] Testing SSRF
  [+] Testing XXE
  [+] Testing Path Traversal
  [+] Testing File Upload
  [+] Testing Insecure Deserialization
  [+] Testing Host Header Injection

======================================================================
[PHASE 4] API & GRAPHQL SECURITY TESTING
======================================================================

  [+] Testing API Security (OWASP API Top 10)
  [+] Testing GraphQL Security
  [+] Testing Business Logic Flaws

======================================================================
[PHASE 5] AUTHENTICATION & SESSION SECURITY
======================================================================

  [+] Testing Authentication Bypass
  [+] Testing JWT Vulnerabilities
  [+] Testing Session Management
  [+] Testing CSRF
  [+] Testing Broken Authentication

======================================================================
[PHASE 6] CONFIGURATION & SECURITY ANALYSIS
======================================================================

  [+] Checking Security Headers
    [!] Missing 3 security headers
  [+] Checking SSL/TLS
    [✓] HTTPS enabled
  [+] Checking CORS
  [+] Checking Sensitive Files
    [!] Sensitive file found: /.env
  [+] Testing Open Redirect
  [+] Checking Information Disclosure

======================================================================
GENERATING PROFESSIONAL REPORTS
======================================================================

Critical: 3
High: 5
Medium: 7
Low: 4

Total: 19

[✓] JSON Report: scan_report_target-website.com_1730569815.json
[✓] HTML Report: scan_report_target-website.com_1730569815.html
```

### JSON Report

```json
{
  "scan_info": {
    "target": "https://target-website.com",
    "scan_date": "2025-11-02T20:30:15",
    "scanner_version": "3.5.0",
    "scan_duration": "00:15:30"
  },
  "statistics": {
    "total_vulnerabilities": 19,
    "critical": 3,
    "high": 5,
    "medium": 7,
    "low": 4
  },
  "vulnerabilities": [
    {
      "type": "SQL Injection (Error-based)",
      "severity": "CRITICAL",
      "location": "https://target-website.com/product.php?id=1",
      "details": "Parameter: id, Payload: ' OR '1'='1",
      "evidence": "SQL error detected: mysql",
      "recommendation": "Use parameterized queries/prepared statements",
      "timestamp": "2025-11-02T20:30:25",
      "cve_references": [],
      "risk_score": 9.5
    }
  ]
}
```

### HTML Report

Report HTML interactive dengan:
- Executive summary
- Statistik visual (charts)
- Detailed findings
- Risk scores (CVSS-style)
- Recommendations
- Filtering & search
- Professional styling

---

## 🎯 Target Testing

### ✅ Cocok untuk:

1. **E-commerce Websites**
   - Tokopedia, Shopee, Bukalapak (clone/test)
   - Toko online pribadi
   - Shopping cart systems

2. **Content Management Systems**
   - WordPress blogs
   - Joomla portals
   - Drupal websites

3. **Web Applications**
   - Portal sekolah/kampus
   - Sistem informasi
   - Web apps custom

4. **API Services**
   - REST APIs
   - GraphQL endpoints
   - Microservices

5. **Corporate Websites**
   - Company websites (dengan izin!)
   - Internal portals
   - Intranet systems

### ⚠️ TIDAK cocok/Hati-hati:

- Website bank/finansial (tanpa izin resmi)
- Website pemerintah (illegal!)
- Website militer (illegal!)
- Production systems tanpa maintenance window
- Websites dengan WAF/IDS yang ketat

---

## ⚖️ Legal & Etika - WAJIB DIBACA!

### ✅ BOLEH Scan:

1. **Website milik sendiri**
   - Fully owned by you
   - No restrictions

2. **Website dengan izin tertulis**
   - Written permission from owner
   - Clear scope of testing
   - Documented authorization

3. **Bug Bounty Programs**
   - HackerOne
   - Bugcrowd
   - Synack
   - Company-specific programs

4. **Testing Environments**
   - Dev/Staging servers
   - Local installations
   - Sandboxed environments

### ❌ DILARANG Scan:

1. **Website orang lain tanpa izin**
   - **ILLEGAL!**
   - **Dapat dipenjara!**
   - **Cybercrime Law applies!**

2. **Critical Infrastructure**
   - Banks, hospitals
   - Government systems
   - Military networks
   - Utility services

3. **Without Proper Authorization**
   - No verbal permission
   - No email confirmation
   - Ambiguous permissions

### 🚔 Konsekuensi Hukum

**Indonesia:**
- UU ITE Pasal 30-33
- Hukuman: 6-12 tahun penjara
- Denda: Rp 600 juta - Rp 12 miliar

**International:**
- Computer Fraud and Abuse Act (US)
- Computer Misuse Act (UK)
- Cybercrime laws (各国)

### 💡 Best Practices Etika

1. **Always Get Permission**
   - Written authorization
   - Clear scope
   - Defined timeframe

2. **Responsible Disclosure**
   - Report vulnerabilities privately
   - Give time to fix
   - Don't publish before fix

3. **Don't Cause Damage**
   - No data deletion
   - No DoS attacks
   - No disruption

4. **Document Everything**
   - Keep logs
   - Screenshot evidence
   - Professional reports

5. **Know Your Limits**
   - Don't exceed authorization
   - Follow scope strictly
   - Ask when uncertain

---

## 🔧 Advanced Configuration

### Custom Headers

Edit file scanner, tambahkan:

```python
self.session.headers.update({
    'Authorization': 'Bearer YOUR_TOKEN',
    'Cookie': 'session=YOUR_SESSION',
    'X-Custom-Header': 'value'
})
```

### Proxy Support

```python
self.session.proxies = {
    'http': 'http://proxy:8080',
    'https': 'http://proxy:8080'
}
```

### Rate Limiting

```python
time.sleep(1)  # Add delay between requests
```

### Custom Payloads

Edit `PayloadGenerator` class untuk add custom payloads.

---

## 📚 Vulnerability Severity Guide

### CRITICAL 🔴 (9.0-10.0)
- **Immediate Action Required**
- SQL Injection
- Command Injection
- RCE (Remote Code Execution)
- Authentication Bypass
- Default Credentials

### HIGH 🔴 (7.0-8.9)
- **High Priority Fix**
- XSS (Cross-Site Scripting)
- SSRF
- LFI/RFI
- XXE
- Insecure Deserialization

### MEDIUM 🟡 (4.0-6.9)
- **Should Fix Soon**
- CSRF
- Open Redirect
- CORS Misconfiguration
- Missing CSRF Protection
- Information Disclosure

### LOW 🔵 (0.1-3.9)
- **Recommended to Fix**
- Missing Security Headers
- SSL/TLS Issues
- Information Disclosure (minor)
- Best Practice violations

---

## 🆘 Troubleshooting

### Error: ModuleNotFoundError

```bash
pip install requests beautifulsoup4 lxml urllib3
```

### Error: Connection timeout

```bash
# Increase timeout
python professional_scanner.py https://target.com --timeout 30
```

### Scanner terlalu lambat

```bash
# Use normal mode (not aggressive)
python professional_scanner.py https://target.com
```

### False Positives

```bash
# Verify manually
# Check JSON report for details
# Re-test specific vulnerability
```

### WAF Detection

```bash
# Use stealth techniques:
# 1. Normal mode (not aggressive)
# 2. Add delays
# 3. Use proxy
# 4. Rotate user agents
```

---

## 📞 Support

**Dokumentasi:** README.md (file ini)
**Issues:** Check console output & logs
**Updates:** Check version history

---

## 📄 Changelog

**v3.5.0** (2025-11-02):
- ✅ 50+ vulnerability types
- ✅ Complete OWASP coverage
- ✅ API & GraphQL testing
- ✅ Advanced payloads
- ✅ Professional HTML reports
- ✅ ML-based detection
- ✅ OSINT capabilities

**v3.0.0** (2025-11-01):
- Initial universal scanner
- Core vulnerabilities
- Basic reporting

---

## ⚖️ Disclaimer

**IMPORTANT - READ CAREFULLY:**

This tool is provided for:
- ✅ Educational purposes
- ✅ Authorized security testing
- ✅ Legal bug bounty programs
- ✅ Personal website testing

This tool is NOT for:
- ❌ Illegal hacking
- ❌ Unauthorized access
- ❌ Malicious activities
- ❌ Causing damage

**Developer Disclaimer:**
- Developer is NOT responsible for misuse
- Developer is NOT responsible for damages
- Developer is NOT responsible for legal issues
- User is FULLY responsible for actions

**USE AT YOUR OWN RISK**
**KNOW THE LAW IN YOUR COUNTRY**
**GET PROPER AUTHORIZATION**

---

## 🏆 Credits

**Developed by:** Professional Security Research Team
**Version:** 3.5.0 Professional Edition
**License:** Educational Use Only
**Support:** Community-driven

---

## 🌟 Features Summary

✅ 50+ Vulnerability Types
✅ OWASP Top 10 Coverage
✅ API Security Testing
✅ GraphQL Security
✅ WebSocket Testing
✅ Advanced Payloads
✅ WAF Bypass (11+ techniques)
✅ ML-Based Detection
✅ OSINT Capabilities
✅ Professional Reports (HTML/JSON)
✅ Interactive Dashboard
✅ Real-time Scanning
✅ Comprehensive Logging

---

**Happy Ethical Hacking! 🔒**

*Remember: With great power comes great responsibility!*

**GUNAKAN DENGAN BIJAK DAN BERTANGGUNG JAWAB!**
