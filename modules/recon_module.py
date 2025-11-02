#!/usr/bin/env python3
"""
Ultimate Reconnaissance Module v5.2
Passive information gathering untuk bug bounty hunting
"""

import requests
import socket
import dns.resolver
import ssl
import subprocess
import json
import re
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

class ReconModule:
    def __init__(self, target, verbose=1, timeout=10):
        self.target = self.clean_target(target)
        self.domain = self.extract_domain(target)
        self.verbose = verbose
        self.timeout = timeout
        self.results = {
            'subdomains': [],
            'dns_records': {},
            'emails': [],
            'technologies': [],
            'ip_addresses': [],
            'ports_discovered': [],
            'ssl_info': {},
            'whois_info': {}
        }
        
    def clean_target(self, target):
        """Bersihkan URL target"""
        if not target.startswith(('http://', 'https://')):
            target = 'https://' + target
        return target.rstrip('/')
    
    def extract_domain(self, target):
        """Extract domain dari URL"""
        parsed = urlparse(target)
        return parsed.netloc or parsed.path.split('/')[0]
    
    def log(self, message, level=1):
        """Logging dengan verbose level"""
        if self.verbose >= level:
            timestamp = time.strftime("%H:%M:%S")
            print(f"[{timestamp}] {message}")
    
    def run_full_recon(self):
        """Jalankan semua reconnaissance"""
        self.log("=" * 60, 1)
        self.log(f"🔍 STARTING RECONNAISSANCE: {self.domain}", 1)
        self.log("=" * 60, 1)
        
        steps = [
            ("Subdomain Enumeration", self.enumerate_subdomains),
            ("DNS Records Gathering", self.gather_dns_records),
            ("IP Address Resolution", self.resolve_ips),
            ("SSL/TLS Information", self.gather_ssl_info),
            ("Technology Detection", self.detect_technologies),
            ("Email Harvesting", self.harvest_emails),
            ("Port Discovery", self.quick_port_scan)
        ]
        
        for step_name, step_func in steps:
            try:
                self.log(f"\n[+] {step_name}...", 1)
                step_func()
            except Exception as e:
                self.log(f"[-] Error in {step_name}: {str(e)}", 1)
        
        return self.results
    
    def enumerate_subdomains(self):
        """Subfinder-style subdomain enumeration"""
        subdomains = set()
        
        # Method 1: Certificate Transparency Logs (crt.sh)
        try:
            self.log("  → Checking crt.sh (Certificate Transparency)...", 2)
            url = f"https://crt.sh/?q=%.{self.domain}&output=json"
            response = requests.get(url, timeout=self.timeout)
            if response.status_code == 200:
                certs = response.json()
                for cert in certs:
                    name = cert.get('name_value', '')
                    for subdomain in name.split('\n'):
                        subdomain = subdomain.strip().lower()
                        if subdomain and subdomain.endswith(self.domain):
                            subdomains.add(subdomain)
                self.log(f"    ✓ Found {len(subdomains)} from crt.sh", 2)
        except Exception as e:
            self.log(f"    ✗ crt.sh failed: {str(e)}", 3)
        
        # Method 2: DNS Dumpster
        try:
            self.log("  → Checking DNSDumpster...", 2)
            # Simulasi - dalam produksi bisa pake API DNSDumpster
            common_subs = ['www', 'mail', 'ftp', 'admin', 'api', 'dev', 'staging', 
                          'test', 'blog', 'shop', 'portal', 'dashboard', 'app']
            for sub in common_subs:
                subdomain = f"{sub}.{self.domain}"
                try:
                    socket.gethostbyname(subdomain)
                    subdomains.add(subdomain)
                    self.log(f"    ✓ Found: {subdomain}", 3)
                except:
                    pass
        except Exception as e:
            self.log(f"    ✗ DNSDumpster check failed: {str(e)}", 3)
        
        # Method 3: Common subdomain wordlist
        self.log("  → Brute forcing common subdomains...", 2)
        wordlist = [
            'www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2',
            'smtp', 'secure', 'vpn', 'admin', 'panel', 'api', 'dev', 'staging',
            'test', 'demo', 'beta', 'shop', 'store', 'forum', 'community', 'support',
            'help', 'portal', 'dashboard', 'app', 'mobile', 'cdn', 'static', 'assets',
            'm', 'news', 'wiki', 'docs', 'status', 'login', 'signin', 'signup'
        ]
        
        def check_subdomain(sub):
            subdomain = f"{sub}.{self.domain}"
            try:
                ip = socket.gethostbyname(subdomain)
                self.log(f"    ✓ {subdomain} → {ip}", 3)
                return subdomain, ip
            except:
                return None, None
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in wordlist]
            for future in as_completed(futures):
                subdomain, ip = future.result()
                if subdomain:
                    subdomains.add(subdomain)
                    if ip:
                        self.results['ip_addresses'].append({
                            'host': subdomain,
                            'ip': ip
                        })
        
        self.results['subdomains'] = sorted(list(subdomains))
        self.log(f"\n  ✓ Total subdomains found: {len(subdomains)}", 1)
        
        return subdomains
    
    def gather_dns_records(self):
        """Gather DNS records (A, AAAA, MX, NS, TXT, CNAME)"""
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        
        for record_type in record_types:
            try:
                self.log(f"  → Querying {record_type} records...", 2)
                answers = dns.resolver.resolve(self.domain, record_type)
                records = [str(rdata) for rdata in answers]
                self.results['dns_records'][record_type] = records
                self.log(f"    ✓ Found {len(records)} {record_type} record(s)", 2)
                for record in records:
                    self.log(f"      {record}", 3)
            except dns.resolver.NoAnswer:
                self.log(f"    - No {record_type} records", 3)
            except Exception as e:
                self.log(f"    ✗ {record_type} query failed: {str(e)}", 3)
    
    def resolve_ips(self):
        """Resolve IP addresses untuk target utama"""
        try:
            self.log(f"  → Resolving IP for {self.domain}...", 2)
            ips = socket.gethostbyname_ex(self.domain)[2]
            for ip in ips:
                if not any(item['ip'] == ip for item in self.results['ip_addresses']):
                    self.results['ip_addresses'].append({
                        'host': self.domain,
                        'ip': ip
                    })
                self.log(f"    ✓ {self.domain} → {ip}", 2)
        except Exception as e:
            self.log(f"    ✗ IP resolution failed: {str(e)}", 2)
    
    def gather_ssl_info(self):
        """Gather SSL/TLS certificate information"""
        try:
            self.log(f"  → Gathering SSL/TLS info...", 2)
            context = ssl.create_default_context()
            with socket.create_connection((self.domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    self.results['ssl_info'] = {
                        'subject': dict(x[0] for x in cert.get('subject', [])),
                        'issuer': dict(x[0] for x in cert.get('issuer', [])),
                        'version': cert.get('version'),
                        'notBefore': cert.get('notBefore'),
                        'notAfter': cert.get('notAfter'),
                        'san': cert.get('subjectAltName', [])
                    }
                    
                    self.log(f"    ✓ Issuer: {self.results['ssl_info']['issuer'].get('organizationName', 'N/A')}", 2)
                    self.log(f"    ✓ Valid until: {self.results['ssl_info']['notAfter']}", 2)
                    
                    # Extract SANs untuk subdomain tambahan
                    for san_type, san_value in cert.get('subjectAltName', []):
                        if san_type == 'DNS' and san_value not in self.results['subdomains']:
                            if self.domain in san_value:
                                self.results['subdomains'].append(san_value)
                                self.log(f"    ✓ SAN found: {san_value}", 3)
        except Exception as e:
            self.log(f"    ✗ SSL info gathering failed: {str(e)}", 2)
    
    def detect_technologies(self):
        """Wappalyzer-style technology detection"""
        try:
            self.log(f"  → Detecting technologies...", 2)
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(self.target, headers=headers, timeout=self.timeout, verify=False)
            
            techs = []
            
            # Detect dari headers
            server = response.headers.get('Server', '')
            if server:
                techs.append({'type': 'Web Server', 'name': server})
                self.log(f"    ✓ Server: {server}", 2)
            
            x_powered = response.headers.get('X-Powered-By', '')
            if x_powered:
                techs.append({'type': 'Framework', 'name': x_powered})
                self.log(f"    ✓ Powered by: {x_powered}", 2)
            
            # Detect dari content
            content = response.text.lower()
            
            tech_signatures = {
                'WordPress': ['wp-content', 'wp-includes', 'wordpress'],
                'Joomla': ['joomla', '/components/com_'],
                'Drupal': ['drupal', '/sites/default/'],
                'Laravel': ['laravel', 'csrf-token'],
                'React': ['react', '__react'],
                'Vue.js': ['vue', 'v-if', 'v-for'],
                'Angular': ['angular', 'ng-app'],
                'jQuery': ['jquery', 'jquery.min.js'],
                'Bootstrap': ['bootstrap', 'bootstrap.min.css'],
                'PHP': ['.php', 'phpsessid'],
                'ASP.NET': ['asp.net', '__viewstate'],
                'Node.js': ['node', 'express']
            }
            
            for tech, signatures in tech_signatures.items():
                if any(sig in content for sig in signatures):
                    techs.append({'type': 'Technology', 'name': tech})
                    self.log(f"    ✓ Detected: {tech}", 2)
            
            self.results['technologies'] = techs
            
        except Exception as e:
            self.log(f"    ✗ Technology detection failed: {str(e)}", 2)
    
    def harvest_emails(self):
        """Harvest email addresses dari public sources"""
        try:
            self.log(f"  → Harvesting emails...", 2)
            
            # Method 1: Dari website content
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(self.target, headers=headers, timeout=self.timeout, verify=False)
            
            # Regex untuk email
            email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
            emails = set(re.findall(email_pattern, response.text))
            
            # Filter hanya email dari domain target
            target_emails = [email for email in emails if self.domain in email]
            
            self.results['emails'] = list(target_emails)
            self.log(f"    ✓ Found {len(target_emails)} email(s)", 2)
            for email in target_emails:
                self.log(f"      {email}", 3)
                
        except Exception as e:
            self.log(f"    ✗ Email harvesting failed: {str(e)}", 2)
    
    def quick_port_scan(self):
        """Quick port scan untuk common ports"""
        common_ports = [
            21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
            3306, 3389, 5432, 5900, 8000, 8080, 8443, 8888
        ]
        
        self.log(f"  → Scanning {len(common_ports)} common ports...", 2)
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.domain, port))
                sock.close()
                if result == 0:
                    return port
            except:
                pass
            return None
        
        open_ports = []
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(check_port, port) for port in common_ports]
            for future in as_completed(futures):
                port = future.result()
                if port:
                    open_ports.append(port)
                    self.log(f"    ✓ Port {port} OPEN", 2)
        
        self.results['ports_discovered'] = sorted(open_ports)
        self.log(f"\n  ✓ Total open ports: {len(open_ports)}", 1)
    
    def generate_report(self):
        """Generate reconnaissance report"""
        report = []
        report.append("\n" + "=" * 60)
        report.append(f"RECONNAISSANCE REPORT: {self.domain}")
        report.append("=" * 60)
        
        report.append(f"\n📊 SUMMARY:")
        report.append(f"  • Subdomains Found: {len(self.results['subdomains'])}")
        report.append(f"  • IP Addresses: {len(self.results['ip_addresses'])}")
        report.append(f"  • Open Ports: {len(self.results['ports_discovered'])}")
        report.append(f"  • Technologies: {len(self.results['technologies'])}")
        report.append(f"  • Emails Found: {len(self.results['emails'])}")
        
        if self.results['subdomains']:
            report.append(f"\n🌐 SUBDOMAINS ({len(self.results['subdomains'])}):")
            for sub in self.results['subdomains'][:20]:  # Top 20
                report.append(f"  • {sub}")
            if len(self.results['subdomains']) > 20:
                report.append(f"  ... and {len(self.results['subdomains']) - 20} more")
        
        if self.results['ip_addresses']:
            report.append(f"\n🔢 IP ADDRESSES:")
            for item in self.results['ip_addresses']:
                report.append(f"  • {item['host']} → {item['ip']}")
        
        if self.results['ports_discovered']:
            report.append(f"\n🔓 OPEN PORTS:")
            port_names = {
                21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
                80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
                3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 8080: 'HTTP-Alt'
            }
            for port in self.results['ports_discovered']:
                service = port_names.get(port, 'Unknown')
                report.append(f"  • {port:5d} ({service})")
        
        if self.results['technologies']:
            report.append(f"\n🛠️  TECHNOLOGIES DETECTED:")
            for tech in self.results['technologies']:
                report.append(f"  • {tech['type']}: {tech['name']}")
        
        if self.results['dns_records']:
            report.append(f"\n📝 DNS RECORDS:")
            for record_type, records in self.results['dns_records'].items():
                if records:
                    report.append(f"  • {record_type}: {len(records)} record(s)")
        
        if self.results['ssl_info']:
            report.append(f"\n🔒 SSL/TLS INFO:")
            ssl = self.results['ssl_info']
            if 'issuer' in ssl:
                report.append(f"  • Issuer: {ssl['issuer'].get('organizationName', 'N/A')}")
            if 'notAfter' in ssl:
                report.append(f"  • Valid Until: {ssl['notAfter']}")
        
        if self.results['emails']:
            report.append(f"\n📧 EMAILS FOUND:")
            for email in self.results['emails']:
                report.append(f"  • {email}")
        
        report.append("\n" + "=" * 60)
        report.append("✓ Reconnaissance Complete!")
        report.append("=" * 60 + "\n")
        
        return "\n".join(report)


if __name__ == "__main__":
    import sys
    import warnings
    warnings.filterwarnings('ignore')
    
    if len(sys.argv) < 2:
        print("Usage: python3 recon_module.py <target> [verbose_level]")
        print("Example: python3 recon_module.py example.com 2")
        sys.exit(1)
    
    target = sys.argv[1]
    verbose = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    
    recon = ReconModule(target, verbose=verbose)
    results = recon.run_full_recon()
    print(recon.generate_report())
