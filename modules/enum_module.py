#!/usr/bin/env python3
"""
Ultimate Enumeration Module v5.2
Active enumeration untuk bug bounty hunting
"""

import requests
import socket
import concurrent.futures
import time
import json
from urllib.parse import urljoin, urlparse
import re

class EnumModule:
    def __init__(self, target, verbose=1, timeout=10, threads=20):
        self.target = self.clean_target(target)
        self.domain = self.extract_domain(target)
        self.verbose = verbose
        self.timeout = timeout
        self.threads = threads
        self.results = {
            'directories': [],
            'files': [],
            'parameters': [],
            'endpoints': [],
            'services': [],
            'headers': {},
            'cookies': [],
            'forms': [],
            'api_endpoints': []
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
    
    def run_full_enum(self):
        """Jalankan semua enumeration"""
        self.log("=" * 60, 1)
        self.log(f"🔎 STARTING ENUMERATION: {self.target}", 1)
        self.log("=" * 60, 1)
        
        steps = [
            ("HTTP Headers Analysis", self.analyze_headers),
            ("Directory Enumeration", self.enumerate_directories),
            ("File Discovery", self.discover_files),
            ("Form Detection", self.detect_forms),
            ("API Endpoint Discovery", self.discover_api_endpoints),
            ("Parameter Mining", self.mine_parameters),
            ("Service Fingerprinting", self.fingerprint_services)
        ]
        
        for step_name, step_func in steps:
            try:
                self.log(f"\n[+] {step_name}...", 1)
                step_func()
            except Exception as e:
                self.log(f"[-] Error in {step_name}: {str(e)}", 1)
        
        return self.results
    
    def analyze_headers(self):
        """Analyze HTTP headers untuk security info"""
        try:
            self.log(f"  → Sending HTTP request...", 2)
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(self.target, headers=headers, timeout=self.timeout, verify=False)
            
            # Store semua headers
            self.results['headers'] = dict(response.headers)
            
            # Check security headers
            security_headers = {
                'Strict-Transport-Security': 'HSTS',
                'X-Frame-Options': 'Clickjacking Protection',
                'X-Content-Type-Options': 'MIME Sniffing Protection',
                'Content-Security-Policy': 'CSP',
                'X-XSS-Protection': 'XSS Protection'
            }
            
            self.log(f"  → Security Headers Check:", 2)
            for header, desc in security_headers.items():
                if header in response.headers:
                    self.log(f"    ✓ {desc}: {response.headers[header]}", 2)
                else:
                    self.log(f"    ✗ {desc}: MISSING (Potential vulnerability)", 2)
            
            # Check cookies
            if response.cookies:
                self.log(f"\n  → Cookies Found:", 2)
                for cookie in response.cookies:
                    cookie_info = {
                        'name': cookie.name,
                        'value': cookie.value[:20] + '...' if len(cookie.value) > 20 else cookie.value,
                        'secure': cookie.secure,
                        'httponly': cookie.has_nonstandard_attr('HttpOnly')
                    }
                    self.results['cookies'].append(cookie_info)
                    self.log(f"    • {cookie.name}: Secure={cookie.secure}, HttpOnly={cookie.has_nonstandard_attr('HttpOnly')}", 3)
                    
        except Exception as e:
            self.log(f"    ✗ Header analysis failed: {str(e)}", 2)
    
    def enumerate_directories(self):
        """Gobuster-style directory enumeration"""
        common_dirs = [
            'admin', 'administrator', 'login', 'dashboard', 'panel', 'cpanel',
            'wp-admin', 'wp-content', 'wp-includes', 'api', 'v1', 'v2',
            'backup', 'backups', 'old', 'test', 'dev', 'staging', 'demo',
            'assets', 'static', 'images', 'img', 'css', 'js', 'uploads',
            'files', 'download', 'downloads', 'temp', 'tmp', 'cache',
            'config', 'conf', 'include', 'inc', 'lib', 'library',
            'private', 'secret', 'hidden', '.git', '.env', '.svn',
            'user', 'users', 'member', 'members', 'profile', 'account',
            'search', 'help', 'support', 'contact', 'about', 'docs'
        ]
        
        self.log(f"  → Testing {len(common_dirs)} common directories...", 2)
        
        def check_directory(directory):
            url = urljoin(self.target + '/', directory)
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
                response = requests.get(url, headers=headers, timeout=self.timeout, 
                                      verify=False, allow_redirects=False)
                
                if response.status_code in [200, 301, 302, 403]:
                    size = len(response.content)
                    return {
                        'url': url,
                        'status': response.status_code,
                        'size': size,
                        'directory': directory
                    }
            except:
                pass
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(check_directory, d) for d in common_dirs]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self.results['directories'].append(result)
                    status_symbol = "✓" if result['status'] == 200 else "⚠"
                    self.log(f"    {status_symbol} [{result['status']}] {result['url']} ({result['size']} bytes)", 2)
        
        self.log(f"\n  ✓ Found {len(self.results['directories'])} accessible directories", 1)
    
    def discover_files(self):
        """FFUF-style file discovery"""
        common_files = [
            'robots.txt', 'sitemap.xml', 'security.txt', '.htaccess', '.htpasswd',
            'phpinfo.php', 'info.php', 'test.php', 'config.php', 'database.php',
            'README.md', 'README.txt', 'CHANGELOG.md', 'LICENSE',
            'composer.json', 'package.json', 'yarn.lock', 'package-lock.json',
            '.env', '.env.local', '.env.production', 'config.json', 'settings.json',
            'backup.zip', 'backup.tar.gz', 'database.sql', 'dump.sql',
            'error_log', 'access_log', 'debug.log', 'app.log',
            'swagger.json', 'openapi.json', 'api-docs', 'graphql'
        ]
        
        self.log(f"  → Testing {len(common_files)} common files...", 2)
        
        def check_file(filename):
            url = urljoin(self.target + '/', filename)
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                }
                response = requests.get(url, headers=headers, timeout=self.timeout, 
                                      verify=False, allow_redirects=False)
                
                if response.status_code == 200:
                    size = len(response.content)
                    return {
                        'url': url,
                        'status': response.status_code,
                        'size': size,
                        'filename': filename,
                        'content_type': response.headers.get('Content-Type', 'Unknown')
                    }
            except:
                pass
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(check_file, f) for f in common_files]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self.results['files'].append(result)
                    self.log(f"    ✓ [{result['status']}] {result['url']} ({result['size']} bytes, {result['content_type']})", 2)
        
        self.log(f"\n  ✓ Found {len(self.results['files'])} accessible files", 1)
    
    def detect_forms(self):
        """Detect HTML forms untuk parameter testing"""
        try:
            self.log(f"  → Analyzing HTML forms...", 2)
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(self.target, headers=headers, timeout=self.timeout, verify=False)
            
            # Simple regex untuk form detection
            form_pattern = r'<form[^>]*>(.*?)</form>'
            forms = re.findall(form_pattern, response.text, re.DOTALL | re.IGNORECASE)
            
            for i, form in enumerate(forms, 1):
                # Extract method
                method_match = re.search(r'method=["\']([^"\']+)["\']', form, re.IGNORECASE)
                method = method_match.group(1).upper() if method_match else 'GET'
                
                # Extract action
                action_match = re.search(r'action=["\']([^"\']+)["\']', form, re.IGNORECASE)
                action = action_match.group(1) if action_match else self.target
                
                # Extract input fields
                input_pattern = r'<input[^>]*name=["\']([^"\']+)["\']'
                inputs = re.findall(input_pattern, form, re.IGNORECASE)
                
                form_info = {
                    'id': i,
                    'method': method,
                    'action': action,
                    'inputs': inputs
                }
                
                self.results['forms'].append(form_info)
                self.log(f"    ✓ Form #{i}: {method} {action}", 2)
                self.log(f"      Inputs: {', '.join(inputs)}", 3)
            
            self.log(f"\n  ✓ Found {len(forms)} HTML forms", 1)
            
        except Exception as e:
            self.log(f"    ✗ Form detection failed: {str(e)}", 2)
    
    def discover_api_endpoints(self):
        """Discover API endpoints"""
        api_paths = [
            '/api', '/api/v1', '/api/v2', '/api/v3',
            '/rest', '/rest/v1', '/graphql',
            '/api/users', '/api/auth', '/api/login',
            '/api/config', '/api/status', '/api/health',
            '/api/docs', '/api/swagger', '/api/openapi',
            '/v1/users', '/v1/auth', '/v2/users',
            '/rest/api', '/rest/v1/api'
        ]
        
        self.log(f"  → Testing {len(api_paths)} API endpoints...", 2)
        
        def check_api(path):
            url = urljoin(self.target, path)
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'Accept': 'application/json'
                }
                response = requests.get(url, headers=headers, timeout=self.timeout, 
                                      verify=False, allow_redirects=False)
                
                if response.status_code in [200, 401, 403]:
                    content_type = response.headers.get('Content-Type', '')
                    is_json = 'application/json' in content_type
                    
                    return {
                        'url': url,
                        'status': response.status_code,
                        'is_json': is_json,
                        'content_type': content_type
                    }
            except:
                pass
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(check_api, p) for p in api_paths]
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self.results['api_endpoints'].append(result)
                    json_indicator = " [JSON]" if result['is_json'] else ""
                    self.log(f"    ✓ [{result['status']}] {result['url']}{json_indicator}", 2)
        
        self.log(f"\n  ✓ Found {len(self.results['api_endpoints'])} API endpoints", 1)
    
    def mine_parameters(self):
        """Mine parameters dari HTML & JS files"""
        try:
            self.log(f"  → Mining parameters from HTML...", 2)
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(self.target, headers=headers, timeout=self.timeout, verify=False)
            
            # Extract dari URL parameters
            url_param_pattern = r'[?&]([^=&]+)='
            url_params = set(re.findall(url_param_pattern, response.text))
            
            # Extract dari JavaScript variables
            js_param_pattern = r'var\s+([a-zA-Z_$][a-zA-Z0-9_$]*)\s*='
            js_params = set(re.findall(js_param_pattern, response.text))
            
            # Extract dari data attributes
            data_attr_pattern = r'data-([a-zA-Z-]+)'
            data_params = set(re.findall(data_attr_pattern, response.text))
            
            all_params = url_params | js_params | data_params
            
            # Filter common/interesting parameters
            interesting_keywords = ['user', 'id', 'key', 'token', 'auth', 'api', 
                                   'admin', 'password', 'secret', 'config', 'file',
                                   'path', 'url', 'redirect', 'callback', 'next']
            
            for param in all_params:
                param_lower = param.lower()
                if any(keyword in param_lower for keyword in interesting_keywords):
                    self.results['parameters'].append(param)
                    self.log(f"    ✓ Interesting parameter: {param}", 2)
            
            self.log(f"\n  ✓ Found {len(self.results['parameters'])} interesting parameters", 1)
            
        except Exception as e:
            self.log(f"    ✗ Parameter mining failed: {str(e)}", 2)
    
    def fingerprint_services(self):
        """Fingerprint running services & versions"""
        try:
            self.log(f"  → Fingerprinting services...", 2)
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(self.target, headers=headers, timeout=self.timeout, verify=False)
            
            services = []
            
            # Dari headers
            if 'Server' in response.headers:
                services.append({
                    'type': 'Web Server',
                    'name': response.headers['Server'],
                    'source': 'HTTP Header'
                })
                self.log(f"    ✓ Server: {response.headers['Server']}", 2)
            
            if 'X-Powered-By' in response.headers:
                services.append({
                    'type': 'Backend',
                    'name': response.headers['X-Powered-By'],
                    'source': 'HTTP Header'
                })
                self.log(f"    ✓ Powered By: {response.headers['X-Powered-By']}", 2)
            
            # Detect dari content
            content = response.text.lower()
            
            signatures = {
                'Apache': r'apache[/\s]*([\d.]+)',
                'nginx': r'nginx[/\s]*([\d.]+)',
                'PHP': r'php[/\s]*([\d.]+)',
                'WordPress': r'wp-content.*version["\s]*([\d.]+)',
                'jQuery': r'jquery[/-]*([\d.]+)',
            }
            
            for service, pattern in signatures.items():
                match = re.search(pattern, content, re.IGNORECASE)
                if match:
                    version = match.group(1) if match.lastindex else 'Unknown'
                    services.append({
                        'type': 'Service',
                        'name': f"{service} {version}",
                        'source': 'Content Analysis'
                    })
                    self.log(f"    ✓ Detected: {service} {version}", 2)
            
            self.results['services'] = services
            
        except Exception as e:
            self.log(f"    ✗ Service fingerprinting failed: {str(e)}", 2)
    
    def generate_report(self):
        """Generate enumeration report"""
        report = []
        report.append("\n" + "=" * 60)
        report.append(f"ENUMERATION REPORT: {self.target}")
        report.append("=" * 60)
        
        report.append(f"\n📊 SUMMARY:")
        report.append(f"  • Directories Found: {len(self.results['directories'])}")
        report.append(f"  • Files Found: {len(self.results['files'])}")
        report.append(f"  • Forms Detected: {len(self.results['forms'])}")
        report.append(f"  • API Endpoints: {len(self.results['api_endpoints'])}")
        report.append(f"  • Parameters: {len(self.results['parameters'])}")
        report.append(f"  • Services: {len(self.results['services'])}")
        
        if self.results['directories']:
            report.append(f"\n📁 DIRECTORIES ({len(self.results['directories'])}):")
            for d in self.results['directories'][:15]:
                report.append(f"  • [{d['status']}] {d['url']}")
        
        if self.results['files']:
            report.append(f"\n📄 FILES ({len(self.results['files'])}):")
            for f in self.results['files'][:15]:
                report.append(f"  • [{f['status']}] {f['filename']} ({f['size']} bytes)")
        
        if self.results['forms']:
            report.append(f"\n📝 FORMS ({len(self.results['forms'])}):")
            for form in self.results['forms']:
                report.append(f"  • Form #{form['id']}: {form['method']} {form['action']}")
                report.append(f"    Inputs: {', '.join(form['inputs'])}")
        
        if self.results['api_endpoints']:
            report.append(f"\n🔌 API ENDPOINTS ({len(self.results['api_endpoints'])}):")
            for api in self.results['api_endpoints']:
                json_tag = " [JSON]" if api['is_json'] else ""
                report.append(f"  • [{api['status']}] {api['url']}{json_tag}")
        
        if self.results['parameters']:
            report.append(f"\n🔑 INTERESTING PARAMETERS ({len(self.results['parameters'])}):")
            for param in self.results['parameters'][:20]:
                report.append(f"  • {param}")
        
        if self.results['services']:
            report.append(f"\n⚙️  SERVICES DETECTED:")
            for svc in self.results['services']:
                report.append(f"  • {svc['type']}: {svc['name']} (from {svc['source']})")
        
        report.append("\n" + "=" * 60)
        report.append("✓ Enumeration Complete!")
        report.append("=" * 60 + "\n")
        
        return "\n".join(report)


if __name__ == "__main__":
    import sys
    import warnings
    warnings.filterwarnings('ignore')
    
    if len(sys.argv) < 2:
        print("Usage: python3 enum_module.py <target> [verbose_level] [threads]")
        print("Example: python3 enum_module.py https://example.com 2 20")
        sys.exit(1)
    
    target = sys.argv[1]
    verbose = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    threads = int(sys.argv[3]) if len(sys.argv) > 3 else 20
    
    enum = EnumModule(target, verbose=verbose, threads=threads)
    results = enum.run_full_enum()
    print(enum.generate_report())
