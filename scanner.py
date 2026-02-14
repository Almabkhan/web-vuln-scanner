#!/usr/bin/env python3
"""
Web Vulnerability Scanner - Educational Tool
Detects common web vulnerabilities using Python
"""

import requests # type: ignore
import sys
from urllib.parse import urljoin

class WebVulnScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.vulnerabilities = []
        
    def scan_sql_injection(self):
        """Test for SQL Injection vulnerabilities"""
        print("[*] Testing SQL Injection...")
        payloads = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1"]
        
        for payload in payloads:
            test_url = f"{self.target_url}?id={payload}"
            try:
                response = self.session.get(test_url, timeout=5)
                if "sql" in response.text.lower() or "mysql" in response.text.lower():
                    vuln = {
                        "type": "SQL Injection",
                        "url": test_url,
                        "payload": payload,
                        "severity": "Critical"
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"  [!] Possible SQL Injection: {test_url}")
                    break
            except:
                pass
    
    def scan_xss(self):
        """Test for XSS vulnerabilities"""
        print("[*] Testing XSS...")
        payload = "<script>alert('XSS')</script>"
        test_url = f"{self.target_url}?q={payload}"
        
        try:
            response = self.session.get(test_url, timeout=5)
            if payload in response.text:
                vuln = {
                    "type": "XSS (Reflected)",
                    "url": test_url,
                    "payload": payload,
                    "severity": "High"
                }
                self.vulnerabilities.append(vuln)
                print(f"  [!] Possible XSS: {test_url}")
        except:
            pass
    
    def scan_command_injection(self):
        """Test for Command Injection"""
        print("[*] Testing Command Injection...")
        payloads = ["; ls", "| dir", "&& whoami"]
        
        for payload in payloads:
            test_url = f"{self.target_url}?cmd={payload}"
            try:
                response = self.session.get(test_url, timeout=5)
                if "root" in response.text.lower() or "users" in response.text.lower():
                    vuln = {
                        "type": "Command Injection",
                        "url": test_url,
                        "payload": payload,
                        "severity": "Critical"
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"  [!] Possible Command Injection: {test_url}")
                    break
            except:
                pass
    
    def scan_headers(self):
        """Check for missing security headers"""
        print("[*] Checking Security Headers...")
        try:
            response = self.session.get(self.target_url)
            headers = response.headers
            
            security_headers = {
                "X-Frame-Options": "Missing - Clickjacking risk",
                "X-Content-Type-Options": "Missing - MIME sniffing risk",
                "Content-Security-Policy": "Missing - XSS protection weak",
                "Strict-Transport-Security": "Missing - No HSTS"
            }
            
            for header, message in security_headers.items():
                if header not in headers:
                    vuln = {
                        "type": "Missing Security Header",
                        "header": header,
                        "message": message,
                        "severity": "Medium"
                    }
                    self.vulnerabilities.append(vuln)
                    print(f"  [!] {header}: {message}")
        except:
            pass
    
    def run_full_scan(self):
        """Run all scans"""
        print(f"\n{'='*50}")
        print(f"Scanning: {self.target_url}")
        print(f"{'='*50}\n")
        
        self.scan_sql_injection()
        self.scan_xss()
        self.scan_command_injection()
        self.scan_headers()
        
        self.generate_report()
    
    def generate_report(self):
        """Generate scan report"""
        print(f"\n{'='*50}")
        print("SCAN REPORT")
        print(f"{'='*50}")
        
        if not self.vulnerabilities:
            print("\n✅ No vulnerabilities found!")
            return
        
        print(f"\n📊 Found {len(self.vulnerabilities)} issues:\n")
        
        for i, vuln in enumerate(self.vulnerabilities, 1):
            print(f"{i}. [{vuln['severity']}] {vuln['type']}")
            if 'url' in vuln:
                print(f"   URL: {vuln['url']}")
            if 'payload' in vuln:
                print(f"   Payload: {vuln['payload']}")
            if 'header' in vuln:
                print(f"   Header: {vuln['header']}")
                print(f"   Issue: {vuln['message']}")
            print()

def main():
    print("="*50)
    print("WEB VULNERABILITY SCANNER")
    print("Educational Purpose Only")
    print("="*50)
    
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("\nEnter target URL (e.g., http://testphp.vulnweb.com): ").strip()
    
    if not target.startswith("http"):
        target = "http://" + target
    
    scanner = WebVulnScanner(target)
    scanner.run_full_scan()

if __name__ == "__main__":
    main()