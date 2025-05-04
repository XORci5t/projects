#!/usr/bin/env python3

import argparse
import socket
import subprocess
import sys
import os
import requests
import concurrent.futures
import dns.resolver
from urllib.parse import urlparse
import json
from datetime import datetime

# ANSI color codes
BLUE = '\033[94m'
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
RESET = '\033[0m'
BOLD = '\033[1m'

def check_dependencies():
    """Check if required external tools are installed"""
    tools = ['nmap', 'dig', 'gobuster', 'ffuf']
    missing = []
    
    for tool in tools:
        try:
            subprocess.check_output(['which', tool], stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError:
            missing.append(tool)
    
    if missing:
        print(f"{RED}[!] Missing dependencies: {', '.join(missing)}{RESET}")
        print(f"{YELLOW}Please install them before running this tool.{RESET}")
        sys.exit(1)

def check_host(target):
    """Check if host is up and resolve hostname if needed"""
    try:
        ip = socket.gethostbyname(target)
        print(f"{GREEN}[+] Target {target} resolves to {ip}{RESET}")
        return ip
    except socket.gaierror:
        print(f"{RED}[!] Could not resolve hostname {target}{RESET}")
        return None

def run_port_scan(target, speed=4, all_ports=False):
    """Run nmap scan on target"""
    print(f"\n{BLUE}{BOLD}[*] Running port scan on {target}...{RESET}")
    
    output_file = f"nmap_scan_{target.replace('.', '_')}.txt"
    
    cmd = ['nmap', '-sV', '-sC', f'-T{speed}']
    
    if all_ports:
        cmd.append('-p-')
    
    cmd.extend(['-oN', output_file, target])
    
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        # Print output in real-time
        for line in process.stdout:
            line = line.strip()
            if 'open' in line and 'PORT' not in line:
                print(f"{GREEN}{line}{RESET}")
            elif 'Starting' in line or 'Completed' in line:
                print(f"{BLUE}{line}{RESET}")
            else:
                print(line)
        
        process.wait()
        
        print(f"{GREEN}[+] Port scan completed. Results saved to {output_file}{RESET}")
        return output_file
    except subprocess.CalledProcessError as e:
        print(f"{RED}[!] Error running nmap: {e}{RESET}")
        return None

def run_dns_enum(target):
    """Run DNS enumeration"""
    print(f"\n{BLUE}{BOLD}[*] Running DNS enumeration on {target}...{RESET}")
    
    record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SOA']
    results = {}
    
    for record_type in record_types:
        try:
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(target, record_type)
            
            if record_type not in results:
                results[record_type] = []
            
            for rdata in answers:
                results[record_type].append(str(rdata))
                print(f"{GREEN}[+] {record_type} record found: {rdata}{RESET}")
        
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.DNSException):
            continue
    
    output_file = f"dns_enum_{target.replace('.', '_')}.json"
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=4)
    
    print(f"{GREEN}[+] DNS enumeration completed. Results saved to {output_file}{RESET}")
    return results

def probe_web_server(target, port=80):
    """Probe web server for basic info"""
    protocol = "https" if port == 443 else "http"
    url = f"{protocol}://{target}:{port}"
    
    print(f"\n{BLUE}{BOLD}[*] Probing web server at {url}...{RESET}")
    
    try:
        response = requests.get(url, timeout=10, verify=False)
        server = response.headers.get('Server', 'Unknown')
        headers = dict(response.headers)
        
        print(f"{GREEN}[+] Server: {server}{RESET}")
        print(f"{GREEN}[+] Status code: {response.status_code}{RESET}")
        
        interesting_headers = ['X-Powered-By', 'X-AspNet-Version', 'X-Runtime']
        for header in interesting_headers:
            if header in headers:
                print(f"{GREEN}[+] {header}: {headers[header]}{RESET}")
        
        # Save response headers
        output_file = f"webprobe_{target}_{port}.json"
        with open(output_file, 'w') as f:
            json.dump(headers, f, indent=4)
        
        return headers
    except requests.exceptions.RequestException as e:
        print(f"{RED}[!] Error connecting to web server: {e}{RESET}")
        return None

def directory_bruteforce(target, port=80, wordlist="/usr/share/wordlists/dirb/common.txt"):
    """Run directory brute force using gobuster or ffuf"""
    if not os.path.exists(wordlist):
        print(f"{YELLOW}[!] Wordlist not found: {wordlist}{RESET}")
        print(f"{YELLOW}[!] Skipping directory bruteforce...{RESET}")
        return None
    
    protocol = "https" if port == 443 else "http"
    url = f"{protocol}://{target}:{port}"
    
    print(f"\n{BLUE}{BOLD}[*] Running directory brute force on {url}...{RESET}")
    
    if port == 80:
        output_file = f"ffuf_{target}_{port}.txt"
        fuzzing_url = f"http://{target}/FUZZ"
        
        cmd = [
            'ffuf',
            '-u', fuzzing_url,
            '-w', wordlist,
            '-o', output_file,
            '-s'
        ]
        
        print(f"{GREEN}[+] Using ffuf with URL: {fuzzing_url}{RESET}")
    else:
        output_file = f"gobuster_{target}_{port}.txt"
        
        cmd = [
            'gobuster', 'dir',
            '-u', url,
            '-w', wordlist,
            '-o', output_file,
            '-q'
        ]
    
    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE,
            universal_newlines=True
        )
        
        for line in process.stdout:
            line = line.strip()
            if line:
                print(f"{GREEN}{line}{RESET}")
        
        process.wait()
        
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            print(f"{GREEN}[+] Directory brute force completed. Results saved to {output_file}{RESET}")
            return output_file
        else:
            print(f"{YELLOW}[!] No directories found{RESET}")
            return None
    except subprocess.CalledProcessError as e:
        print(f"{RED}[!] Error running directory bruteforce: {e}{RESET}")
        return None

def create_report(target, scan_results):
    """Create a summary report of all scan results"""
    report_file = f"recon_report_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
    
    with open(report_file, 'w') as f:
        f.write(f"RECONNAISSANCE REPORT FOR {target}\n")
        f.write(f"Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")
        
        f.write("SUMMARY\n")
        f.write("-" * 80 + "\n")
        for scan_type, result in scan_results.items():
            if result:
                f.write(f"{scan_type}: Completed successfully\n")
            else:
                f.write(f"{scan_type}: Failed or no results\n")
        
        f.write("\n")
        f.write("See individual output files for detailed results.\n")
    
    print(f"\n{GREEN}[+] Reconnaissance completed. Report saved to {report_file}{RESET}")
    return report_file

def main():
    parser = argparse.ArgumentParser(description='CTF Reconnaissance Tool')
    parser.add_argument('target', help='Target hostname or IP address')
    parser.add_argument('-p', '--ports', help='Comma-separated list of ports to scan', default='80,443')
    parser.add_argument('-a', '--all-ports', action='store_true', help='Scan all 65535 ports')
    parser.add_argument('-s', '--speed', type=int, choices=range(1, 6), default=4, help='Nmap scan speed (1-5, 5 is fastest)')
    parser.add_argument('-w', '--wordlist', help='Wordlist for directory brute force', default='/usr/share/wordlists/dirb/common.txt')
    
    args = parser.parse_args()
    
    print_banner()
    check_dependencies()
    
    target_ip = check_host(args.target)
    if not target_ip:
        sys.exit(1)
    
    scan_results = {}
    
    # Run nmap scan
    scan_results['port_scan'] = run_port_scan(args.target, speed=args.speed, all_ports=args.all_ports)
    
    # Run DNS enumeration
    scan_results['dns_enum'] = run_dns_enum(args.target)
    
    # Probe web servers
    web_ports = [int(port.strip()) for port in args.ports.split(',')]
    scan_results['web_probe'] = {}
    scan_results['dir_brute'] = {}
    
    for port in web_ports:
        scan_results['web_probe'][port] = probe_web_server(args.target, port)
        scan_results['dir_brute'][port] = directory_bruteforce(args.target, port, args.wordlist)
    
    # Create final report
    create_report(args.target, scan_results)

if __name__ == "__main__":
    # Suppress warnings for unverified HTTPS requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Scan interrupted by user{RESET}")
        sys.exit(0)
