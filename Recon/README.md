# CTF Reconnaissance Tool

A comprehensive tool for reconnaissance in Capture The Flag (CTF) environments. This tool automates common enumeration tasks to help you gather information about CTF targets quickly and efficiently.

## Features

- **Port Scanning**: Uses Nmap to discover open ports and services
- **DNS Enumeration**: Checks for various DNS records (A, AAAA, CNAME, MX, NS, TXT, SOA)
- **Web Server Probing**: Identifies web servers and extracts interesting headers
- **Directory Enumeration**: Discovers hidden directories and files using gobuster
- **Report Generation**: Creates a summary report of all findings

## Prerequisites

The tool requires the following dependencies:

- Python 3.6+
- Python packages:
  - requests
  - dnspython
- External tools:
  - nmap
  - dig
  - gobuster

## Installation

1. Clone this repository or download the script
2. Install Python dependencies:

```bash
pip install requests dnspython
```

3. Install external tools:

For Debian/Ubuntu:
```bash
sudo apt-get update
sudo apt-get install nmap dnsutils gobuster
```

For Fedora/RHEL:
```bash
sudo dnf install nmap bind-utils gobuster
```

For Arch Linux:
```bash
sudo pacman -S nmap bind-tools gobuster
```

## Usage

Basic usage:

```bash
python recon.py target.example.com
```

Advanced options:

```bash
python recon.py target.example.com -a -s 4 -w /path/to/wordlist.txt
```

### Options

- `-p, --ports`: Comma-separated list of ports to scan (default: 80,443)
- `-a, --all-ports`: Scan all 65535 ports
- `-s, --speed`: Nmap scan speed (1-5, 5 is fastest)
- `-w, --wordlist`: Wordlist for directory brute force

## Output

The tool creates several output files:

- `nmap_scan_*.txt`: Nmap scan results
- `dns_enum_*.json`: DNS enumeration results
- `webprobe_*_*.json`: Web server probe results
- `gobuster_*_*.txt`: Directory enumeration results
- `recon_report_*.txt`: Summary report

## Disclaimer

This tool is intended for use in CTF environments and authorized penetration testing only. Do not use it against systems you don't have permission to test.
