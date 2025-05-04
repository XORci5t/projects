# Offensive Security Tools Collection

A collection of tools for CTF competitions and offensive security assessments. This repository contains various utilities designed to assist in reconnaissance, exploitation, and privilege escalation.

## Tools

### Recon

A comprehensive reconnaissance tool for CTF environments. Automates common enumeration tasks for quick information gathering.

- Port scanning with Nmap
- DNS enumeration
- Web server probing
- Directory enumeration
- Report generation

[View Recon Tool](./Recon)

### ReverseShellGenerator

A flexible tool for generating reverse shell payloads in various programming languages with encoding options.

- Supports multiple shell types (Bash, Python, Perl, PHP, PowerShell, etc.)
- Multiple encoding options (Base64, Hex, URL)
- Built-in command for starting a listener

[View Reverse Shell Generator](./ReverseShellGenerator)

### LinuxPrivEscScanner (still in development)

A comprehensive scanner for identifying potential privilege escalation vectors on Linux systems.

- System information enumeration
- User and permission checks
- Configuration analysis
- Network enumeration
- Container escape detection
- Sensitive information discovery

[View Linux Privilege Escalation Scanner](./LinuxPrivEscScanner)

### ECC_Cybergame_exploit

Exploit for the ECC Cybergame challenge, demonstrating an attack on a vulnerable elliptic curve cryptography implementation.

- Exploits a weak curve with small subgroup 
- Implements successful recovery of server's private key
- Decrypts intercepted AES-CBC encrypted messages
- Mathematical approach using elliptic curve operations

The exploit demonstrates practical attacks against insecure ECC implementations by finding the subgroup order and brute-forcing the private key within the subgroup.

[View ECC Exploit](./ECC_Cybergame_exploit)

### RaceCondition_Cybergame_exploit

Exploit for the Race Condition Cybergame challenge, targeting a vulnerability in user registration and authentication flow.

- Exploits timing window between registration and email verification
- Implements multi-threaded requests to achieve successful exploitation
- Bypasses email verification process through race condition
- Gains unauthorized access to user accounts

This exploit demonstrates how race conditions in web applications can be leveraged to bypass security controls by exploiting timing vulnerabilities in critical processes.

[View Race Condition Exploit](./RaceCondition_Cybergame_exploit)

## Disclaimer

These tools are intended for use in authorized CTF competitions and penetration testing environments only. Do not use against systems you don't have permission to test.