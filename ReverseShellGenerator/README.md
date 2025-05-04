# Reverse Shell Generator

A flexible tool for generating reverse shell payloads in various programming languages with encoding options to help bypass security controls.

## Features

- Supports multiple shell types (Bash, Python, Perl, PHP, PowerShell, etc.)
- Customizable IP address and port
- Multiple encoding options (Base64, Hex, URL)
- Built-in command for starting a listener
- Easy-to-use command-line interface

## Installation

1. Clone this repository
2. Make the script executable:
```bash
chmod +x revshell.py
```

## Usage

### List available shells and encodings

```bash
python3 revshell.py -l
```

### Generate a basic reverse shell

```bash
python3 revshell.py -s bash -i 10.0.0.1 -p 4444
```

### Generate an encoded reverse shell

```bash
python3 revshell.py -s powershell -i 10.0.0.1 -p 4444 -e base64 --listener
```

### Available Options

- `-l, --list`: List available shell types and encodings
- `-s, --shell`: Shell type to generate
- `-i, --ip`: IP address for the reverse shell
- `-p, --port`: Port for the reverse shell
- `-e, --encode`: Encoding method to use (default: none)
- `--listener`: Include listener command

## Available Shell Types

- bash: Basic Bash TCP shell
- bash_196: Alternative Bash TCP shell using file descriptor 196
- perl: Perl reverse shell
- python: Python 2 reverse shell
- python3: Python 3 reverse shell
- php: PHP reverse shell
- ruby: Ruby reverse shell
- netcat: Netcat reverse shell with -e option
- ncat: Ncat reverse shell
- powershell: PowerShell reverse shell (automatically base64 encoded)
- awk: AWK reverse shell
- java: Java reverse shell class
- javascript: Node.js reverse shell
- telnet: Telnet reverse shell using named pipes
- golang: Go reverse shell
- socat: Socat reverse shell with PTY

## Available Encodings

- none: No encoding (default)
- base64: Base64 encoding
- hex: Hexadecimal encoding
- url: URL encoding

## Security Considerations

This tool is intended for use in CTF environments and authorized penetration testing only. Do not use it against systems you don't have permission to test. 