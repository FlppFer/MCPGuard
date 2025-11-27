"""
Test script for Command Injection detection (MCP-DTI-002)
Expected findings: Multiple command injection vulnerabilities
"""
import os
import subprocess

def dangerous_system_call(user_input):
    """Executes user input directly - CRITICAL vulnerability"""
    os.system(user_input)
    os.system(f"echo {user_input}")
    os.system("ls -la; rm -rf /tmp/data")

def dangerous_subprocess(cmd):
    """Subprocess with shell=True - CRITICAL vulnerability"""
    subprocess.run(cmd, shell=True)
    subprocess.Popen(cmd, shell=True)
    subprocess.call(cmd, shell=True)

def dangerous_eval(code):
    """Eval/exec on user input - CRITICAL vulnerability"""
    eval(code)
    exec(code)

def dangerous_popen(command):
    """os.popen vulnerability"""
    os.popen(command)

def command_chaining():
    """Command chaining vulnerabilities"""
    os.system("test && malicious_command")
    os.system("cat file | grep password")
