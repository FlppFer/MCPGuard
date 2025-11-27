"""
Test script for File Operations attack detection (MCP-DTI-002-FILE-OPS)
Expected findings: File addition, deletion, modification, and retrieval attacks
"""
import os
import shutil
from pathlib import Path

# === File Addition Attacks (III-A1a) ===
def file_addition_attack():
    """Creating malicious files"""
    with open("malicious.py", "w") as f:
        f.write("import os; os.system('whoami')")
    
    Path("backdoor.py").write_text("exec(payload)")
    shutil.copy("malware", "/usr/bin/")
    
    # Shell profile poisoning
    with open(".bashrc", "a") as f:
        f.write("export PATH=/malicious:$PATH")

# === File Deletion Attacks (III-A1b) ===
def file_deletion_attack():
    """Deleting critical files - CRITICAL"""
    os.remove("/important/file.txt")
    os.unlink("critical_data.db")
    os.rmdir("/var/log")
    shutil.rmtree("/home/user/documents")
    
    # Shell command deletion
    os.system("rm -rf /tmp/sensitive")

# === File Modification Attacks (III-A1c) ===
def file_modification_attack():
    """Modifying system files and configs"""
    # MCP config modification
    with open("mcp.json", "r+") as f:
        config = f.read()
    
    os.chmod("/etc/passwd", 0o777)
    os.chown("/root/.ssh", 1000, 1000)
    
    # In-place file editing
    os.system("sed -i 's/password/hacked/' config.txt")

# === File Retrieval Attacks (III-A1d) ===
def file_retrieval_attack():
    """Enumerating and reading sensitive files"""
    import glob
    
    # System file access
    with open("/etc/passwd", "r") as f:
        data = f.read()
    
    # SSH key theft
    ssh_key = open("~/.ssh/id_rsa").read()
    
    # File enumeration
    files = glob.glob("/home/*/.ssh/*")
    
    for root, dirs, files in os.walk("/"):
        print(files)
