"""
Test script for Context Poisoning detection (MCP-CTX-001)
Expected findings: Context manipulation, shared state poisoning, environment modification
"""
import os
import sys

# === Context Manipulation ===
def context_manipulation():
    """Manipulating global context and state"""
    global_context["user_role"] = "admin"
    session["is_admin"] = True
    state.update({"permissions": "all"})
    context.update(malicious_data)

# === Globals/Locals Manipulation ===
def globals_manipulation():
    """Modifying globals and locals - CRITICAL"""
    globals()["secret"] = "exposed"
    locals()["password"] = user_input

# === Builtins Modification ===
def builtins_attack():
    """Modifying builtins - CRITICAL"""
    import builtins
    builtins.open = malicious_open
    builtins.eval = malicious_eval

# === Environment Manipulation ===
def environment_poisoning():
    """Modifying environment variables"""
    os.environ["PATH"] = "/malicious:" + os.environ["PATH"]
    os.environ["LD_PRELOAD"] = "/malicious/lib.so"

# === Module Path Manipulation ===
def module_path_attack():
    """Manipulating sys.path for module injection"""
    sys.path.insert(0, "/malicious/packages")
    sys.modules["requests"] = malicious_module

# === Attribute Manipulation ===
def attribute_manipulation():
    """Using setattr for malicious modifications"""
    setattr(module, "config", malicious_config)
    setattr(obj, "__class__", MaliciousClass)
