# MCP Security Rules Taxonomy

This document maps all 31 attack types from the MCP Attack Taxonomy paper (arXiv:2508.12538) to their corresponding detection rules in MCPGuard.

## Attack Categories Overview

| Category | Attack Count | Rule Files |
|----------|-------------|------------|
| I. Direct Tool Injection (III-A) | 14 | tool_poisoning, file_operations, command_injection, remote_attacks, multi_tool_attack |
| II. Indirect Tool Injection (III-B) | 3 | indirect_injection |
| III. Malicious User Attack (III-C) | 7 | malicious_user, privilege_escalation, credential_theft |
| IV. LLM Inherent Attack (III-D) | 6 | llm_attacks |
| **Total** | **31** | |

---

## I. Direct Tool Injection Attack (14 attacks)

### Single Tool Attacks (III-A1) - 8 attacks

| # | Attack | Rule ID | Rule File | Description |
|---|--------|---------|-----------|-------------|
| 1 | File-Based Injection Attack-Addition (III-A1a) | MCP-DTI-002-FILE-OPS-FILE-ADDITION | python_rule_file_operations.go | Detects file write/append operations, shell profile modifications, PATH pollution |
| 2 | File-Based Injection Attack-Deletion (III-A1b) | MCP-DTI-002-FILE-OPS-FILE-DELETION | python_rule_file_operations.go | Detects os.remove, shutil.rmtree, rm -rf commands |
| 3 | File-Based Injection Attack-Modification (III-A1c) | MCP-DTI-002-FILE-OPS-FILE-MODIFICATION | python_rule_file_operations.go | Detects mcp.json access, chmod, chown, in-place edits |
| 4 | File-Based Injection Attack-Retrieval (III-A1d) | MCP-DTI-002-FILE-OPS-FILE-RETRIEVAL | python_rule_file_operations.go | Detects sensitive file reads, /etc/passwd, SSH keys, glob patterns |
| 5 | Rug Pull Attack (III-A1e) | MCP-DTI-001-TOOL-POISON-RUG-PULL | python_rule_tool_poisoning.go | Detects dynamic __doc__ modification, setattr on docstrings |
| 6 | Remote Listener Attack (III-A1f) | MCP-DTI-003-REMOTE-REMOTE-LISTENER | python_rule_remote_attacks.go | Detects netcat listeners, reverse shells, socket servers, pty.spawn |
| 7 | Command Injection Attack (III-A1g) | MCP-DTI-002-CMD-INJECTION | python_rule_command_injection.go | Detects os.system, subprocess with shell=True, eval, exec |
| 8 | Remote Code Execution Attack (III-A1h) | MCP-DTI-003-REMOTE-RCE | python_rule_remote_attacks.go | Detects eval, exec, curl|bash, remote code fetch and execution |

### Multi-Tool Attacks (III-A2) - 6 attacks

| # | Attack | Rule ID | Rule File | Description |
|---|--------|---------|-----------|-------------|
| 9 | Shadowing Attack (III-A2a) | MCP-MTA-001-SHADOWING | python_rule_multi_tool_attack.go | Detects tool call redirection, interception, API path alteration |
| 10 | Malicious Tool Coverage Attack (III-A2b) | MCP-MTA-001-TOOL-COVERAGE | python_rule_multi_tool_attack.go | Detects false deprecation claims, version suffix naming (email_sender_v2) |
| 11 | Tool Preference Manipulation (III-A2b) | MCP-MTA-001-TOOL-PREFERENCE | python_rule_multi_tool_attack.go | Detects "better than", "use this instead", "recommended tool" patterns |
| 12 | Functional Obfuscation Attack (III-A2c) | MCP-MTA-001-FUNCTIONAL-OBFUSCATION | python_rule_multi_tool_attack.go | Detects hidden functionality, ambiguous descriptions, undocumented behavior |
| 13 | Malicious Tool Forced Execution Attack (III-A2d) | MCP-MTA-001-FORCED-EXECUTION | python_rule_multi_tool_attack.go | Detects forced pre-execution, fake security checks, resource exhaustion |
| 14 | Multi-Tool Coordination Attack (III-A2e) | MCP-MTA-001-MULTI-TOOL-COORDINATION | python_rule_multi_tool_attack.go | Detects tool chaining, shared state manipulation, cross-tool variable access |
| 15 | Infectious Attack (III-A2f) | MCP-MTA-001-INFECTIOUS | python_rule_multi_tool_attack.go | Detects tool templates, eval(user_input), tool generation patterns |

---

## II. Indirect Tool Injection Attack (3 attacks)

| # | Attack | Rule ID | Rule File | Description |
|---|--------|---------|-----------|-------------|
| 16 | Webpage Poison Attack (III-B1) | MCP-ITI-001-WEBPAGE-POISON | python_rule_indirect_injection.go | Detects HTML comments, hidden elements, script tags, media captions |
| 17 | Malicious Project Installation Attack (III-B2) | MCP-ITI-001-MALICIOUS-PROJECT | python_rule_indirect_injection.go | Detects pip install from git, curl|bash in README, setup.py cmdclass |
| 18 | MCP Tool Return Attack (III-B3) | MCP-ITI-001-TOOL-RETURN | python_rule_indirect_injection.go | Detects instruction-like returns, hex-encoded returns, tool references in returns |

---

## III. Malicious User Attack (7 attacks)

| # | Attack | Rule ID | Rule File | Description |
|---|--------|---------|-----------|-------------|
| 19 | Malicious Tool Registration Attack (III-C1) | MCP-MUA-002-USER-TOOL-REGISTRATION | python_rule_malicious_user.go | Detects dynamic tool registration, @tool decorators, registry modification |
| 20 | Privilege Escalation (III-C2) | MCP-MUA-001-PRIV-ESC | python_rule_privilege_escalation.go | Detects sudo, setuid, container escape, namespace manipulation |
| 21 | Data Injection on Server (III-C3) | MCP-MUA-002-USER-DATA-INJECTION | python_rule_malicious_user.go | Detects CSV formula injection, XML parsing (XXE), hex-encoded data |
| 22 | Token Theft and Account Takeover (III-C4) | MCP-MUA-002-USER-TOKEN-THEFT | python_rule_malicious_user.go | Detects OAuth token handling, authorization headers, third-party API access |
| 23 | Server Code Leakage (III-C5) | MCP-MUA-002-USER-CODE-LEAKAGE | python_rule_malicious_user.go | Detects path disclosure, traceback exposure, debug mode, inspect.getsource |
| 24 | Installer Spoofing (III-C6) | MCP-MUA-002-USER-INSTALLER-SPOOFING | python_rule_malicious_user.go | Detects mcp-get references, insecure pip index, dynamic pip install |
| 25 | Sandbox Escape (III-C7) | MCP-MUA-001-SANDBOX-ESCAPE | python_rule_privilege_escalation.go | Detects ctypes, /proc/self/mem, Docker socket, ptrace, chroot manipulation |

---

## IV. LLM Inherent Attack (6 attacks)

| # | Attack | Rule ID | Rule File | Description |
|---|--------|---------|-----------|-------------|
| 26 | Jailbreak Attack (III-D1) | MCP-LLM-001-JAILBREAK | python_rule_llm_attacks.go | Detects DAN, role-playing, instruction override, fake mode activation |
| 27 | Prompt Leakage Attack (III-D2) | MCP-LLM-001-PROMPT-LEAKAGE | python_rule_llm_attacks.go | Detects prompt extraction, repetition attacks, training data extraction |
| 28 | Hallucination Attack (III-D3) | MCP-LLM-001-HALLUCINATION | python_rule_llm_attacks.go | Detects fake_database, fabrication instructions, false real-time data claims |
| 29 | Backdoor Attack (III-D4) | MCP-LLM-001-BACKDOOR | python_rule_llm_attacks.go | Detects trigger-based patterns, hidden keywords, string trigger checks |
| 30 | Goal Hijack Attack (III-D5) | MCP-LLM-001-GOAL-HIJACK | python_rule_llm_attacks.go | Detects goal redirection, priority manipulation, malicious link injection |
| 31 | SQL Injection & API Theft Attack (III-D6) | MCP-LLM-001-SQL-INJECTION / MCP-LLM-001-API-THEFT | python_rule_llm_attacks.go | Detects SQL injection patterns, read_config, mcp.json API key access |

---

## Rule Files Summary

| File | Attack Categories Covered | Pattern Count |
|------|--------------------------|---------------|
| `python_rule_tool_poisoning.go` | Rug Pull, Tool Preference | ~10 |
| `python_rule_file_operations.go` | File Addition/Deletion/Modification/Retrieval | ~20 |
| `python_rule_command_injection.go` | Command Injection | ~15 |
| `python_rule_remote_attacks.go` | Remote Listener, RCE | ~25 |
| `python_rule_multi_tool_attack.go` | Shadowing, Coverage, Obfuscation, Forced Exec, Coordination, Infectious | ~30 |
| `python_rule_indirect_injection.go` | Webpage Poison, Malicious Project, Tool Return | ~20 |
| `python_rule_malicious_user.go` | Tool Registration, Data Injection, Token Theft, Code Leakage, Installer Spoofing | ~25 |
| `python_rule_privilege_escalation.go` | Privilege Escalation, Sandbox Escape | ~20 |
| `python_rule_llm_attacks.go` | Jailbreak, Prompt Leakage, Hallucination, Backdoor, Goal Hijack, SQL Injection | ~35 |
| `python_rule_credential_theft.go` | Credential/Token Theft (supplementary) | ~15 |
| `python_rule_context_poisoning.go` | Context Manipulation (supplementary) | ~10 |

---

## Severity Levels

- **CRITICAL**: Immediate exploitation risk, arbitrary code execution, data exfiltration
- **HIGH**: Significant security impact, requires attention
- **MEDIUM**: Potential security concern, context-dependent
- **LOW**: Informational, best practice recommendation

---

## References

- Paper: "Systematic Analysis of MCP Security" (arXiv:2508.12538)
- Authors: Guo et al.
- MCPLIB: MCP Attack Library with 31 attack implementations
