# Design — omibao-multilayer-detector v1.0.0

## Architecture

Four-layer static analysis engine with weighted scoring. No network calls, no LLM dependency — runs entirely offline within competition constraints.

### Detection Layers

**Layer 1: Manifest Analysis**
Parses `manifest.json`. Flags suspicious permissions (`execute_command`, `file_system`, `sudo`), URLs pointing to known paste/exfil services, typosquatted dependency names, and path-traversal entry points.

**Layer 2: Pattern Matching (~120 regex rules)**
Covers all 10 OWASP AST categories. Each rule has a severity weight (1–10). Categories covered:
- AST01: command injection, code execution (`os.system`, `subprocess`, `eval`, `exec`)
- AST02: credential theft (`.aws/credentials`, `id_rsa`, env var harvesting)
- AST03: data exfiltration (`requests.post`, `socket`, `smtplib`, webhooks)
- AST04: SSRF/XXE (XML parsing, user-controlled URLs in requests)
- AST05: privilege escalation (`setuid`, `chmod`, Docker socket, cgroups)
- AST06: security misconfiguration (`verify=False`, debug=True, hardcoded secrets)
- AST07: XSS/HTML injection (`innerHTML`, `document.write`, `mark_safe`)
- AST08: insecure deserialization (`pickle.loads`, `yaml.load`, `marshal.loads`)
- AST09: vulnerable dependencies (typosquatting, git+https deps)
- AST10: log suppression (`logging.disable`, `os.remove(*.log)`, `HISTFILE=/dev/null`)

**Layer 3: Entropy Analysis**
Shannon entropy on strings and whole files. Detects base64/hex-encoded payloads and obfuscation keywords.

**Layer 4: Python AST Analysis**
Parses Python code into AST. Detects dangerous call chains (`os.system`, `pickle.loads`, `subprocess.Popen`) with full attribute path resolution. Flags suspicious imports.

### Scoring

Logistic function maps total weighted evidence to 0–100 risk score:
- ≥60 → `malicious`
- ≥25 → `suspicious`
- <25 → `benign`

Primary category = highest-scoring OWASP AST category. Confidence from distance to nearest threshold.

## Resource Profile
- Pure Python stdlib — zero pip dependencies
- Single-pass file scan, no caching needed
- Estimated: ~50ms per skill, ~50KB memory per skill
