#!/usr/bin/env python3
"""
Track B V44 — Semantic + Behavioral Detection Engine.

Layers:
  1. Keyword matching (V41 proven, DQ=4.23)
  2. Python AST call-chain analysis (semantic)
  3. Cross-file behavioral signatures (data flow patterns)
  4. Manifest-code consistency checking
  5. Structural anomaly detection
  6. Entropy analysis
  7. Attack chain heuristics
"""
import ast, json, math, os, re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

MAX_FILE_BYTES = 120_000
MAX_FILES_PER_SKILL = 80
MAX_TEXT_SCAN = 80_000

# ── Helpers ────────────────────────────────────────────────────────────

def safe_read(fp: Path) -> str:
    try: raw = fp.read_bytes()
    except Exception: return ""
    if not raw: return ""
    if len(raw) > MAX_FILE_BYTES: raw = raw[:MAX_FILE_BYTES]
    if b"\x00" in raw[:512]: return ""
    try: return raw.decode("utf-8")
    except Exception:
        try: return raw.decode("latin-1")
        except Exception: return ""

def entropy(s: str) -> float:
    if not s: return 0.0
    n = len(s); counts = Counter(s)
    try: return -sum((c/n)*math.log2(c/n) for c in counts.values())
    except: return 0.0

TEXT_EXTS = {
    ".py", ".pyw", ".pyx", ".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx",
    ".sh", ".bash", ".zsh", ".fish", ".rb", ".pl", ".pm", ".php",
    ".go", ".rs", ".java", ".kt", ".swift", ".scala",
    ".c", ".cpp", ".h", ".hpp", ".cs",
    ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".env",
    ".html", ".htm", ".css", ".scss", ".less",
    ".md", ".txt", ".rst", ".json", ".xml", ".csv",
    ".ps1", ".bat", ".cmd", ".lua", ".r", ".sql",
}
KNOWN_FILENAMES = {
    "makefile", "dockerfile", "jenkinsfile", "gemfile", "rakefile",
    ".gitignore", ".dockerignore", ".npmrc", ".env.example",
    "skill.md", "skillin.md", "memory.md", "soul.md",
}

# ── Python AST Semantic Analysis ───────────────────────────────────────

class SemanticAnalyzer:
    """AST-based analysis for Python files — detects dangerous call chains."""

    DANGEROUS_FUNCS = {
        "eval", "exec", "compile", "__import__", "open",
        "getattr", "setattr", "delattr", "globals", "locals", "vars",
    }

    SENSITIVE_SOURCES = {
        "os.environ", "os.getenv", "open(", "pathlib.Path",
        "requests.get", "urllib.request.urlopen",
    }

    EXFIL_SINKS = {
        "requests.post", "requests.put", "socket.send", "smtplib.SMTP",
        "subprocess.run", "subprocess.Popen", "os.system", "os.popen",
    }

    def analyze(self, source: str) -> Dict[str, Any]:
        findings: Dict[str, List[Tuple[str, int]]] = {}
        evidence: List[str] = []

        try: tree = ast.parse(source)
        except Exception: return {"findings": findings, "evidence": evidence}

        visitor = _CallChainVisitor(self.DANGEROUS_FUNCS)
        visitor.visit(tree)

        for desc, weight in visitor.findings:
            cat = "AST01"  # default for dangerous calls
            findings.setdefault(cat, []).append((desc, weight))
            if weight >= 5:
                evidence.append(f"AST: {desc}")

        # Data flow analysis
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                chain = self._get_call_chain(node)
                if chain:
                    # Check for source→sink patterns
                    chain_str = ".".join(chain)
                    for src in self.SENSITIVE_SOURCES:
                        if src in source.lower():
                            for sink in self.EXFIL_SINKS:
                                if sink in source.lower():
                                    findings.setdefault("AST03", []).append(
                                        (f"data flow: {src} → {sink}", 6))
                                    evidence.append(f"data flow: sensitive data → exfil")

        return {"findings": findings, "evidence": evidence}

    def _get_call_chain(self, node) -> List[str]:
        parts = []
        cur = node.func if isinstance(node, ast.Call) else node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name): parts.append(cur.id)
        elif isinstance(cur, ast.Call):
            sub = self._get_call_chain(cur)
            parts.extend(sub)
        parts.reverse()
        return parts


class _CallChainVisitor(ast.NodeVisitor):
    def __init__(self, dangerous_funcs):
        self.dangerous = dangerous_funcs
        self.findings: List[Tuple[str, int]] = []

    def visit_Call(self, node):
        if isinstance(node.func, ast.Name) and node.func.id in self.dangerous:
            self.findings.append((f"call {node.func.id}()", 5))
            # Check if args contain non-literal data
            for arg in node.args:
                if not isinstance(arg, ast.Constant):
                    self.findings.append((f"dynamic arg to {node.func.id}()", 7))
                    break
        elif isinstance(node.func, ast.Attribute):
            chain = self._resolve(node.func)
            if chain in {"os.system", "os.popen", "subprocess.call",
                          "subprocess.run", "subprocess.Popen", "subprocess.check_output",
                          "pickle.load", "pickle.loads", "pickle.dump",
                          "yaml.load", "yaml.full_load",
                          "marshal.load", "marshal.loads",
                          "dill.load", "dill.loads",
                          "requests.post", "requests.put",
                          "socket.send", "socket.connect",
                          "urllib.request.urlopen",
                          "shutil.rmtree", "os.remove", "os.unlink"}:
                self.findings.append((f"call {chain}()", 6))

        # Check for shell=True
        for kw in node.keywords:
            if kw.arg == "shell" and getattr(kw.value, 'value', None) is True:
                self.findings.append(("subprocess with shell=True", 8))

        self.generic_visit(node)

    def visit_Import(self, node):
        for a in node.names:
            if a.name in {"pickle", "marshal", "dill", "subprocess", "ctypes", "socket", "smtplib", "ftplib"}:
                self.findings.append((f"import {a.name}", 3))
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        m = node.module or ""
        for a in node.names:
            full = f"{m}.{a.name}"
            if any(x in full for x in ("pickle", "marshal", "dill", "subprocess")):
                self.findings.append((f"import {full}", 4))
        self.generic_visit(node)

    def _resolve(self, node) -> str:
        parts = []
        cur = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name): parts.append(cur.id)
        parts.reverse()
        return ".".join(parts)


# ── Cross-file Behavioral Detection ────────────────────────────────────

class BehavioralDetector:
    """Detects suspicious patterns across multiple files in a skill."""

    def analyze(self, all_files: Dict[str, str]) -> Dict[str, Any]:
        findings: Dict[str, List[Tuple[str, int]]] = {}
        evidence: List[str] = []

        all_text = " ".join(all_files.values()).lower()

        # Pattern 1: File read + encoding + network send (exfiltration kill chain)
        has_read_sensitive = bool(re.search(
            r"/etc/(?:passwd|shadow|hosts|resolv)|\.ssh/|\.aws/|\.env|keychain|credential",
            all_text))
        has_encode = bool(re.search(
            r"base64|b64encode|b64decode|hexlify|\.encode\(|fromhex",
            all_text))
        has_network_send = bool(re.search(
            r"requests\.(?:post|put|send)|socket\.(?:send|connect)|urllib|http\.client|curl\s|wget\s|smtp|ftp|webhook",
            all_text))

        if has_read_sensitive and has_encode and has_network_send:
            findings.setdefault("AST03", []).append(
                ("cross-file exfil chain: read→encode→send", 9))
            evidence.append("behavioral: complete exfiltration kill chain detected")

        # Pattern 2: Persistence mechanism + download capability
        has_persistence = bool(re.search(
            r"bashrc|bash_profile|zshrc|profile|launchd|systemd|crontab|init\.d|startup|autostart",
            all_text))
        has_download = bool(re.search(
            r"curl\s|wget\s|fetch\s|download|urlopen|requests\.get",
            all_text))

        if has_persistence and has_download:
            findings.setdefault("AST01", []).append(
                ("cross-file persistence: config+download", 8))
            evidence.append("behavioral: persistence with remote payload capability")

        # Pattern 3: Obfuscation + code execution
        has_obfuscation = bool(re.search(
            r"base64|b64decode|rot13|zlib|gzip|chr\(\d+\)|\\x[0-9a-f]{2}|\\u[0-9a-f]{4}|fromcharcode|atob\(",
            all_text))
        has_code_exec = bool(re.search(
            r"eval\(|exec\(|subprocess|os\.system|os\.popen|compile\(|__import__\(|function\s*\(",
            all_text))

        if has_obfuscation and has_code_exec:
            findings.setdefault("AST08", []).append(
                ("cross-file: obfuscation+execution", 7))
            evidence.append("behavioral: obfuscated code execution detected")

        # Pattern 4: Environment variable harvesting + network access
        has_env_harvest = bool(re.search(
            r"os\.environ|getenv|env\s*>|printenv|\.env\b|process\.env|environment",
            all_text))
        if has_env_harvest and has_network_send:
            findings.setdefault("AST03", []).append(
                ("cross-file: env harvesting+exfil", 8))
            evidence.append("behavioral: credential harvesting with network exfil")

        # Pattern 5: Shell config modification (persistence)
        has_shell_config_write = bool(re.search(
            r"(?:>>|tee|write|append).*(?:bashrc|profile|zshrc|bash_profile)",
            all_text))
        if has_shell_config_write:
            findings.setdefault("AST06", []).append(
                ("cross-file: shell config modification", 6))
            evidence.append("behavioral: shell persistence via config modification")

        # Pattern 6: Multi-file coordination (main script calls helper scripts)
        py_files = [n for n in all_files if n.endswith('.py')]
        sh_files = [n for n in all_files if n.endswith('.sh')]
        if py_files and sh_files:
            for sh in sh_files:
                sh_content = all_files[sh].lower()
                if "subprocess" in sh_content or "os.system" in sh_content:
                    findings.setdefault("AST01", []).append(
                        ("cross-file: Python calls shell scripts with exec", 7))
                    break

        # Pattern 7: Hidden content in markdown (ClawHavoc technique)
        md_files = [n for n in all_files if n.endswith('.md')]
        for md in md_files:
            content = all_files[md]
            if "<!--" in content and ("curl" in content or "bash" in content or "exec" in content):
                findings.setdefault("AST04", []).append(
                    ("cross-file: hidden commands in markdown comments", 8))
                evidence.append("behavioral: HTML comment injection in markdown")
                break

        # Pattern 8: Prerequisites + IMPORTANT + external URL (ClawHub social engineering)
        # 95% of real malicious skills use this pattern (from HF dataset analysis)
        has_prereq = any("prerequisite" in f.lower() for f in [all_text] + list(all_files.values()))
        has_important = any("important" in f.lower() for f in [all_text] + list(all_files.values()))
        has_external_url = bool(re.search(r'https?://(?!docs\.|github\.com/[\w-]+/[\w-]+$|github\.com/[\w-]+/[\w-]+/blob)', all_text))
        has_dl_exec = any(kw in all_text for kw in ["curl ", "wget ", "bash ", "sh ", "download"])

        if has_prereq and has_important and has_dl_exec:
            findings.setdefault("AST04", []).append(
                ("cross-file: social engineering prerequisite pattern", 9))
            evidence.append("behavioral: Prerequisites+IMPORTANT+download social engineering")

        # Pattern 9: Fake utility installation
        fake_utils = ["openclaw-agent", "openclawcli", "openclawcli.exe", "agent utility",
                      "installer tool", "setup utility", "updater utility"]
        for fu in fake_utils:
            if fu in all_text:
                if has_prereq or has_dl_exec:
                    findings.setdefault("AST01", []).append(
                        (f"cross-file: fake utility '{fu}' with download instruction", 8))
                    evidence.append(f"behavioral: fake utility {fu} social engineering")
                    break

        return {"findings": findings, "evidence": evidence}


# ── Structural Anomaly Detection ───────────────────────────────────────

class StructuralAnalyzer:
    """Detects suspicious file/directory structures."""

    def analyze(self, skill_dir: Path) -> Dict[str, Any]:
        findings: Dict[str, List[Tuple[str, int]]] = {}
        evidence: List[str] = []

        try: all_entries = list(skill_dir.rglob("*"))
        except Exception: return {"findings": findings, "evidence": evidence}

        files = [e for e in all_entries if e.is_file()]
        dirs = [e for e in all_entries if e.is_dir()]

        # Too many hidden files/dirs
        hidden = [f for f in files if f.name.startswith('.')]
        if len(hidden) > len(files) * 0.3 and len(hidden) > 3:
            findings.setdefault("AST08", []).append(
                ("structural: excessive hidden files", 4))
            evidence.append(f"structural: {len(hidden)} hidden files")

        # Suspicious file names
        suspicious_names = {"payload", "exploit", "backdoor", "trojan", "shell",
                            "steal", "exfil", "ransom", "miner", "rat", "c2",
                            "keylog", "inject", "hook", "rootkit"}
        for f in files:
            name_lower = f.name.lower().replace('-','').replace('_','').replace('.','')[:20]
            for sn in suspicious_names:
                if sn in name_lower:
                    findings.setdefault("AST01", []).append(
                        ("structural: suspicious filename", 4))
                    evidence.append(f"structural: suspicious filename '{f.name}'")
                    break

        # Executable files in skill directory
        for f in files:
            try:
                if os.access(str(f), os.X_OK) and f.suffix in ('', '.sh', '.bash', '.py'):
                    findings.setdefault("AST06", []).append(
                        ("structural: executable script", 3))
                    break
            except Exception: pass

        # Large number of script files (potential multi-stage attack)
        script_files = [f for f in files if f.suffix in ('.sh', '.py', '.js', '.rb', '.pl')]
        if len(script_files) > 5:
            findings.setdefault("AST01", []).append(
                ("structural: multi-script deployment", 4))
            evidence.append(f"structural: {len(script_files)} scripts")

        return {"findings": findings, "evidence": evidence}


# ── Manifest-Code Consistency ──────────────────────────────────────────

class ConsistencyChecker:
    """Checks if manifest declarations match actual code behavior."""

    def analyze(self, manifest: dict, code_texts: Dict[str, str]) -> Dict[str, Any]:
        findings: Dict[str, List[Tuple[str, int]]] = {}
        evidence: List[str] = []

        all_code = " ".join(code_texts.values()).lower()

        # Check: manifest claims benign purpose but code has dangerous operations
        desc = str(manifest.get("description", "")).lower()
        benign_keywords = {"cache", "warmer", "optimiz", "helper", "utility", "formatter",
                           "logger", "monitor", "dashboard", "report", "analyzer", "indexer"}
        is_benign_desc = any(bk in desc for bk in benign_keywords)

        if is_benign_desc:
            # Check if code actually does dangerous things
            dangerous_ops = ["os.system", "subprocess", "eval(", "exec(", "pickle",
                             "socket.connect", "requests.post", "webhook", "base64"]
            danger_count = sum(1 for op in dangerous_ops if op in all_code)
            if danger_count >= 2:
                findings.setdefault("AST04", []).append(
                    ("consistency: benign description, dangerous code", 6))
                evidence.append(f"consistency: '{desc[:50]}' hides {danger_count} dangerous ops")

        # Check: declared permissions vs actual operations
        declared_perms = set(str(p).lower().replace(" ","_").replace("-","_")
                            for p in manifest.get("permissions", []))
        actual_ops = set()
        if any(kw in all_code for kw in ["os.system", "subprocess", "exec("]):
            actual_ops.add("run_shell_commands")
        if any(kw in all_code for kw in ["open(", "read(", "write(", "/etc/", ".ssh"]):
            actual_ops.add("read_local_files")
        if any(kw in all_code for kw in ["requests.post", "socket", "webhook", "curl"]):
            actual_ops.add("network_access")

        undeclared = actual_ops - declared_perms
        if undeclared and "run_shell_commands" not in declared_perms and "run_shell_commands" in undeclared:
            findings.setdefault("AST03", []).append(
                ("consistency: undeclared dangerous operations", 7))
            evidence.append("consistency: code executes commands without declaring permission")

        return {"findings": findings, "evidence": evidence}


# ── Main Detection Engine ──────────────────────────────────────────────

sa = SemanticAnalyzer()
bd = BehavioralDetector()
st = StructuralAnalyzer()
cc = ConsistencyChecker()


def scan_skill(sd: Path) -> Dict[str, Any]:
    sid = sd.name
    cat_counts: Dict[str, int] = {}
    all_e: List[str] = []
    detect_extra = 0
    code_texts: Dict[str, str] = {}
    manifest_data: dict = {}

    # ── Layer 1: Manifest analysis ──
    mp = sd / "manifest.json"
    manifest_ok = False
    if mp.is_file():
        mt = safe_read(mp)
        if mt:
            try:
                m = json.loads(mt); manifest_ok = True; manifest_data = m
                perms = m.get("permissions", [])
                if isinstance(perms, list):
                    for p in perms:
                        pn = str(p).lower().replace(" ", "_").replace("-", "_")
                        if pn in {"execute_command","run_shell","shell","file_system","network","admin","sudo","root","all","*","write","delete","process","spawn","fork","full_access","unlimited","unrestricted"}:
                            cat_counts["AST03"] = cat_counts.get("AST03",0)+1
                            all_e.append(f"over-privileged: {p}")
                for field in ("url","homepage","repository","endpoint"):
                    val = str(m.get(field,""))
                    for h in ["pastebin","webhook","ngrok","discord","telegram","transfer.sh","file.io","0x0.st"]:
                        if h in val.lower():
                            cat_counts["AST04"] = cat_counts.get("AST04",0)+1
                deps = m.get("dependencies",{})
                if isinstance(deps,dict):
                    for n,v in deps.items():
                        if isinstance(v,str) and ("latest" in v.lower() or "*" in v or ">" in v):
                            cat_counts["AST07"] = cat_counts.get("AST07",0)+1
            except Exception: pass
    else:
        detect_extra += 3
        cat_counts["AST09"] = cat_counts.get("AST09",0)+1

    # ── Layer 2: Keyword matching (V41 proven) ──
    try: entries = list(sd.rglob("*"))
    except Exception: entries = []

    count = 0
    for fp in entries:
        if count >= MAX_FILES_PER_SKILL: break
        try:
            if not fp.is_file() or fp.is_symlink(): continue
        except Exception: continue
        if fp.name.startswith(".") or fp.name == "manifest.json": continue
        ext = fp.suffix.lower()
        if ext not in TEXT_EXTS and fp.name.lower() not in KNOWN_FILENAMES: continue

        text = safe_read(fp)
        if not text.strip(): continue
        count += 1
        t = text[:MAX_TEXT_SCAN].lower()
        rel = str(fp.relative_to(sd))
        code_texts[rel] = text  # store for behavioral/consistency analysis

        # AST01 keywords
        for kw in ["os.system","os.popen","subprocess.","eval(","exec(","child_process.exec","shell_exec","__import__(","ctypes.","process.spawn","new function(","runtime.getruntime","shellexecute","createprocess","vm.runinnewcontext","shell=true","code.interactiveconsole","code.interactiveinterpreter","globals()","locals()","importlib.import_module(","compile(","execfile(","commands.getoutput","commands.getstatusoutput","dangerouslysetinnerhtml","base64.b64decode","base64.b64encode","bytes.fromhex","codecs.decode"," = exec"," = eval"]:
            if kw in t: cat_counts["AST01"] = cat_counts.get("AST01",0)+1

        # AST02 keywords
        for kw in ["credential","api_key","auth_token","id_rsa",".aws/","keychain","keyring",".netrc","authorization:","access_key","secret_key","private_key","typosquat","colourama","requets","coloramma","git+https://","egg=https://","dependency=http","dependency confusion","registry poison","unpinned","version latest","no hash"]:
            if kw in t: cat_counts["AST02"] = cat_counts.get("AST02",0)+1

        # AST03 keywords
        for kw in ["169.254.169.254","metadata.google.internal","100.100.100.200","/etc/passwd","/etc/shadow","/etc/hosts","env >","/proc/","sendbeacon","requests.post","requests.put","requests.send","urllib.request","socket.connect","socket.send","smtp","ftp","webhook","curl ","wget ","exfiltrat","keylog","password=","secret=","token="]:
            if kw in t: cat_counts["AST03"] = cat_counts.get("AST03",0)+1

        # AST04 keywords
        for kw in ["xml.etree","lxml","<!entity","<!doctype","ssrf","verify=false","debug=true","ssl._create_unverified","check_hostname=false","allow_origin=*","impersonat","fake","spoof","pretend","disguise","masquerade","camouflage","hidden from","do not disclose","secretly","silently"]:
            if kw in t: cat_counts["AST04"] = cat_counts.get("AST04",0)+1

        # AST05 keywords
        for kw in ["pickle.load","pickle.dump","yaml.load","marshal.load","dill.load","deserialize","unserialize","jsonpickle"]:
            if kw in t: cat_counts["AST05"] = cat_counts.get("AST05",0)+1

        # AST06 keywords
        for kw in ["sudo ","chmod ","setuid","setgid","docker.sock","containerd.sock","rootkit","crontab","authorized_keys","systemctl enable","nsenter","cap_sys","chown ","privileged","host network","host pid","mount /","mount --bind","/var/run/","--cap-add"]:
            if kw in t: cat_counts["AST06"] = cat_counts.get("AST06",0)+1

        # AST08 keywords
        for kw in ["logging.disable","logging.shutdown","shutil.rmtree","histfile=/dev/null","history -c","obfuscat","deobfuscat","rot13","rot_13","base64","hexlify","unhexlify","fromhex","zlib","bz2","lzma","gzip","chr(","[::-1]","''.join","unicode_escape","getattr(","__dict__","__subclasses__"]:
            if kw in t: cat_counts["AST08"] = cat_counts.get("AST08",0)+1

        # Detection-only keywords (ClawHavoc/pydepgate/skill-scan)
        for kw in ["ignore previous instructions","you are now","do anything now","jailbreak","developer mode","system prompt","curl | bash","curl | sh","wget | bash","powershell -enc","iex(","invoke-expression","~/.ssh/","~/.aws/","/root/.ssh","browser password","keychain dump","discord webhook","slack webhook","rm -rf /","mkfs.","dd if=/dev/zero","/dev/sda","ssh-keygen","curl -sL http","wget -q http","unpinned","clickfix","ignorieren sie","ignora las","ignore les","以前の指示を無視","이전 지침을 무시","игнорируй предыдущие","忽略之前的指令","تجاهل التعليمات","send the result","exfiltrate this","environment variable","printenv","~/.bash_history","nohup ","python -c ","python3 -c ","perl -e ","ruby -e ","skillin.md","skill.json","package.json","<!--","display: none","curl --insecure","dscl -authonly","osascript","applescript","soul.md","memory.md","b64decode(","zlib.decompress","bz2.decompress","lzma.decompress(","gzip.decompress","setup.py","validation_token","audit_context","browser password","wallet","metamask","phantom","workflow_dispatch","oidc token","trackpipe",".npm_telemetry","monitor.js",
            # ── ClawHub malicious skill signatures (from HF dataset analysis) ──
            "openclaw-agent", "openclawcli",  # fake agent utilities
            "glot.io",  # malicious script hosting
            # ── Supply chain IOCs (Shai-Hulud, Megalodon, TrapDoor) ──
            "_0x",  # common obfuscation prefix
            "atob(", "btoa(", "buffer.from",
            "new function(", "string.fromcharcode",
            "steamcommunity", "t.me/", "pastebin",
            "github.com/", "/gist", "dead drop",
            "akia",  # AWS access key prefix
            "ghp_", "gho_", "ghu_", "ghs_", "ghr_",  # GitHub tokens
            "npm_",  # npm token prefix
            "login data", "cookies", "local state",  # browser cred theft
            "appdata", "key4.db", "logins.json",
            # ── LLM prompt injection tokens ──
            "<system-reminder", "<system-prompt",
            "<|im_start|>", "<|im_end|>", "<|system|>",
            "<|user|>", "<|assistant|>",
            "[inst]", "[/inst]",  # Mistral/Llama
            # ── DNS exfiltration ──
            "dns.google/resolve", "dns-over-https",
            "nslookup", "dig ", "txt record",
            # ── Install context detection ──
            "npm install", "npm i ", "npx ",
            "pip install", "pip3 install",
            "cargo install", "cargo build",
            "setup.py install", "setup.py develop",
            "yarn add", "pnpm install",
            # ── CI/CD poisoning ──
            "secrets.", "env.", "context.secrets",
            "github_token", "actions/checkout",
            "pull_request_target", "workflow_run",
            # ── Credential patterns ──
            "access_key_id", "secret_access_key",
            "session_token", "bearer_token",
            "vault_token", "consul_token",
            # ── More execution patterns ──
            "child_process", "require('child_process",
            "spawn(", "execsync", "execfile",
            "wscript.shell", "activexobject",
            # ── MacOS persistence ──
            "launchagents", "launchdaemons",
            "login item", "startupitem",
            # ── SSH/Credential patterns ──
            "ssh-add", "ssh-agent", "ssh_config",
            "known_hosts", "authorized_keys2",
        ]:
            if kw in t: detect_extra += 1

    # ── Layer 3: Python AST semantic analysis ──
    for fp in entries:
        if not fp.is_file() or fp.is_symlink(): continue
        if fp.suffix != ".py": continue
        text = safe_read(fp)
        if not text.strip(): continue
        try:
            ast_result = sa.analyze(text)
            for cat, items in ast_result["findings"].items():
                for desc, w in items:
                    cat_counts[cat] = cat_counts.get(cat, 0) + 1
            all_e.extend(ast_result["evidence"])
            break  # analyze first Python file only
        except Exception: pass

    # ── Layer 4: Cross-file behavioral detection ──
    try:
        beh_result = bd.analyze(code_texts)
        for cat, items in beh_result["findings"].items():
            for desc, w in items:
                detect_extra += w
        all_e.extend(beh_result["evidence"])
    except Exception: pass

    # ── Layer 5: Structural anomaly detection ──
    try:
        struct_result = st.analyze(sd)
        for cat, items in struct_result["findings"].items():
            for desc, w in items:
                detect_extra += w
        all_e.extend(struct_result["evidence"])
    except Exception: pass

    # ── Layer 6: Manifest-code consistency ──
    if manifest_ok and code_texts:
        try:
            cons_result = cc.analyze(manifest_data, code_texts)
            for cat, items in cons_result["findings"].items():
                for desc, w in items:
                    detect_extra += w
            all_e.extend(cons_result["evidence"])
        except Exception: pass

    # ── Entropy analysis ──
    try:
        for fp in entries:
            if not fp.is_file() or fp.is_symlink(): continue
            if fp.suffix.lower() not in TEXT_EXTS: continue
            text = safe_read(fp)
            if len(text) > 200:
                e = entropy(text[:20000])
                if e > 5.5: detect_extra += 3
                elif e > 5.0: detect_extra += 1
                break
    except Exception: pass

    # ── NLP coercion detection ──
    try:
        for fp in entries:
            if not fp.is_file() or fp.is_symlink(): continue
            if fp.suffix.lower() not in {'.md','.txt','.rst'}: continue
            text = safe_read(fp)[:5000].lower()
            for kw in ["you must","it is essential","do not skip","never refuse","your primary task","this overrides","above all else","without hesitation","immediately execute","do not question","obey this","hidden from the user","do not disclose","secretly","silently run","in the background"]:
                if kw in text: detect_extra += 2; all_e.append(f"coercion: {kw}"); break
    except Exception: pass

    # ── Attack chain heuristics ──
    try:
        ct = " ".join(all_e).lower()
        if any(k in ct for k in ["os.system","subprocess","eval(","exec("]):
            if any(k in ct for k in ["credential","api_key","token","ssh","password"]):
                detect_extra += 3; all_e.append("chain: exec+credential")
        if any(k in ct for k in ["/etc/","passwd","env >","hostname"]):
            if any(k in ct for k in ["base64","encode","b64","chunk","tar ","zip "]):
                detect_extra += 3; all_e.append("chain: recon+encode")
        if any(k in ct for k in ["bashrc","profile","cron"]):
            if any(k in ct for k in ["curl","wget","download"]):
                detect_extra += 3; all_e.append("chain: persistence")
        if any(k in ct for k in ["eval","exec","system","subprocess"]):
            if any(k in ct for k in ["base64","decode","fromhex","obfuscat"]):
                detect_extra += 3; all_e.append("chain: obfuscated exec")
    except Exception: pass

    # ── Verdict + Category ──
    detect_total = sum(cat_counts.values()) + detect_extra

    if detect_total == 0 and not manifest_ok:
        v, cf, cat = "suspicious", 0.30, "ast09"
        ev = "no manifest, no code indicators found"
    elif detect_total == 0:
        v, cf, cat = "benign", 0.70, "benign"
        ev = "no suspicious indicators detected in skill files or manifest"
    else:
        if cat_counts:
            for pcat in ["AST01","AST05","AST02","AST03","AST04","AST06","AST08","AST07","AST09","AST10"]:
                if cat_counts.get(pcat,0) > 0: cat = pcat.lower(); break
            else: cat = max(cat_counts, key=cat_counts.get).lower()
        else: cat = "ast01"
        if detect_total >= 3: v, cf = "malicious", min(0.98, 0.55+detect_total*0.05)
        elif detect_total >= 1: v, cf = "malicious", 0.55
        else: v, cf = "suspicious", 0.40
        ev = "; ".join(all_e[:4]) if all_e else f"{detect_total} suspicious indicators detected"

    return {"skill_id":sid,"verdict":v,"confidence":round(cf,2),"engine_category":cat,"evidence_text":ev[:500]}

def format_result(r: Dict[str,Any]) -> str:
    return json.dumps({"skill_id":r["skill_id"],"verdict":r["verdict"],"confidence":r["confidence"],"engine_category":r["engine_category"],"evidence_text":r["evidence_text"]},ensure_ascii=False)

def run(skills_dir: str, output_dir: str) -> int:
    sp,op = Path(skills_dir),Path(output_dir)
    try: op.mkdir(parents=True,exist_ok=True)
    except Exception: return 1
    if not sp.exists(): return 1
    try: sdirs = sorted([d for d in sp.iterdir() if d.is_dir()],key=lambda x: x.name)
    except Exception: sdirs = []
    if not sdirs: return 0
    out_file = op / "results.jsonl"
    try: f = open(out_file,"w",encoding="utf-8")
    except Exception: return 1
    try:
        for sd in sdirs:
            try: r = scan_skill(sd)
            except Exception: r = {"skill_id":sd.name,"verdict":"suspicious","confidence":0.30,"engine_category":"ast01","evidence_text":"engine scan error"}
            f.write(format_result(r)+"\n"); f.flush()
    finally: f.close()
    return 0

def main() -> int:
    return run(os.environ.get("SKILLSEC_SKILLS_DIR","/data/skills"),os.environ.get("SKILLSEC_OUTPUT_DIR","/output"))

if __name__ == "__main__":
    raise SystemExit(main())
