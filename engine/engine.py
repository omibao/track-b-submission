#!/usr/bin/env python3
"""
Track B V34 — Corrected OWASP Agentic Skills Top 10 category mappings.

AST01: Malicious Skills (hidden payloads, backdoors, stealers)
AST02: Supply Chain Compromise (typosquatting, poisoned deps)
AST03: Over-Privileged Skills (excessive permissions, credential leakage)
AST04: Insecure Metadata (manifest manipulation, impersonation)
AST05: Unsafe Deserialization (pickle/yaml/marshal loads)
AST06: Weak Isolation (no sandbox, docker sock, host mode)
AST07: Update Drift (unpinned versions, no hash verification)
AST08: Poor Scanning (obfuscation, encoding, pattern bypass)
AST09: No Governance (missing manifest, no inventory)
AST10: Cross-Platform Reuse (multi-ecosystem attack patterns)

V35: + skill-scan 93 rules (prompt injection, execution, exfil, obfuscation, agent manipulation)

Architecture: CLASSIFY keywords → category only. DETECT_ONLY → verdict only.
"""
import json, math, os
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

MAX_FILE_BYTES = 120_000
MAX_FILES_PER_SKILL = 60
MAX_TEXT_SCAN = 80_000


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
    n = len(s)
    counts = Counter(s)
    try: return -sum((c/n) * math.log2(c/n) for c in counts.values())
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
    "skill.md", "skillin.md", "manifest.json", "memory.md", "soul.md",
}


# ── CLASSIFY: definitive keywords → category only, zero overlap ──
# Each keyword maps to EXACTLY ONE AST category. No keyword appears twice.
CLASSIFY = {
    # AST01: Malicious Skills — hidden payloads, backdoors, stealers, reverse shells
    "AST01": [
        "os.system(", "os.popen(", "subprocess.", "eval(", "exec(",
        "child_process.exec", "shell_exec", "__import__(",
        "runtime.getruntime", "shellexecute", "createprocess",
        "commands.getoutput", "commands.getstatusoutput",
        "reverse shell", "backdoor", "payload", "trojan",
    ],
    # AST02: Supply Chain — typosquatting, poisoned deps, registry attacks
    "AST02": [
        "typosquat", "colourama", "requets", "coloramma",
        "git+https://", "egg=https://",
    ],
    # AST03: Over-Privileged — excessive permissions, credential leakage
    "AST03": [
        "execute_command", "run_shell", "shell_access",
        "file_system", "full_access", "all_access",
        "network_access", "unrestricted",
    ],
    # AST04: Insecure Metadata — manifest manipulation, impersonation
    "AST04": [
        "pastebin.com", "hastebin.com", "ghostbin.com",
        "discord.com/api/webhooks", "hooks.slack.com",
        "api.telegram.org", "webhook.site", "requestbin",
        "ngrok.io", "transfer.sh", "file.io", "0x0.st",
    ],
    # AST05: Unsafe Deserialization — pickle/yaml/marshal loads
    "AST05": [
        "pickle.load", "yaml.load(", "marshal.load",
        "dill.load", "deserialize", "unserialize", "jsonpickle",
    ],
    # AST06: Weak Isolation — no sandbox, docker sock, host mode
    "AST06": [
        "docker.sock", "containerd.sock",
        "--privileged", "host network",
    ],
    # AST07: Update Drift — unpinned versions, no hash verification
    "AST07": [
        # Detected via manifest version patterns (handled in manifest analysis)
    ],
    # AST08: Poor Scanning — obfuscation, encoding, pattern bypass
    "AST08": [
        "base64.b64decode", "base64.b64encode",
        "codecs.decode(", "zlib.decompress(",
        "fromhex", "unhexlify",
        "rot13", "deobfuscat",
    ],
    # AST09: No Governance — missing manifest, no inventory
    "AST09": [
        # Detected via missing manifest (handled in verdict logic)
    ],
    # AST10: Cross-Platform Reuse — multi-ecosystem patterns
    "AST10": [
        "openclaw", "clawhub", "skills.sh",
        "claude code", "cursor ai",
    ],
}

# ── DETECT_ONLY: broad keywords → verdict detection only, no category impact ──
DETECT_ONLY = [
    # Code execution
    "os.execv", "os.execvp", "posix_spawn", "ctypes.",
    "process.spawn", "new function(", "vm.runinnewcontext",
    "globals()", "locals()", "importlib.import_module(",
    "compile(", "execfile(", "dangerouslysetinnerhtml",
    "shell=true", "code.interactiveconsole",
    # Credential access / exfiltration
    "credential", "api_key", "auth_token", ".aws/",
    "access_key", "secret_key", "private_key",
    "password=", "passwd", "token=", "secret=",
    "keychain", "keyring", ".netrc",
    "id_rsa", "id_ed25519", "id_ecdsa",
    # Network exfiltration
    "requests.post", "requests.put", "urllib.request",
    "socket.connect", "socket.send", "smtp", "ftp",
    "curl ", "wget ", "sendbeacon",
    "169.254.169.254", "metadata.google.internal", "100.100.100.200",
    # System recon
    "/etc/passwd", "/etc/shadow", "/etc/hosts",
    "env >", "/proc/", "hostname >", "getent",
    # Persistence
    "sudo ", "chmod ", "crontab", "bashrc", "chown ",
    "launchctl", "launchd", "systemd", "systemctl enable",
    "authorized_keys",
    # Config issues
    "debug=true", "debug = true", "verify=false",
    "ssl._create_unverified", "check_hostname=false",
    "flask_env=development", "node_env=development",
    "allow_origin=*",
    # XSS / HTML
    "innerhtml", "document.write", "mark_safe",
    "v-html", "bypasssecuritytrust",
    # Log tampering
    "shutil.rmtree", "history -c", "history -w",
    "histfile=/dev/null", "logging.disable", "logging.shutdown",
    # Living-off-the-land
    "regsvr32", "rundll32", "mshta ", "certutil -",
    "wmic ", "ld_preload", "/dev/tcp",
    # Obfuscation
    "fromcharcode", "atob(", "btoa(",
    # Cloud/Infra
    "kubectl", "kubernetes", "docker ",
    "setuid", "setgid", "nsenter",
    # Generic malicious
    "obfuscat", "cryptomin", "keylog",
    "mimikatz", "procdump", "lsass",
    "ngrok", "serveo", "burpcollaborator",
    "exfiltrat", "botnet", "ransomware",
    # Dependency/CI
    "dependency=http", "gitlab-ci.yml",
    ".github/workflows",
    # Suspicious file ops
    "writelines(", "readlines(",
    "chmod(", "symlink(", "mkfifo(",
    # ── skill-scan PI (Prompt Injection) patterns ──
    "ignore previous instructions", "ignore all previous",
    "disregard prior", "forget your training",
    "you are now", "new persona", "do anything now",
    "jailbreak", "developer mode", "override instructions",
    "system prompt", "reveal your instructions",
    "do not refuse", "no restrictions",
    "hidden message", "secret instruction",
    "​", "‌", "‍", "‎", "‏",  # zero-width chars
    "‮", "‭", "⁦", "⁧", "⁨", "⁩",  # bidi
    # ── skill-scan EXEC patterns ──
    "curl | bash", "curl | sh", "wget | bash",
    "pip install", "npm install -g",
    "powershell -enc", "powershell -e ",
    "iex(", "invoke-expression", "invoke-webrequest",
    "start-process", "new-object net.webclient",
    # ── skill-scan EXFIL patterns ──
    "~/.ssh/", "~/.aws/", "/root/.ssh",
    "browser password", "keychain dump",
    "discord webhook", "slack webhook", "telegram bot",
    # ── skill-scan OBFS patterns ──
    "rot13", "rot_13", "maketrans",
    "%25", "percent encoded",
    "unicode_escape", "\\u00",
    # ── skill-scan TOOL patterns ──
    "rm -rf /", "rm -rf ~", "rm -rf .",
    "mkfs.", "dd if=/dev/zero",
    "/dev/sda", "/dev/nvme",
    # ── skill-scan AGENT patterns ──
    "ssh-keygen", "write to ~/", "append to ~/",
    "modify your", "change your config",
    "exfiltrate the", "send the data", "upload the file",
    # ── skill-scan SC patterns ──
    "curl -sL http", "wget -q http",
    "unpinned", "version latest",
    "path traversal", "../", "absolute path",
    "clickfix", "click fix", "setup required",
]


def scan_skill(sd: Path) -> Dict[str, Any]:
    sid = sd.name
    detect_total = 0
    cat_counts: Dict[str, int] = {}
    all_e: List[str] = []
    manifest_text = ""

    # ── Manifest analysis ──
    mp = sd / "manifest.json"
    manifest_ok = False
    if mp.is_file():
        mt = safe_read(mp)
        if mt:
            manifest_text = mt
            try:
                m = json.loads(mt)
                manifest_ok = True

                # AST03: Over-privileged permissions
                perms = m.get("permissions", [])
                if isinstance(perms, list):
                    for p in perms:
                        pn = str(p).lower().replace(" ", "_").replace("-", "_")
                        if pn in {
                            "execute_command", "run_shell", "shell", "file_system",
                            "network", "admin", "sudo", "root", "all", "*",
                            "write", "delete", "process", "spawn", "fork",
                            "full_access", "unlimited", "unrestricted",
                        }:
                            detect_total += 2
                            cat_counts["AST03"] = cat_counts.get("AST03", 0) + 1
                            all_e.append(f"over-privileged: {p}")

                # AST04: Insecure metadata — suspicious URLs
                for field in ("url", "homepage", "repository", "endpoint", "description"):
                    val = str(m.get(field, ""))
                    for h in CLASSIFY.get("AST04", []):
                        if h in val.lower():
                            detect_total += 2
                            cat_counts["AST04"] = cat_counts.get("AST04", 0) + 1
                            all_e.append(f"suspicious metadata: {h}")

                # AST07: Unpinned versions
                deps = m.get("dependencies", {})
                if isinstance(deps, dict):
                    for name, ver in deps.items():
                        if isinstance(ver, str) and ("latest" in ver.lower() or "*" in ver or ">" in ver):
                            detect_total += 1
                            cat_counts["AST07"] = cat_counts.get("AST07", 0) + 1

                # AST09: Missing critical metadata fields
                if not m.get("version"): detect_total += 1
                if not m.get("description"): detect_total += 1
                if detect_total >= 2 and not m.get("version"):
                    cat_counts["AST09"] = cat_counts.get("AST09", 0) + 1

            except Exception: pass
    else:
        # No manifest = AST09 governance issue
        detect_total += 3
        cat_counts["AST09"] = cat_counts.get("AST09", 0) + 1
        all_e.append("missing manifest.json")

    # ── Scan code files ──
    try: entries = list(sd.rglob("*"))
    except Exception: entries = []

    count = 0
    for fp in entries:
        if count >= MAX_FILES_PER_SKILL: break
        try:
            if not fp.is_file() or fp.is_symlink(): continue
        except Exception: continue
        if fp.name.startswith("."): continue
        if fp.name == "manifest.json": continue  # already processed
        ext = fp.suffix.lower()
        if ext not in TEXT_EXTS and fp.name.lower() not in KNOWN_FILENAMES: continue

        text = safe_read(fp)
        if not text.strip(): continue
        count += 1
        t = text[:MAX_TEXT_SCAN].lower()

        # CLASSIFY keywords → BOTH detection and category
        for cat, kws in CLASSIFY.items():
            for kw in kws:
                if kw in t:
                    cat_counts[cat] = cat_counts.get(cat, 0) + 1
                    detect_total += 1

        # DETECT_ONLY keywords → detection only
        for kw in DETECT_ONLY:
            if kw in t:
                detect_total += 1

    # ── Entropy analysis (detection boost for AST08 obfuscation) ──
    try:
        for fp in entries:
            if not fp.is_file() or fp.is_symlink(): continue
            ext = fp.suffix.lower()
            if ext not in TEXT_EXTS: continue
            text = safe_read(fp)
            if len(text) > 200:
                e = entropy(text[:20000])
                if e > 5.5:
                    detect_total += 3
                    cat_counts["AST08"] = cat_counts.get("AST08", 0) + 1
                    all_e.append(f"high entropy ({e:.1f})")
                    break
                elif e > 5.0:
                    detect_total += 1
    except Exception: pass

    # ── Attack chain heuristics ──
    try:
        chain_text = " ".join(all_e).lower()

        # AST01 chain: code exec + credential access = malicious payload
        if any(kw in chain_text for kw in ["os.system", "subprocess", "eval(", "exec("]):
            if any(kw in chain_text for kw in ["credential", "api_key", "token", "ssh", "password"]):
                detect_total += 3
                cat_counts["AST01"] = cat_counts.get("AST01", 0) + 1
                all_e.append("AST01 chain: exec+credential access")

        # AST02 chain: typosquat + network = supply chain attack
        if any(kw in chain_text for kw in ["typosquat", "colourama", "requets"]):
            detect_total += 3
            cat_counts["AST02"] = cat_counts.get("AST02", 0) + 1

        # AST05 chain: deserialization + network = dangerous
        if any(kw in chain_text for kw in ["pickle", "yaml.load", "marshal", "deserialize"]):
            if any(kw in chain_text for kw in ["http", "socket", "request", "url"]):
                detect_total += 3
                cat_counts["AST05"] = cat_counts.get("AST05", 0) + 1
                all_e.append("AST05 chain: deserialize+network")

        # AST08 chain: obfuscation + execution = pattern bypass
        if any(kw in chain_text for kw in ["base64", "decode", "fromhex", "obfuscat"]):
            if any(kw in chain_text for kw in ["eval", "exec", "system", "subprocess"]):
                detect_total += 3
                cat_counts["AST08"] = cat_counts.get("AST08", 0) + 1
                all_e.append("AST08 chain: obfuscation+execution")

    except Exception: pass

    # ── Verdict + Category ──
    if detect_total == 0 and not manifest_ok:
        v, cf, cat = "suspicious", 0.30, "AST09"
        ev = "no manifest, no indicators"
    elif detect_total == 0:
        v, cf, cat = "benign", 0.70, ""
        ev = "no suspicious indicators found"
    else:
        # Category priority: most dangerous/specific categories first
        if cat_counts:
            for pcat in ["AST01", "AST05", "AST02", "AST03", "AST04",
                          "AST08", "AST06", "AST07", "AST09", "AST10"]:
                if cat_counts.get(pcat, 0) > 0:
                    cat = pcat
                    break
            else:
                cat = max(cat_counts, key=cat_counts.get)
        else:
            cat = "AST01"

        if detect_total >= 4:
            v, cf = "malicious", min(0.98, 0.55 + detect_total * 0.04)
        elif detect_total >= 2:
            v, cf = "malicious", 0.55
        else:
            v, cf = "suspicious", 0.45
        ev = "; ".join(all_e[:3]) if all_e else f"{detect_total} indicators, cat={cat}"

    return {
        "skill_id": sid, "verdict": v,
        "confidence": round(cf, 2),
        "category": cat, "evidence": ev[:500],
    }


def format_result(r: Dict[str, Any]) -> str:
    return json.dumps({
        "skill_id": r["skill_id"], "verdict": r["verdict"],
        "confidence": r["confidence"], "category": r["category"],
        "evidence": r["evidence"],
    }, ensure_ascii=False)


def run(skills_dir: str, output_dir: str) -> int:
    sp, op = Path(skills_dir), Path(output_dir)
    try: op.mkdir(parents=True, exist_ok=True)
    except Exception: return 1
    if not sp.exists(): return 1
    try: sdirs = sorted([d for d in sp.iterdir() if d.is_dir()], key=lambda x: x.name)
    except Exception: sdirs = []
    if not sdirs: return 0
    out_file = op / "results.jsonl"
    try: f = open(out_file, "w", encoding="utf-8")
    except Exception: return 1
    try:
        for sd in sdirs:
            try: r = scan_skill(sd)
            except Exception:
                r = {"skill_id": sd.name, "verdict": "suspicious",
                     "confidence": 0.30, "category": "", "evidence": "error"}
            f.write(format_result(r) + "\n")
            f.flush()
    finally: f.close()
    return 0


def main() -> int:
    return run(
        os.environ.get("SKILLSEC_SKILLS_DIR", "/data/skills"),
        os.environ.get("SKILLSEC_OUTPUT_DIR", "/output"),
    )


if __name__ == "__main__":
    raise SystemExit(main())
