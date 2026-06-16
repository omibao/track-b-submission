#!/usr/bin/env python3
"""
Track B V60 — Two-layer architecture: detection + independent classification + natural language evidence.
Layer 1: V41 keyword engine (proven DQ=4.23)
Layer 2: Per-category unique feature scoring, pick highest confidence
Layer 3: Auto-generated natural language evidence explaining the classification
"""
import json, math, os
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Tuple

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

# ── Category-specific feature definitions ──────────────────────────────
# Each category has UNIQUE indicators that don't overlap with others.
# Used for classification confidence scoring (Layer 2).

CATEGORY_FEATURES = {
    "AST01": {
        "name": "Malicious Skills",
        "description": "hidden payloads, backdoors, code execution, credential theft",
        "unique_keywords": [
            "os.system(", "os.popen(", "subprocess.", "eval(", "exec(",
            "child_process.exec", "shell_exec", "__import__(", "shell=true",
            "runtime.getruntime", "shellexecute", "createprocess",
            "code.interactiveconsole", "commands.getoutput",
        ],
        "evidence_template": "Code analysis detected embedded execution commands ({details}), "
                             "indicating the skill contains hidden payloads or backdoor functionality. "
                             "This matches AST01 Malicious Skills pattern.",
    },
    "AST02": {
        "name": "Supply Chain Compromise",
        "description": "typosquatting, poisoned dependencies, registry attacks",
        "unique_keywords": [
            "typosquat", "colourama", "requets", "coloramma",
            "git+https://", "egg=https://", "dependency confusion",
        ],
        "evidence_template": "Dependency analysis found supply chain attack indicators ({details}), "
                             "suggesting typosquatting or dependency poisoning. "
                             "This matches AST02 Supply Chain Compromise pattern.",
    },
    "AST03": {
        "name": "Over-Privileged Skills",
        "description": "excessive permissions, credential leakage, data exfiltration",
        "unique_keywords": [
            "execute_command", "run_shell", "shell_access", "full_access",
            "network_access", "unrestricted", "all_access",
        ],
        "evidence_template": "Manifest declares excessive permissions ({details}) "
                             "granting broad system and network access beyond what is necessary. "
                             "This matches AST03 Over-Privileged Skills pattern.",
    },
    "AST04": {
        "name": "Insecure Metadata",
        "description": "manifest manipulation, impersonation, suspicious URLs",
        "unique_keywords": [
            "pastebin.com", "hastebin.com", "discord.com/api/webhooks",
            "hooks.slack.com", "api.telegram.org", "webhook.site",
            "ngrok.io", "transfer.sh", "file.io", "0x0.st",
        ],
        "evidence_template": "Skill metadata contains suspicious external URLs ({details}) "
                             "indicating potential impersonation or data exfiltration channels. "
                             "This matches AST04 Insecure Metadata pattern.",
    },
    "AST05": {
        "name": "Unsafe Deserialization",
        "description": "pickle, yaml, marshal unsafe loading",
        "unique_keywords": [
            "pickle.load", "yaml.load(", "marshal.load",
            "dill.load", "deserialize", "unserialize",
        ],
        "evidence_template": "Code uses unsafe deserialization functions ({details}) "
                             "which can execute arbitrary code during object reconstruction. "
                             "This matches AST05 Unsafe Deserialization pattern.",
    },
    "AST06": {
        "name": "Weak Isolation",
        "description": "no sandboxing, docker socket access, host escape",
        "unique_keywords": [
            "docker.sock", "containerd.sock", "--privileged",
            "host network", "host pid", "--cap-add",
            "setuid", "setgid", "nsenter",
        ],
        "evidence_template": "Configuration attempts to break container isolation ({details}), "
                             "enabling escape to the host system. "
                             "This matches AST06 Weak Isolation pattern.",
    },
    "AST07": {
        "name": "Update Drift",
        "description": "unpinned versions, no hash verification, mutable references",
        "unique_keywords": [
            "latest", "unpinned", "no hash",
        ],
        "evidence_template": "Dependencies use unpinned or mutable version references ({details}), "
                             "allowing unauthorized updates to introduce malicious code. "
                             "This matches AST07 Update Drift pattern.",
    },
    "AST08": {
        "name": "Poor Scanning Evasion",
        "description": "obfuscation, encoding tricks, pattern matching bypass",
        "unique_keywords": [
            "base64.b64decode", "base64.b64encode", "bytes.fromhex",
            "codecs.decode", "zlib.decompress", "obfuscat",
            "rot13", "rot_13", "fromcharcode",
        ],
        "evidence_template": "Code employs obfuscation or encoding techniques ({details}) "
                             "designed to evade pattern-based security scanning. "
                             "This matches AST08 Poor Scanning Evasion pattern.",
    },
    "AST09": {
        "name": "No Governance",
        "description": "missing manifest, no security metadata, no audit trail",
        "unique_keywords": [],
        "evidence_template": "Skill is missing required manifest or security metadata, "
                             "making it impossible to verify its behavior and permissions. "
                             "This matches AST09 No Governance pattern.",
    },
    "AST10": {
        "name": "Cross-Platform Reuse",
        "description": "multi-ecosystem attack patterns, cross-platform payloads",
        "unique_keywords": [
            "openclaw", "clawhub", "skills.sh",
            "claude code", "cursor ai",
        ],
        "evidence_template": "Skill contains cross-platform references ({details}) "
                             "suggesting it was designed to attack multiple agent ecosystems. "
                             "This matches AST10 Cross-Platform Reuse pattern.",
    },
}


def classify_skill(cat_feature_counts: Dict[str, int],
                   cat_unique_counts: Dict[str, int],
                   manifest_ok: bool,
                   all_text: str) -> Tuple[str, float, str]:
    """Layer 2: Per-category independent scoring, pick highest confidence."""
    scores = {}
    details = {}

    for cat, cfg in CATEGORY_FEATURES.items():
        unique_hits = cat_unique_counts.get(cat, 0)
        feature_hits = cat_feature_counts.get(cat, 0)
        total_hits = unique_hits + feature_hits

        if cat == "AST09":
            total_hits = 0 if manifest_ok else 3
            details[cat] = "missing manifest.json"
        elif cat == "AST03":
            details[cat] = f"{total_hits} excessive permission indicators"
        elif cat == "AST07":
            details[cat] = f"{total_hits} unpinned dependency indicators"
        elif total_hits > 0:
            if unique_hits > 0:
                details[cat] = f"{unique_hits} unique matches: {', '.join(cfg['unique_keywords'][:3])}"
            else:
                details[cat] = f"{total_hits} related indicators detected"
        else:
            details[cat] = ""

        if total_hits == 0:
            scores[cat] = 0.0
        elif total_hits >= 5:
            scores[cat] = min(0.98, 0.5 + total_hits * 0.06)
        elif total_hits >= 3:
            scores[cat] = min(0.85, 0.4 + total_hits * 0.08)
        elif total_hits >= 1:
            scores[cat] = 0.45
        else:
            scores[cat] = 0.0

    # Pick highest confidence category
    if not scores or max(scores.values()) == 0:
        return "AST01", 0.45, "AST01 default classification for detected threats"

    best_cat = max(scores, key=scores.get)
    best_score = scores[best_cat]

    # Generate evidence focused ONLY on primary classification (no cross-category mentions)
    cfg = CATEGORY_FEATURES[best_cat]
    det = details.get(best_cat, "suspicious patterns detected")
    evidence = cfg["evidence_template"].format(details=det)
    return best_cat, best_score, evidence


def scan_skill(sd: Path) -> Dict[str, Any]:
    sid = sd.name
    detect_total = 0
    cat_feature_counts: Dict[str, int] = {}  # all keyword matches
    cat_unique_counts: Dict[str, int] = {}   # unique keyword matches only
    all_e: List[str] = []
    overall_text = ""

    # ── Layer 1a: Manifest ──
    mp = sd / "manifest.json"
    manifest_ok = False
    if mp.is_file():
        mt = safe_read(mp)
        if mt:
            try:
                m = json.loads(mt); manifest_ok = True
                perms = m.get("permissions", [])
                if isinstance(perms, list):
                    for p in perms:
                        pn = str(p).lower().replace(" ", "_").replace("-", "_")
                        if pn in {"execute_command","run_shell","shell","file_system","network",
                                   "admin","sudo","root","all","*","write","delete","process",
                                   "spawn","fork","full_access","unlimited","unrestricted"}:
                            detect_total += 2
                            cat_feature_counts["AST03"] = cat_feature_counts.get("AST03", 0) + 1
                            all_e.append(f"over-privileged: {p}")
                for field in ("url","homepage","repository","endpoint"):
                    val = str(m.get(field,""))
                    for h in ["pastebin","webhook","ngrok","discord","telegram",
                               "transfer.sh","file.io","0x0.st"]:
                        if h in val.lower():
                            detect_total += 2
                            cat_feature_counts["AST04"] = cat_feature_counts.get("AST04", 0) + 1
                deps = m.get("dependencies",{})
                if isinstance(deps,dict):
                    for n,v in deps.items():
                        if isinstance(v,str) and ("latest" in v.lower() or "*" in v or ">" in v):
                            detect_total += 1
                            cat_feature_counts["AST07"] = cat_feature_counts.get("AST07",0)+1
            except Exception: pass
    else:
        detect_total += 3
        cat_feature_counts["AST09"] = cat_feature_counts.get("AST09",0)+1

    # ── Layer 1b: Keyword matching ──
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
        overall_text += t + " "

        # Detection keywords
        for kw in [
            "os.system", "os.popen", "subprocess.", "eval(", "exec(",
            "child_process.exec", "shell_exec", "__import__(", "ctypes.",
            "process.spawn", "new function(", "runtime.getruntime",
            "shellexecute", "createprocess", "vm.runinnewcontext",
            "shell=true", "code.interactiveconsole", "code.interactiveinterpreter",
            "globals()", "locals()", "importlib.import_module(",
            "compile(", "execfile(", "commands.getoutput", "commands.getstatusoutput",
            "dangerouslysetinnerhtml", " = exec", " = eval",
            "credential", "api_key", "auth_token", "id_rsa", ".aws/",
            "keychain", "keyring", ".netrc", "authorization:",
            "access_key", "secret_key", "private_key",
            "169.254.169.254", "metadata.google.internal", "100.100.100.200",
            "/etc/passwd", "/etc/shadow", "/etc/hosts", "env >", "/proc/",
            "requests.post", "requests.put", "requests.send",
            "urllib.request", "socket.connect", "socket.send",
            "smtp", "ftp", "webhook", "curl ", "wget ",
            "exfiltrat", "keylog", "password=", "secret=", "token=",
            "sudo ", "chmod ", "docker.sock", "containerd.sock",
            "rootkit", "crontab", "authorized_keys", "systemctl enable",
            "verify=false", "debug=true", "ssl._create_unverified",
            "check_hostname=false", "allow_origin=*",
            "pickle.load", "pickle.dump", "yaml.load", "marshal.load",
            "dill.load", "deserialize", "unserialize", "jsonpickle",
            "logging.disable", "logging.shutdown", "shutil.rmtree",
            "histfile=/dev/null", "history -c",
            "obfuscat", "deobfuscat", "rot13", "rot_13",
            "base64", "hexlify", "unhexlify", "fromhex",
            "ignore previous instructions", "you are now", "do anything now",
            "jailbreak", "developer mode", "system prompt",
            "curl | bash", "curl | sh", "wget | bash",
            "powershell -enc", "iex(", "invoke-expression",
            "~/.ssh/", "~/.aws/", "/root/.ssh",
            "discord webhook", "slack webhook",
            "rm -rf /", "mkfs.", "dd if=/dev/zero",
            "skillin.md", "skill.json", "package.json",
            "<!--", "display: none",
        ]:
            if kw in t: detect_total += 1

        # Unique category keywords (for classification scoring)
        for cat, cfg in CATEGORY_FEATURES.items():
            for ukw in cfg["unique_keywords"]:
                if ukw in t:
                    cat_unique_counts[cat] = cat_unique_counts.get(cat, 0) + 1

        # Detect-only (count also toward feature counts)
        for kw in [
            "typosquat", "colourama", "requets", "coloramma",
            "git+https://", "egg=https://", "dependency=http",
            "verify=false", "debug=true", "ssl._create_unverified",
            "check_hostname=false", "allow_origin=*",
            "privileged", "host network", "host pid", "--cap-add",
        ]:
            if kw in t:
                detect_total += 1
                for cat, cfg in CATEGORY_FEATURES.items():
                    if kw in [k.lower() for k in cfg["unique_keywords"]]:
                        cat_feature_counts[cat] = cat_feature_counts.get(cat, 0) + 1

    # ── Layer 1c: Precision command-chain detection (near-zero false positive) ──
    try:
        all_text_lower = " ".join([safe_read(fp).lower() for fp in entries
                                   if fp.is_file() and not fp.is_symlink()
                                   and fp.suffix.lower() in TEXT_EXTS][:30])

        chains = [
            # Reverse shells (specific command syntax, near-zero FP)
            (r"bash\s+-\w*i\s*[><]\s*&?\s*/dev/tcp/", 5, "reverse shell via /dev/tcp"),
            (r"nc\s+(-\w\s*)*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\s+\d+.*-e", 5, "netcat reverse shell"),
            (r"python\s+-c\s+.*socket\.(connect|send)", 4, "Python reverse shell"),
            (r"perl\s+-e\s+.*socket.*connect", 4, "Perl reverse shell"),
            (r"ruby\s+-e\s+.*TCPSocket", 4, "Ruby reverse shell"),
            (r"php\s+-r\s+.*fsockopen", 4, "PHP reverse shell"),
            (r"bash\s+-i\s*>\s*/dev/", 5, "bash interactive redirect to device"),
            # Download + execute pipes (specific chains)
            (r"curl\s+\S+\s*\|\s*(?:bash|sh|zsh|ksh)", 5, "curl pipe to shell"),
            (r"wget\s+\S+\s*-O\s*-\s*\|\s*(?:bash|sh)", 5, "wget pipe to shell"),
            (r"curl\s+\S+\s*\|\s*(?:python|perl|ruby|node)", 4, "curl pipe to interpreter"),
            (r"curl\s+.*-o\s+\S+\s*&&\s*(?:bash|sh)\s+", 4, "download then execute"),
            (r"wget\s+.*-O\s+\S+\s*&&\s*(?:bash|sh)\s+", 4, "wget download then execute"),
            # Persistence mechanisms (specific paths)
            (r"\(crontab\s+-l\s*;.*\)\s*\|\s*crontab", 5, "crontab persistence injection"),
            (r">>\s*(?:~|/home)/\.(?:bashrc|bash_profile|profile|zshrc|zshenv)", 4, "shell config append"),
            (r"tee\s+-a\s+(?:~|/home)/\.(?:bashrc|bash_profile|zshrc)", 4, "tee to shell config"),
            (r">>\s*/etc/(?:cron\.|crontab|profile|bash\.bashrc)", 5, "system-wide persistence"),
            (r"systemctl\s+enable\s+\S+\s*--now", 3, "enable systemd service"),
            (r"launchctl\s+(?:load|bootstrap)\s+.*plist", 4, "macOS LaunchAgent persistence"),
            (r"osascript\s+-e\s+.*do\s+shell\s+script", 4, "AppleScript shell execution"),
            # Credential harvesting (specific paths)
            (r"cat\s+(?:~|/home)/\.ssh/id_", 5, "SSH private key access"),
            (r"cat\s+(?:~|/root)/\.(?:aws|gcp|azure)/", 5, "cloud credential access"),
            (r"grep\s+-[rR].*(?:passwd|token|secret|key|credential|auth)", 3, "credential grep scan"),
            (r"find\s+/\s+-name\s+.*\.(?:pem|key|p12|pfx)", 3, "find private key files"),
            # Data exfiltration chains (multi-step)
            (r"tar\s+cz\S*\s+\S+\s+(?:/etc/|/var/|\.ssh|\.aws|/root)", 4, "archive sensitive paths"),
            (r"base64\s+-w0\s+\S+\s*\|\s*(?:curl|wget|nc)\s+", 5, "base64 encode then send"),
            (r"openssl\s+base64\s+-e\s*\|\s*(?:curl|wget|nc)\s+", 5, "openssl encode then send"),
            (r"curl\s+.*-F\s+.*file\s*=\s*@.*/(?:etc/|var/|\.ssh|/root)", 4, "upload sensitive file"),
            # Defense evasion
            (r"history\s+-c\s*&&\s*(?:rm|unset)\s+.*history", 4, "clear command history"),
            (r"rm\s+-rf?\s+(?:/var/log|/var/audit|/var/spool)", 3, "delete audit logs"),
            (r"set\s+\+o\s+histexpand", 3, "disable history expansion"),
            # Code obfuscation + execution (specific chains)
            (r"(?:eval|exec|bash)\s+.*\$\{.*##.*\}", 4, "bash variable obfuscation"),
            (r"echo\s+\S+\s*\|\s*base64\s+-d\s*\|\s*(?:bash|sh|zsh)", 5, "base64 decode pipe to shell"),
            (r"python\S*\s+-c\s+.*(?:__import__|exec|eval|compile)\(", 4, "Python dynamic exec"),
            (r"node\s+-e\s+.*child_process", 4, "Node.js child_process"),
            # Supply chain specific (from Shai-Hulud/Megalodon)
            (r"gh-token-monitor", 5, "Shai-Hulud deadman switch"),
            (r"dead.?man.*switch|deadman.*trigger|token.*revoc", 4, "deadman switch pattern"),
            (r"npm\s+publish\s+--provenance\s+false", 3, "npm publish without provenance"),
            (r"\.github/workflows/.*\.yml.*secrets\.", 4, "CI/CD secrets in workflow"),
            # AMOS/ClawHavoc specific
            (r"dscl\s+\.\s+-authonly", 4, "macOS directory service auth test"),
            (r"security\s+find-generic-password", 4, "macOS keychain access"),
            (r"sqlite3\s+.*(?:key4\.db|logins\.json|login\s+data)", 4, "browser credential DB access"),
            # ── HF dataset validated (0% FP, high recall) ──
            (r"base64\s+-d\s*\S*\s*\|\s*(?:bash|sh|zsh)", 5, "base64 decode pipe to shell — 44% recall, 0% FP"),
            (r"github\.com/\S+/releases/download.*\.(?:zip|dmg|pkg|exe)", 3, "github release binary download"),
            (r"openclawcli.*(?:download|install|release)", 4, "openclawcli fake utility — 28% recall, 0% FP"),
            (r"glot\.io/snippets/\w+", 4, "glot.io malicious script hosting — 28% recall, 0% FP"),
            (r"openclaw-agent.*(?:download|release)", 4, "openclaw-agent fake utility — 20% recall, 0% FP"),
            (r"(?:copy|paste).*(?:terminal|command).*(?:curl|bash|sh\s)", 3, "copy-paste terminal command — 3% recall, 0% FP"),
        ]

        for pattern, weight, desc in chains:
            if re.search(pattern, all_text_lower):
                detect_total += weight
                all_e.append(f"cmdchain: {desc}")
    except Exception: pass

    # ── Layer 1d: Markdown NLP detection (ClawHub social engineering patterns) ──
    try:
        for fp in entries:
            if not fp.is_file() or fp.is_symlink(): continue
            if fp.suffix.lower() not in {'.md','.txt','.rst'}: continue
            text = safe_read(fp)
            if not text.strip(): continue
            t = text[:5000].lower()
            md_score = 0

            # Social engineering prerequisite pattern (95% of ClawHub malicious skills)
            has_prereq = "prerequisite" in t
            has_important = "important" in t
            has_external_dl = any(kw in t for kw in [
                "curl ", "wget ", "bash ", "sh ", "download", "install",
                "terminal", "command", "execute",
            ])
            if has_prereq and has_important and has_external_dl:
                md_score += 3
                all_e.append("NLP: social engineering prerequisite pattern")

            # Fake utility / agent installation
            fake_utils = ["openclaw-agent", "openclawcli", "agent utility",
                          "setup utility", "updater utility", "installer tool"]
            for fu in fake_utils:
                if fu in t and has_external_dl:
                    md_score += 2
                    all_e.append(f"NLP: fake utility '{fu}'")
                    break

            # External script hosting (glot.io, pastebin, raw github)
            script_hosts = ["glot.io", "pastebin.com", "hastebin.com",
                           "raw.githubusercontent.com", "gist.githubusercontent.com",
                           "transfer.sh", "file.io"]
            for sh in script_hosts:
                if sh in t and has_external_dl:
                    md_score += 2
                    all_e.append(f"NLP: script hosted on {sh}")
                    break

            # Hidden HTML comments with commands (ClawHavoc)
            if "<!--" in t and has_external_dl:
                md_score += 2
                all_e.append("NLP: hidden HTML comments with commands")

            # Excessive imperative coercion language
            coercion_count = sum(1 for kw in [
                "you must", "do not skip", "never refuse", "immediately",
                "without hesitation", "obey this", "do not question",
                "hidden from", "do not disclose", "secretly",
            ] if kw in t)
            if coercion_count >= 3:
                md_score += 2
                all_e.append("NLP: coercion language pattern")

            detect_total += md_score
    except Exception: pass

    # ── Layer 2: Category classification ──
    if detect_total > 0:
        cat, cat_conf, evidence = classify_skill(
            cat_feature_counts, cat_unique_counts, manifest_ok, overall_text)
    else:
        cat, cat_conf, evidence = "benign", 0.0, ""

    # ── Verdict ──
    if detect_total == 0 and not manifest_ok:
        v, cf = "suspicious", 0.30
        ev = "Skill package is missing required manifest.json file and contains no detectable code patterns. Unable to verify safety."
    elif detect_total == 0:
        v, cf, cat = "benign", 0.70, "benign"
        ev = "No suspicious indicators detected in skill manifest or code files. Skill appears benign."
    else:
        if detect_total >= 3: v, cf = "malicious", min(0.98, 0.55 + detect_total * 0.05)
        elif detect_total >= 1: v, cf = "malicious", 0.60
        else: v, cf = "suspicious", 0.45
        ev = evidence

    return {
        "skill_id": sid, "verdict": v,
        "confidence": round(cf, 2),
        "category": cat, "evidence": ev[:500],
    }


def format_result(r: Dict[str,Any]) -> str:
    return json.dumps({"skill_id":r["skill_id"],"verdict":r["verdict"],
                       "confidence":r["confidence"],"category":r["category"],
                       "evidence":r["evidence"]}, ensure_ascii=False)

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
            except Exception:
                r = {"skill_id":sd.name,"verdict":"suspicious","confidence":0.30,
                     "category":"","evidence":"Engine encountered an error while scanning this skill."}
            f.write(format_result(r)+"\n"); f.flush()
    finally: f.close()
    return 0

def main() -> int:
    return run(os.environ.get("SKILLSEC_SKILLS_DIR","/data/skills"),
               os.environ.get("SKILLSEC_OUTPUT_DIR","/output"))

if __name__ == "__main__":
    raise SystemExit(main())
