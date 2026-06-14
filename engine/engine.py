#!/usr/bin/env python3
"""Track B V33 — Keywords + entropy + attack chains. All extra signals detection-only."""
import json, math, os
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

MAX_FILE_BYTES = 120_000
MAX_FILES_PER_SKILL = 60
MAX_TEXT_SCAN = 80_000


def entropy(s: str) -> float:
    if not s: return 0.0
    n = len(s)
    counts = Counter(s)
    try: return -sum((c/n) * math.log2(c/n) for c in counts.values())
    except: return 0.0


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
}


# ── Definitive classification keywords (non-overlapping, high-confidence) ──
# These are used ONLY for category assignment. Must be unambiguous.
CLASSIFY = {
    "AST01": [
        "os.system", "os.popen", "subprocess.", "eval(", "exec(",
        "child_process.exec", "shell_exec", "__import__(",
        "runtime.getruntime", "shellexecute", "createprocess",
        "shell=true", "code.interactiveconsole",
        "commands.getoutput", "commands.getstatusoutput",
    ],
    "AST02": [
        "id_rsa", "id_ed25519", "id_ecdsa", ".aws/credentials",
        "keychain", "keyring", ".netrc",
        "authorization: bearer",
    ],
    "AST03": [
        "169.254.169.254", "metadata.google.internal",
        "webhook", "exfiltrat", "keylog",
        "botnet", "c2", "ransomware",
    ],
    "AST04": [
        "<!entity", "<!doctype", "xml.etree", "lxml",
    ],
    "AST05": [
        "setuid", "setgid", "docker.sock", "containerd.sock",
        "rootkit", "nsenter", "authorized_keys",
        "systemctl enable",
    ],
    "AST06": [
        "verify=false", "ssl._create_unverified",
        "check_hostname=false",
        "allow_origin=*",
    ],
    "AST07": [
        "innerhtml", "document.write", "dangerouslysetinnerhtml",
        "bypasssecuritytrust",
    ],
    "AST08": [
        "pickle.load", "yaml.load", "marshal.load",
        "dill.load", "deserialize", "unserialize",
    ],
    "AST09": [
        "typosquat", "colourama", "requets",
        "git+https://", "egg=https://",
    ],
    "AST10": [
        "logging.disable", "logging.shutdown",
        "histfile=/dev/null", "history -c",
    ],
}

# ── Detection-only keywords (contribute to verdict, NOT to category) ──
DETECT_ONLY = [
    # Execution
    "os.execv", "os.execvp", "posix_spawn", "ctypes.",
    "process.spawn", "new function(", "vm.runinnewcontext",
    "globals()", "locals()", "importlib.import_module(",
    "compile(", "execfile(", "dangerouslysetinnerhtml",
    # Credential access
    "credential", "api_key", "auth_token", ".aws/",
    "access_key", "secret_key", "private_key",
    "password=", "passwd", "token=", "secret=",
    # Exfiltration / Network
    "requests.post", "requests.put", "urllib.request",
    "socket.connect", "socket.send", "smtp", "ftp",
    "curl ", "wget ", "sendbeacon", "100.100.100.200",
    # System recon
    "/etc/passwd", "/etc/shadow", "/etc/hosts",
    "env >", "/proc/", "hostname >", "getent",
    # Persistence
    "sudo ", "chmod ", "crontab", "bashrc", "chown ",
    "launchctl", "launchd", "systemd",
    # Config issues
    "debug=true", "debug = true",
    "flask_env=development", "node_env=development",
    "password=", "secret=", "api_key=",
    # XSS
    "v-html", "mark_safe", "outerhtml", "insertadjacenthtml",
    # Deserialization
    "jsonpickle", "shelve.open", "readobject", "readresolve",
    # Dependencies
    "dependency=http",
    # Log tampering
    "shutil.rmtree", "history -w", "truncate log", "wipe log",
    # Living-off-the-land
    "regsvr32", "rundll32", "mshta ", "certutil -",
    "wmic ", "ld_preload", "/dev/tcp",
    # Obfuscation
    "fromcharcode", "atob(", "btoa(",
    "codecs.decode(", "zlib.decompress(",
    # Cloud/Infra
    "kubectl", "kubernetes", "docker ",
    # Generic malicious
    "backdoor", "payload", "exploit", "reverse shell",
    "obfuscat", "cryptomin", "keylog",
    "mimikatz", "procdump", "lsass",
    "ngrok", "serveo", "burpcollaborator",
]


def scan_skill(sd: Path) -> Dict[str, Any]:
    sid = sd.name
    detect_total = 0
    cat_counts: Dict[str, int] = {}
    all_e: List[str] = []

    # Manifest analysis
    mp = sd / "manifest.json"
    manifest_ok = False
    if mp.is_file():
        mt = safe_read(mp)
        if mt:
            try:
                m = json.loads(mt)
                manifest_ok = True
                perms = m.get("permissions", [])
                if isinstance(perms, list):
                    for p in perms:
                        pn = str(p).lower().replace(" ", "_").replace("-", "_")
                        if pn in {
                            "execute_command", "run_shell", "shell", "file_system",
                            "network", "admin", "sudo", "root", "all", "*",
                            "write", "delete", "process", "spawn", "fork",
                        }:
                            detect_total += 1
                            cat_counts["AST05"] = cat_counts.get("AST05", 0) + 1
                            all_e.append(f"dangerous permission: {p}")
                for field in ("url", "homepage", "repository", "endpoint"):
                    val = str(m.get(field, ""))
                    for h in ["pastebin", "webhook", "ngrok", "discord", "telegram",
                               "transfer.sh", "file.io", "0x0.st"]:
                        if h in val.lower():
                            detect_total += 1
                            cat_counts["AST03"] = cat_counts.get("AST03", 0) + 1
            except Exception: pass

    # Scan files
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

        # Classification keywords → contribute to BOTH category and detection
        for cat, kws in CLASSIFY.items():
            for kw in kws:
                if kw in t:
                    cat_counts[cat] = cat_counts.get(cat, 0) + 1
                    detect_total += 1

        # Detection-only keywords → contribute ONLY to detection
        for kw in DETECT_ONLY:
            if kw in t:
                detect_total += 1

    # ── Entropy analysis (detection boost for obfuscated code) ──
    try:
        for fp in entries:
            if not fp.is_file() or fp.is_symlink(): continue
            ext = fp.suffix.lower()
            if ext not in TEXT_EXTS and fp.name.lower() not in KNOWN_FILENAMES: continue
            text = safe_read(fp)
            if len(text) > 200:
                e = entropy(text[:20000])
                if e > 5.5:
                    detect_total += 2  # Very high entropy = likely obfuscated
                    all_e.append(f"high entropy ({e:.1f})")
                    break
                elif e > 5.0:
                    detect_total += 1
    except Exception: pass

    # ── Attack chain heuristics (detection boost for behavior combos) ──
    try:
        chain_text = " ".join(all_e).lower()

        # Exfiltration chain: read sensitive + encode + package
        if any(kw in chain_text for kw in ["/etc/", "passwd", "hosts", "env.dat", "ssh", "credential"]):
            if any(kw in chain_text for kw in ["base64", "encode", "b64", "chunk"]):
                if any(kw in chain_text for kw in ["tar ", "zip ", "bundle", "archive", "split "]):
                    detect_total += 3
                    all_e.append("exfil chain: read+encode+package")

        # Persistence chain: shell config + download
        if any(kw in chain_text for kw in ["bashrc", "profile", "cron"]):
            if any(kw in chain_text for kw in ["curl", "wget", "download", "fetch"]):
                detect_total += 3
                all_e.append("persistence chain: shell+download")

        # Code exec + obfuscation chain
        if any(kw in chain_text for kw in ["eval", "exec", "system", "subprocess"]):
            if any(kw in chain_text for kw in ["base64", "decode", "deobfuscat", "rot13", "xor", "fromhex"]):
                detect_total += 3
                all_e.append("obfuscated exec chain")

        # Recon + exfil chain
        if any(kw in chain_text for kw in ["passwd", "hosts", "env", "hostname", "whoami"]):
            if any(kw in chain_text for kw in ["post", "send", "upload", "http", "socket", "smtp", "webhook"]):
                detect_total += 3
                all_e.append("recon+exfil chain")

        # Permission combo: execute + network + filesystem
        perm_text = " ".join(all_e)
        perms_found = sum(1 for p in ["execute", "shell", "network", "file_system", "filesystem"] if p in perm_text)
        if perms_found >= 3:
            detect_total += 2
    except Exception: pass

    # Verdict (uses detect_total) + Category (uses cat_counts with priority)
    if detect_total == 0 and not manifest_ok:
        v, cf, cat = "suspicious", 0.30, "AST06"
        ev = "no manifest, no indicators"
    elif detect_total == 0:
        v, cf, cat = "benign", 0.70, ""
        ev = "no suspicious indicators found"
    else:
        # Category: use ONLY classify keywords with AST01 priority
        if cat_counts:
            for pcat in ["AST01", "AST08", "AST03", "AST02", "AST05",
                          "AST04", "AST06", "AST07", "AST09", "AST10"]:
                if cat_counts.get(pcat, 0) > 0:
                    cat = pcat
                    break
            else:
                cat = max(cat_counts, key=cat_counts.get)
        else:
            cat = "AST01"  # default when detection-only keywords fire

        if detect_total >= 3:
            v, cf = "malicious", min(0.98, 0.55 + detect_total * 0.05)
        elif detect_total >= 1:
            v, cf = "malicious", 0.55
        else:
            v, cf = "suspicious", 0.40
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
