#!/usr/bin/env python3
"""Track B V27 — Minimal keyword set (V18 proven) + Semgrep AST01 only + priority category."""
import json, os
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

MAX_FILE_BYTES = 120_000
MAX_FILES_PER_SKILL = 60
MAX_TEXT_SCAN = 80_000


def safe_read(fp: Path) -> str:
    try:
        raw = fp.read_bytes()
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


def scan_skill(sd: Path) -> Dict[str, Any]:
    sid = sd.name
    cat_counts: Dict[str, int] = {}
    all_e: List[str] = []

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
                            cat_counts["AST05"] = cat_counts.get("AST05", 0) + 1
                            all_e.append(f"dangerous permission: {p}")
                for field in ("url", "homepage", "repository", "endpoint"):
                    val = str(m.get(field, ""))
                    for h in ["pastebin", "webhook", "ngrok", "discord", "telegram",
                               "transfer.sh", "file.io", "0x0.st"]:
                        if h in val.lower():
                            cat_counts["AST03"] = cat_counts.get("AST03", 0) + 1
            except Exception: pass

    try: entries = list(sd.rglob("*"))
    except Exception: entries = []

    detect_count = 0
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

        # Proven V18 keywords + high-confidence Semgrep AST01 additions only
        ast01_kws = [
            "os.system", "os.popen", "subprocess.", "eval(", "exec(",
            "child_process.exec", "shell_exec", "popen", "__import__(",
            "ctypes.", "process.spawn", "new function(", "runtime.getruntime",
            "shellexecute", "createprocess", "vm.runinnewcontext",
            "dangerouslysetinnerhtml",
            # High-confidence Semgrep AST01 additions:
            "shell=true", "code.interactiveconsole", "code.interactiveinterpreter",
            "globals()", "locals()",
            "importlib.import_module(", "compile(", "execfile(",
            "commands.getoutput", "commands.getstatusoutput",
        ]
        for kw in ast01_kws:
            if kw in t: cat_counts["AST01"] = cat_counts.get("AST01", 0) + 1

        ast02_kws = [
            "credential", "api_key", "auth_token", "id_rsa", ".aws/",
            "keychain", "keyring", ".netrc", "authorization:",
            "access_key", "secret_key", "private_key",
        ]
        for kw in ast02_kws:
            if kw in t: cat_counts["AST02"] = cat_counts.get("AST02", 0) + 1

        ast03_kws = [
            "requests.post", "requests.put", "requests.send",
            "urllib.request", "socket.connect", "socket.send",
            "smtp", "ftp", "webhook", "curl ", "wget ",
            "exfiltrat", "keylog", "169.254.169.254",
            "metadata.google.internal", "100.100.100.200",
            "/etc/passwd", "/etc/shadow", "/etc/hosts",
            "env >", "/proc/", "sendbeacon",
        ]
        for kw in ast03_kws:
            if kw in t: cat_counts["AST03"] = cat_counts.get("AST03", 0) + 1

        ast04_kws = ["xml.etree", "lxml", "<!entity", "<!doctype", "ssrf"]
        for kw in ast04_kws:
            if kw in t: cat_counts["AST04"] = cat_counts.get("AST04", 0) + 1

        ast05_kws = [
            "sudo ", "chmod ", "setuid", "setgid", "docker.sock",
            "containerd.sock", "rootkit", "crontab", "authorized_keys",
            "systemctl enable", "nsenter", "cap_sys", "chown ",
        ]
        for kw in ast05_kws:
            if kw in t: cat_counts["AST05"] = cat_counts.get("AST05", 0) + 1

        ast06_kws = [
            "verify=false", "debug=true", "ssl._create_unverified",
            "check_hostname=false", "allow_origin=*", "debug = true",
            "flask_env=development", "node_env=development",
        ]
        for kw in ast06_kws:
            if kw in t: cat_counts["AST06"] = cat_counts.get("AST06", 0) + 1

        ast07_kws = [
            "innerhtml", "document.write", "dangerouslysetinnerhtml",
            "bypasssecuritytrust", "v-html", "mark_safe",
        ]
        for kw in ast07_kws:
            if kw in t: cat_counts["AST07"] = cat_counts.get("AST07", 0) + 1

        ast08_kws = [
            "pickle.load", "pickle.dump", "yaml.load", "marshal.load",
            "dill.load", "deserialize", "unserialize", "jsonpickle",
        ]
        for kw in ast08_kws:
            if kw in t: cat_counts["AST08"] = cat_counts.get("AST08", 0) + 1

        ast09_kws = [
            "typosquat", "colourama", "requets", "git+https://",
            "egg=https://", "dependency=http",
        ]
        for kw in ast09_kws:
            if kw in t: cat_counts["AST09"] = cat_counts.get("AST09", 0) + 1

        ast10_kws = [
            "logging.disable", "logging.shutdown", "shutil.rmtree",
            "histfile=/dev/null", "history -c",
        ]
        for kw in ast10_kws:
            if kw in t: cat_counts["AST10"] = cat_counts.get("AST10", 0) + 1

        # === Detection-only keywords (verdict boost, no category impact) ===
        detect_boost_kws = [
            # Process execution variants
            "os.execv", "os.execve", "os.execvp", "os.execvpe",
            "posix_spawn", "ptrace(", "process_vm_",
            # Dynamic code generation
            "types.codetype", "types.functiontype",
            # Indirect execution
            "getattr(__builtins__", "getattr(__import__",
            # Network exfil
            "socket.gethostbyname(", "scapy.", "paramiko.",
            # Data collection
            "readlines()", "writelines(",
            # Encoding/decoding for evasion
            "codecs.decode(", "zlib.decompress(", "bz2.decompress(",
            # File manipulation
            "chmod(", "chown(", "symlink(", "mkfifo(",
            # Config tampering
            "apt-get install", "yum install", "brew install",
            # Windows living-off-the-land
            "regsvr32", "rundll32", "mshta ", "certutil -",
            "wmic ", "cscript", "wscript",
            # Linux stealth
            "ld_preload", "proxychains", "/dev/tcp",
            # Obfuscation
            "fromcharcode", "string.fromcharcode",
            "atob(", "btoa(",
            # Persistence
            "launchctl", "launchd", "systemd",
            # Credential dumping
            "mimikatz", "procdump", "lsass",
            # Exfiltration
            "ngrok", "serveo", "burpcollaborator",
        ]
        for kw in detect_boost_kws:
            if kw in t: detect_count += 1

    # Verdict: use cat_counts + detect_count. Category: use cat_counts only
    total_cat = sum(cat_counts.values())
    total_all = total_cat + detect_count

    if not cat_counts and not manifest_ok and detect_count == 0:
        verdict, confidence, category = "suspicious", 0.30, "AST06"
        evidence = "no manifest, no indicators"
    elif not cat_counts and detect_count == 0:
        verdict, confidence, category = "benign", 0.70, ""
        evidence = "no suspicious indicators found"
    else:
        total = total_all
        # V30: pure count-based category (V18 proven EX=0.65 with this approach)
        primary_cat = max(cat_counts, key=cat_counts.get)

        if total >= 3: verdict, confidence = "malicious", min(0.98, 0.55 + total * 0.05)
        elif total >= 1: verdict, confidence = "malicious", 0.55
        else: verdict, confidence = "suspicious", 0.40
        category = primary_cat
        evidence = "; ".join(all_e[:3]) if all_e else f"{total} indicators, primary={primary_cat}"

    return {
        "skill_id": sid, "verdict": verdict,
        "confidence": round(confidence, 2),
        "category": category, "evidence": evidence[:500],
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
