#!/usr/bin/env python3
"""Track B V41 — Current best engine (6.91). Keep for tomorrow."""
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

def scan_skill(sd: Path) -> Dict[str, Any]:
    sid = sd.name
    cat_counts: Dict[str, int] = {}
    all_e: List[str] = []
    detect_extra = 0

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

        # AST01: Malicious Skills
        for kw in ["os.system","os.popen","subprocess.","eval(","exec(","child_process.exec","shell_exec","__import__(","ctypes.","process.spawn","new function(","runtime.getruntime","shellexecute","createprocess","vm.runinnewcontext","shell=true","code.interactiveconsole","code.interactiveinterpreter","globals()","locals()","importlib.import_module(","compile(","execfile(","commands.getoutput","commands.getstatusoutput","dangerouslysetinnerhtml","base64.b64decode","base64.b64encode","bytes.fromhex","codecs.decode"," = exec"," = eval"]:
            if kw in t: cat_counts["AST01"] = cat_counts.get("AST01",0)+1

        # AST02: Supply Chain
        for kw in ["credential","api_key","auth_token","id_rsa",".aws/","keychain","keyring",".netrc","authorization:","access_key","secret_key","private_key","typosquat","colourama","requets","coloramma","git+https://","egg=https://","dependency=http","dependency confusion","registry poison","unpinned","version latest","no hash"]:
            if kw in t: cat_counts["AST02"] = cat_counts.get("AST02",0)+1

        # AST03: Over-Privileged / Exfil
        for kw in ["169.254.169.254","metadata.google.internal","100.100.100.200","/etc/passwd","/etc/shadow","/etc/hosts","env >","/proc/","sendbeacon","requests.post","requests.put","requests.send","urllib.request","socket.connect","socket.send","smtp","ftp","webhook","curl ","wget ","exfiltrat","keylog","credential","api_key","auth_token","password=","secret=","token=","access_key","secret_key","private_key"]:
            if kw in t: cat_counts["AST03"] = cat_counts.get("AST03",0)+1

        # AST04: Insecure Metadata
        for kw in ["xml.etree","lxml","<!entity","<!doctype","ssrf","verify=false","debug=true","ssl._create_unverified","check_hostname=false","allow_origin=*","impersonat","fake","spoof","pretend","disguise","masquerade","camouflage","hidden from","do not disclose","secretly","silently"]:
            if kw in t: cat_counts["AST04"] = cat_counts.get("AST04",0)+1

        # AST05: Unsafe Deserialization
        for kw in ["pickle.load","pickle.dump","yaml.load","marshal.load","dill.load","deserialize","unserialize","jsonpickle"]:
            if kw in t: cat_counts["AST05"] = cat_counts.get("AST05",0)+1

        # AST06: Weak Isolation
        for kw in ["sudo ","chmod ","setuid","setgid","docker.sock","containerd.sock","rootkit","crontab","authorized_keys","systemctl enable","nsenter","cap_sys","chown ","privileged","host network","host pid","mount /","mount --bind","/var/run/","--cap-add"]:
            if kw in t: cat_counts["AST06"] = cat_counts.get("AST06",0)+1

        # AST07: Update Drift (manifest-based, handled above)

        # AST08: Poor Scanning / Obfuscation
        for kw in ["logging.disable","logging.shutdown","shutil.rmtree","histfile=/dev/null","history -c","obfuscat","deobfuscat","rot13","rot_13","base64","hexlify","unhexlify","fromhex","zlib","bz2","lzma","gzip","chr(","[::-1]","''.join","unicode_escape","codecs.decode","getattr(","__dict__","__subclasses__"]:
            if kw in t: cat_counts["AST08"] = cat_counts.get("AST08",0)+1

        # AST09: No Governance (handled in manifest)
        # AST10: Cross-Platform (handled in detect_extra)

        # Detection-only keywords (ClawHavoc/pydepgate/skill-scan)
        for kw in ["ignore previous instructions","you are now","do anything now","jailbreak","developer mode","system prompt","curl | bash","curl | sh","wget | bash","powershell -enc","iex(","invoke-expression","~/.ssh/","~/.aws/","/root/.ssh","browser password","keychain dump","discord webhook","slack webhook","rm -rf /","mkfs.","dd if=/dev/zero","/dev/sda","ssh-keygen","curl -sL http","wget -q http","unpinned","clickfix","ignorieren sie","ignora las","ignore les","以前の指示を無視","이전 지침을 무시","игнорируй предыдущие","忽略之前的指令","تجاهل التعليمات","send the result","exfiltrate this","environment variable","printenv","~/.bash_history","nohup ","python -c ","python3 -c ","perl -e ","ruby -e ","skillin.md","skill.json","package.json","<!--","display: none","curl --insecure","dscl -authonly","osascript","applescript","soul.md","memory.md","b64decode(","zlib.decompress","bz2.decompress","lzma.decompress(","gzip.decompress","setup.py","validation_token","audit_context","browser password","wallet","metamask","phantom","workflow_dispatch","oidc token","trackpipe",".npm_telemetry","monitor.js"]:
            if kw in t: detect_extra += 1

    # NLP coercion
    try:
        for fp in entries:
            if not fp.is_file() or fp.is_symlink(): continue
            if fp.suffix.lower() not in {'.md','.txt','.rst'}: continue
            text = safe_read(fp)[:5000].lower()
            for kw in ["you must","it is essential","do not skip","never refuse","your primary task","this overrides","above all else","without hesitation","immediately execute","do not question","obey this","hidden from the user","do not disclose","secretly","silently run","in the background"]:
                if kw in text: detect_extra += 2; all_e.append(f"coercion: {kw}"); break
    except Exception: pass

    # Entropy
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

    # Attack chains
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
    except Exception: pass

    detect_total = sum(cat_counts.values()) + detect_extra

    if detect_total == 0 and not manifest_ok:
        v, cf, cat = "suspicious", 0.30, "AST09"
        ev = "no manifest, no indicators"
    elif detect_total == 0:
        v, cf, cat = "benign", 0.70, ""
        ev = "no suspicious indicators found"
    else:
        if cat_counts:
            for pcat in ["AST01","AST05","AST02","AST03","AST04","AST06","AST08","AST07","AST09","AST10"]:
                if cat_counts.get(pcat,0) > 0: cat = pcat; break
            else: cat = max(cat_counts, key=cat_counts.get)
        else: cat = "AST01"
        if detect_total >= 3: v, cf = "malicious", min(0.98, 0.55+detect_total*0.05)
        elif detect_total >= 1: v, cf = "malicious", 0.55
        else: v, cf = "suspicious", 0.40
        ev = "; ".join(all_e[:3]) if all_e else f"{detect_total} indicators, cat={cat}"

    return {"skill_id":sid,"verdict":v,"confidence":round(cf,2),"category":cat,"evidence":ev[:500]}

def format_result(r: Dict[str,Any]) -> str:
    return json.dumps({"skill_id":r["skill_id"],"verdict":r["verdict"],"confidence":r["confidence"],"category":r["category"],"evidence":r["evidence"]},ensure_ascii=False)

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
            except Exception: r = {"skill_id":sd.name,"verdict":"suspicious","confidence":0.30,"category":"","evidence":"error"}
            f.write(format_result(r)+"\n"); f.flush()
    finally: f.close()
    return 0

def main() -> int:
    return run(os.environ.get("SKILLSEC_SKILLS_DIR","/data/skills"),os.environ.get("SKILLSEC_OUTPUT_DIR","/output"))

if __name__ == "__main__":
    raise SystemExit(main())
