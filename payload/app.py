#!/usr/bin/env python3
"""reconFTW Control Panel — visual operator UI. Created by ZynTarvo."""

import io
import json
import os
import re
import secrets
import shlex
import shutil
import signal
import subprocess
import threading
import time
import zipfile

import findings as F
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import (
    Flask,
    Response,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    send_from_directory,
    session,
)
from flask_socketio import SocketIO, emit

# ── paths / env ──────────────────────────────────────────────────────────────
ROOT = Path(__file__).resolve().parent
DATA = ROOT / "data"
JOBS_DIR = DATA / "jobs"
TARGETS_DIR = DATA / "targets"
LOGS_DIR = DATA / "logs"
NC_FILE = DATA / "notifications.json"
NOTIF_FILE = DATA / "notify_settings.json"
for p in (DATA, JOBS_DIR, TARGETS_DIR, LOGS_DIR):
    p.mkdir(parents=True, exist_ok=True)

def _load_env_file(path):
    p = Path(path)
    if not p.is_file():
        return
    for raw in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip().strip("'").strip('"'))

_load_env_file(ROOT / ".env")

RECONFTW_DIR = Path(os.environ.get("RECONFTW_DIR", "/root/reconftw"))
RECONFTW_SH = RECONFTW_DIR / "reconftw.sh"
RECONFTW_CFG = RECONFTW_DIR / "reconftw.cfg"
SECRETS_CFG = RECONFTW_DIR / "secrets.cfg"
INSTALL_LOG = RECONFTW_DIR / "install.log"
INSTALL_DONE = RECONFTW_DIR / ".panel_install_done"
OUTPUT_DIR = Path(os.environ.get("RECONFTW_OUTPUT", str(RECONFTW_DIR / "Recon")))
TOOLS_DIR = Path(os.environ.get("RECONFTW_TOOLS", "/root/Tools"))

PANEL_HOST = os.environ.get("PANEL_HOST", "0.0.0.0")
PANEL_PORT = int(os.environ.get("PANEL_PORT", "8443"))
PANEL_USER = os.environ.get("PANEL_USER", "root")
PANEL_PASS = os.environ.get("PANEL_PASS", "")
PANEL_VERSION = "1.0.0"

JOBS_FILE = DATA / "jobs.json"
_jobs_lock = threading.Lock()
_nc_lock = threading.Lock()
_followers = {}  # job_id -> stop event

# ── flask ────────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("PANEL_SECRET") or secrets.token_hex(32)
app.config["PERMANENT_SESSION_LIFETIME"] = 86400
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")


@app.context_processor
def _inject_panel():
    return {"panel_version": PANEL_VERSION}


def auth(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not session.get("ok"):
            if request.is_json or request.path.startswith("/api/"):
                return jsonify(error="Unauthorized"), 401
            return redirect("/login")
        return fn(*a, **kw)
    return wrapper


# ── reconFTW visual maps ─────────────────────────────────────────────────────
MODES = [
    {"id": "r", "name": "Recon", "icon": "fa-satellite-dish",
     "desc": "Full reconnaissance. Subdomains, web, OSINT. No active vuln attacks."},
    {"id": "s", "name": "Subdomains", "icon": "fa-sitemap",
     "desc": "Subdomain enumeration, live web probe, takeover checks."},
    {"id": "p", "name": "Passive", "icon": "fa-user-secret",
     "desc": "Passive only. No direct hitting of the target."},
    {"id": "a", "name": "All + vulns", "icon": "fa-burst",
     "desc": "Full recon plus active vulnerability checks. Heavy and noisy."},
    {"id": "w", "name": "Web", "icon": "fa-globe",
     "desc": "Web analysis on already known URLs."},
    {"id": "n", "name": "OSINT", "icon": "fa-binoculars",
     "desc": "OSINT only: emails, leaks, dorks, metadata. No subdomain brute."},
    {"id": "z", "name": "Zen", "icon": "fa-leaf",
     "desc": "Light recon. Faster, fewer modules."},
    {"id": "c", "name": "Custom", "icon": "fa-sliders",
     "desc": "Run one selected module from the list below."},
]

SCAN_OPTIONS = [
    {"id": "deep", "flag": "--deep", "label": "Deep scan",
     "hint": "Slower and more thorough. Recommended on a VPS."},
    {"id": "incremental", "flag": "--incremental", "label": "Incremental",
     "hint": "Only new findings since the last run."},
    {"id": "adaptive", "flag": "--adaptive-rate", "label": "Adaptive rate",
     "hint": "Slow down automatically on 429 / 503."},
    {"id": "dry_run", "flag": "--dry-run", "label": "Dry run",
     "hint": "Show the plan. Do not actually scan."},
    {"id": "parallel", "flag": "--parallel", "label": "Parallel",
     "hint": "Faster, uses more RAM. This box has 4 GB — keep off unless idle."},
    {"id": "no_parallel", "flag": "--no-parallel", "label": "Force sequential",
     "hint": "One module at a time. Safer on small servers."},
    {"id": "quick_rescan", "flag": "--quick-rescan", "label": "Quick rescan",
     "hint": "Skip heavy stages when nothing new appeared."},
    {"id": "ai", "flag": "-y", "label": "AI report",
     "hint": "Generate an AI analysis of results (needs local model)."},
    {"id": "export_html", "flag": "--export", "value": "html", "label": "HTML export",
     "hint": "Rebuild HTML report artifacts."},
]

CUSTOM_FUNCS = [
    {"id": "osint", "label": "OSINT pack"},
    {"id": "google_dorks", "label": "Google dorks"},
    {"id": "github_dorks", "label": "GitHub dorks"},
    {"id": "metadata", "label": "Document metadata"},
    {"id": "emails", "label": "Email harvesting"},
    {"id": "domain_info", "label": "WHOIS / domain info"},
    {"id": "sub_passive", "label": "Passive subdomains"},
    {"id": "sub_crt", "label": "Certificate Transparency"},
    {"id": "sub_brute", "label": "DNS bruteforce"},
    {"id": "sub_permut", "label": "Subdomain permutations"},
    {"id": "sub_takeover", "label": "Subdomain takeover"},
    {"id": "zonetransfer", "label": "DNS zone transfer"},
    {"id": "webprobe_full", "label": "Live web probe"},
    {"id": "screenshot", "label": "Screenshots"},
    {"id": "virtualhosts", "label": "Virtual hosts"},
    {"id": "urlchecks", "label": "URL collection"},
    {"id": "jschecks", "label": "JavaScript analysis"},
    {"id": "fuzzing", "label": "Directory fuzzing"},
    {"id": "cms_scanner", "label": "CMS detection"},
    {"id": "portscan", "label": "Port scan"},
    {"id": "nuclei_check", "label": "Nuclei templates"},
    {"id": "xss", "label": "XSS checks"},
    {"id": "ssrf_checks", "label": "SSRF checks"},
    {"id": "sqli", "label": "SQLi checks"},
    {"id": "lfi", "label": "LFI checks"},
    {"id": "ssti", "label": "SSTI checks"},
    {"id": "crlf_checks", "label": "CRLF checks"},
    {"id": "smuggling", "label": "HTTP smuggling"},
    {"id": "test_ssl", "label": "SSL / TLS"},
]

MODULE_GROUPS = [
    ("OSINT", [
        "OSINT", "GOOGLE_DORKS", "GITHUB_DORKS", "GITHUB_REPOS", "METADATA",
        "EMAILS", "DOMAIN_INFO", "IP_INFO", "API_LEAKS", "THIRD_PARTIES",
        "SPOOF", "MAIL_HYGIENE", "CLOUD_ENUM", "GITHUB_LEAKS",
    ]),
    ("Subdomains", [
        "SUBDOMAINS_GENERAL", "SUBPASSIVE", "SUBCRT", "SUBANALYTICS", "SUBBRUTE",
        "SUBSCRAPING", "SUBPERMUTE", "SUBIAPERMUTE", "SUBREGEXPERMUTE",
        "SUBTAKEOVER", "ZONETRANSFER", "S3BUCKETS", "REVERSE_IP", "ASN_ENUM",
        "SRV_ENUM", "NS_DELEGATION",
    ]),
    ("Web", [
        "WEBPROBEFULL", "WEBSCREENSHOT", "VIRTUALHOSTS", "FAVIRECON",
        "URL_CHECK", "URL_CHECK_PASSIVE", "URL_CHECK_ACTIVE", "URL_GF",
        "JSCHECKS", "FUZZ", "CMS_SCANNER", "WORDLIST", "GRAPHQL_CHECK",
        "PARAM_DISCOVERY",
    ]),
    ("Hosts", [
        "PORTSCANNER", "GEO_INFO", "PORTSCAN_PASSIVE", "PORTSCAN_ACTIVE",
        "NAABU_ENABLE", "CDN_IP", "WAF_DETECTION",
    ]),
    ("Vulnerabilities", [
        "VULNS_GENERAL", "NUCLEICHECK", "XSS", "TEST_SSL", "SSRF_CHECKS",
        "CRLF_CHECKS", "LFI", "SSTI", "SQLI", "SQLMAP", "BROKENLINKS",
        "COMM_INJ", "SMUGGLING", "WEBCACHE", "FUZZPARAMS", "NUCLEI_DAST",
    ]),
    ("Engine", [
        "DEEP", "DIFF", "NOTIFICATION", "SOFT_NOTIFICATION", "PARALLEL_MODE",
        "INCREMENTAL_MODE", "ADAPTIVE_RATE_LIMIT", "PRESERVE", "REMOVETMP",
        "REMOVELOG", "QUICK_RESCAN", "ASSET_STORE",
    ]),
]

SECRET_FIELDS = [
    {
        "id": "SHODAN_API_KEY",
        "label": "Shodan",
        "hint": "Passive port data",
        "url": "https://account.shodan.io/",
        "url_label": "account.shodan.io",
    },
    {
        "id": "PDCP_API_KEY",
        "label": "ProjectDiscovery Cloud",
        "hint": "subfinder / asnmap",
        "url": "https://cloud.projectdiscovery.io/settings/api-key",
        "url_label": "cloud.projectdiscovery.io/settings/api-key",
    },
    {
        "id": "WHOISXML_API",
        "label": "WhoisXML",
        "hint": "WHOIS lookups",
        "url": "https://user.whoisxmlapi.com/products",
        "url_label": "user.whoisxmlapi.com",
    },
    {
        "id": "XSS_SERVER",
        "label": "Blind XSS server",
        "hint": "Collaborator / XSS hunter URL",
        "url": "https://xss.report/dashboard#settings",
        "url_label": "xss.report/dashboard#settings",
    },
    {
        "id": "COLLAB_SERVER",
        "label": "SSRF collaborator",
        "hint": "interactsh / similar",
        "url": "https://app.interactsh.com/",
        "url_label": "app.interactsh.com",
    },
    {
        "id": "GITHUB_TOKENS",
        "label": "GitHub tokens",
        "hint": "One token per line",
        "multiline": True,
        "file": True,
        "url": "https://github.com/settings/tokens",
        "url_label": "github.com/settings/tokens",
    },
    {
        "id": "GITLAB_TOKENS",
        "label": "GitLab tokens",
        "hint": "One token per line",
        "multiline": True,
        "file": True,
        "url": "https://gitlab.com/-/user_settings/personal_access_tokens",
        "url_label": "gitlab.com/tokens",
    },
]

FE_ROOTS = [
    str(RECONFTW_DIR),
    str(OUTPUT_DIR),
    str(TOOLS_DIR),
    str(ROOT),
    "/root",
]


# ── jobs store ───────────────────────────────────────────────────────────────
def _jobs_load():
    if JOBS_FILE.is_file():
        try:
            return json.loads(JOBS_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"seq": 1, "items": []}


def _jobs_save(d):
    tmp = JOBS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(d, indent=2), encoding="utf-8")
    tmp.replace(JOBS_FILE)


def _job_get(jid):
    d = _jobs_load()
    for it in d["items"]:
        if str(it.get("id")) == str(jid):
            return d, it
    return d, None


def _job_collect(it):
    root = F.recon_dir(it.get("target"), OUTPUT_DIR, RECONFTW_DIR / "Recon")
    if not root:
        return None, None
    return root, F.collect(root)


# ── notifications ────────────────────────────────────────────────────────────
def _nc_load():
    if NC_FILE.is_file():
        try:
            return json.loads(NC_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"items": [], "seq": 1}


def _nc_save(d):
    NC_FILE.write_text(json.dumps(d), encoding="utf-8")


def nc_push(title, message, ntype="info"):
    with _nc_lock:
        d = _nc_load()
        item = {
            "id": d.get("seq", 1),
            "title": title,
            "message": message,
            "type": ntype,
            "ts": int(time.time()),
            "read": False,
        }
        d["seq"] = item["id"] + 1
        d.setdefault("items", []).insert(0, item)
        d["items"] = d["items"][:300]
        _nc_save(d)
    try:
        socketio.emit("nc_new", item)
    except Exception:
        pass
    try:
        ns = _notif_load()
        if ns.get("enabled") and ns.get("bot_token") and ns.get("chat_id"):
            _send_telegram(ns["bot_token"], ns["chat_id"], f"<b>{title}</b>\n{message}")
    except Exception:
        pass
    return item


def _notif_load():
    if NOTIF_FILE.is_file():
        try:
            return json.loads(NOTIF_FILE.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {"enabled": False, "bot_token": "", "chat_id": ""}


def _send_telegram(token, chat_id, text):
    import urllib.parse
    import urllib.request
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    data = urllib.parse.urlencode({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": "1",
    }).encode()
    req = urllib.request.Request(url, data=data)
    urllib.request.urlopen(req, timeout=12)


_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _strip_ansi(s):
    return _ANSI.sub("", s or "")
def _install_running():
    try:
        out = subprocess.check_output(
            ["pgrep", "-f", r"[.]/install\.sh|bash \./install\.sh"],
            text=True, stderr=subprocess.DEVNULL,
        )
        return bool(out.strip())
    except subprocess.CalledProcessError:
        return False
    except Exception:
        return False


def _recon_ready():
    return RECONFTW_SH.is_file() and os.access(RECONFTW_SH, os.X_OK)


def _recon_version():
    try:
        if (RECONFTW_DIR / ".git").is_dir():
            br = subprocess.check_output(
                ["git", "-C", str(RECONFTW_DIR), "rev-parse", "--abbrev-ref", "HEAD"],
                text=True, timeout=5,
            ).strip()
            tag = subprocess.check_output(
                ["git", "-C", str(RECONFTW_DIR), "describe", "--tags", "--always"],
                text=True, timeout=5,
            ).strip()
            return f"{br}-{tag}"
    except Exception:
        pass
    return "unknown"


def _install_status():
    ready = _recon_ready() and not _install_running()
    running = _install_running()
    log_tail = ""
    log_lines = 0
    if INSTALL_LOG.is_file():
        try:
            text = INSTALL_LOG.read_text(encoding="utf-8", errors="replace")
            lines = text.splitlines()
            log_lines = len(lines)
            log_tail = _strip_ansi("\n".join(lines[-40:]))
        except Exception:
            pass
    state = "missing"
    if ready and (INSTALL_DONE.is_file() or (RECONFTW_DIR / "Recon").exists() or shutil.which("subfinder") or shutil.which("httpx")):
        state = "ready"
    elif running:
        state = "installing"
    elif RECONFTW_SH.is_file():
        # cloned, installer idle — either not started or finished without marker
        if shutil.which("nuclei") or shutil.which("subfinder"):
            state = "ready"
        elif INSTALL_LOG.is_file() and "Final" in log_tail:
            state = "ready"
        elif INSTALL_LOG.is_file() and log_lines > 5:
            state = "installing" if running else "cloned"
        else:
            state = "cloned"
    return {
        "state": state,
        "ready": state == "ready",
        "running": running,
        "dir": str(RECONFTW_DIR),
        "script": RECONFTW_SH.is_file(),
        "version": _recon_version() if RECONFTW_SH.is_file() else None,
        "log_lines": log_lines,
        "log_tail": log_tail,
        "tools_hint": bool(shutil.which("subfinder") or shutil.which("nuclei")),
    }


def _detect_goroot():
    try:
        return subprocess.check_output(["go", "env", "GOROOT"], text=True, timeout=5).strip()
    except Exception:
        for cand in ("/usr/lib/go-1.26", "/usr/local/go"):
            if os.path.isdir(os.path.join(cand, "bin")):
                return cand
        return "/usr/local/go"


def _scan_env():
    env = os.environ.copy()
    goroot = env.get("GOROOT") or _detect_goroot()
    extra = [
        os.path.join(goroot, "bin"),
        "/usr/local/go/bin",
        str(Path.home() / "go" / "bin"),
        str(Path.home() / ".local" / "bin"),
        "/usr/local/bin",
        str(Path.home() / ".cargo" / "bin"),
    ]
    env["PATH"] = ":".join(extra) + ":" + env.get("PATH", "")
    env["HOME"] = str(Path.home())
    env["USER"] = "root"
    env["GOROOT"] = goroot
    env["GOPATH"] = env.get("GOPATH") or str(Path.home() / "go")
    env["PYTHONUNBUFFERED"] = "1"
    if SECRETS_CFG.is_file():
        for line in SECRETS_CFG.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip(), v.strip().strip("'").strip('"')
            if k and k not in env:
                env[k] = v
    return env


# ── cfg parse / write (boolean keys only, preserve rest) ─────────────────────
_BOOL_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(true|false)(\s*(#.*))?$")


def _cfg_bools():
    out = {}
    if not RECONFTW_CFG.is_file():
        return out
    for line in RECONFTW_CFG.read_text(encoding="utf-8", errors="replace").splitlines():
        m = _BOOL_RE.match(line.strip())
        if m:
            out[m.group(1)] = m.group(2) == "true"
    return out


def _cfg_set_bools(updates):
    if not RECONFTW_CFG.is_file():
        raise FileNotFoundError("reconftw.cfg missing")
    lines = RECONFTW_CFG.read_text(encoding="utf-8", errors="replace").splitlines(True)
    known = set()
    new = []
    for line in lines:
        raw = line.rstrip("\n")
        stripped = raw.strip()
        m = _BOOL_RE.match(stripped)
        if m and m.group(1) in updates:
            key = m.group(1)
            val = "true" if updates[key] else "false"
            comment = m.group(3) or ""
            indent = raw[: len(raw) - len(raw.lstrip())]
            new.append(f"{indent}{key}={val}{comment}\n" if line.endswith("\n") or True else f"{indent}{key}={val}{comment}")
            if not new[-1].endswith("\n"):
                new[-1] += "\n"
            known.add(key)
        else:
            new.append(line if line.endswith("\n") else line + "\n")
    RECONFTW_CFG.write_text("".join(new), encoding="utf-8")
    return list(known)


def _secrets_read():
    vals = {f["id"]: "" for f in SECRET_FIELDS}
    if SECRETS_CFG.is_file():
        for line in SECRETS_CFG.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            if k.strip() in vals:
                vals[k.strip()] = v.strip().strip("'").strip('"')
    gh = TOOLS_DIR / ".github_tokens"
    gl = TOOLS_DIR / ".gitlab_tokens"
    if gh.is_file():
        vals["GITHUB_TOKENS"] = gh.read_text(encoding="utf-8", errors="replace")
    if gl.is_file():
        vals["GITLAB_TOKENS"] = gl.read_text(encoding="utf-8", errors="replace")
    return vals


def _secrets_write(payload):
    TOOLS_DIR.mkdir(parents=True, exist_ok=True)
    keep = []
    for f in SECRET_FIELDS:
        if f.get("file"):
            path = TOOLS_DIR / (".github_tokens" if f["id"] == "GITHUB_TOKENS" else ".gitlab_tokens")
            text = (payload.get(f["id"]) or "").replace("\r\n", "\n").strip() + ("\n" if payload.get(f["id"]) else "")
            path.write_text(text, encoding="utf-8")
        else:
            val = (payload.get(f["id"]) or "").strip()
            if val:
                keep.append(f'{f["id"]}="{val}"')
    SECRETS_CFG.write_text("\n".join(keep) + ("\n" if keep else ""), encoding="utf-8")


# ── scan runner ──────────────────────────────────────────────────────────────
def _validate_domain(s):
    s = (s or "").strip().lower()
    if not s or len(s) > 253:
        return None
    if s.startswith("http://") or s.startswith("https://"):
        s = re.sub(r"^https?://", "", s).split("/")[0]
    if not re.match(r"^[a-z0-9.-]+$", s):
        return None
    if ".." in s or s.startswith(".") or s.endswith("."):
        return None
    return s


def _validate_func(name):
    name = (name or "").strip()
    if re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", name):
        return name
    return None


def _build_cmd(body):
    if not _recon_ready():
        raise ValueError("reconFTW is not installed yet")
    mode = (body.get("mode") or "r").strip()
    if mode not in {m["id"] for m in MODES}:
        raise ValueError("Unknown scan mode")
    cmd = ["bash", str(RECONFTW_SH), f"-{mode}"]
    kind = body.get("target_kind") or "domain"
    target_label = ""
    extra_files = []

    if kind == "list":
        lines = [ln.strip() for ln in (body.get("list") or "").splitlines() if ln.strip()]
        domains = []
        for ln in lines:
            d = _validate_domain(ln)
            if not d:
                raise ValueError(f"Bad domain in list: {ln}")
            domains.append(d)
        if not domains:
            raise ValueError("List is empty")
        job_tmp = TARGETS_DIR / f"list_{int(time.time())}.txt"
        job_tmp.write_text("\n".join(domains) + "\n", encoding="utf-8")
        extra_files.append(str(job_tmp))
        cmd += ["-l", str(job_tmp)]
        target_label = f"{len(domains)} domains"
        if body.get("company"):
            cmd += ["-m", str(body["company"])[:80]]
    else:
        d = _validate_domain(body.get("domain"))
        if not d:
            raise ValueError("Enter a valid domain")
        cmd += ["-d", d]
        target_label = d

    if mode == "c":
        fn = _validate_func(body.get("custom_func"))
        if not fn:
            raise ValueError("Pick a module for Custom mode")
        cmd += [fn]

    opts = body.get("options") or {}
    for spec in SCAN_OPTIONS:
        if opts.get(spec["id"]):
            cmd.append(spec["flag"])
            if spec.get("value"):
                cmd.append(spec["value"])

    inc = [ln.strip() for ln in (body.get("include") or "").splitlines() if ln.strip()]
    exc = [ln.strip() for ln in (body.get("exclude") or "").splitlines() if ln.strip()]
    if inc:
        ip = TARGETS_DIR / f"inc_{int(time.time())}.txt"
        ip.write_text("\n".join(inc) + "\n", encoding="utf-8")
        cmd += ["-i", str(ip)]
        extra_files.append(str(ip))
    if exc:
        ep = TARGETS_DIR / f"exc_{int(time.time())}.txt"
        ep.write_text("\n".join(exc) + "\n", encoding="utf-8")
        cmd += ["-x", str(ep)]
        extra_files.append(str(ep))

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    # reconFTW already writes to <repo>/Recon/<target>. Passing -o that folder
    # makes it abort: "Output directory is a parent of the working directory".
    default_out = RECONFTW_DIR / "Recon"
    if OUTPUT_DIR.resolve() != default_out.resolve():
        cmd += ["-o", str(OUTPUT_DIR)]
    return cmd, target_label, extra_files


def _follow_log(job_id, path, proc, stop_ev):
    pos = 0
    while not stop_ev.is_set():
        try:
            if Path(path).is_file():
                with open(path, "rb") as f:
                    f.seek(pos)
                    chunk = f.read()
                    if chunk:
                        pos += len(chunk)
                        text = _strip_ansi(chunk.decode("utf-8", errors="replace"))
                        socketio.emit("job_log", {"id": job_id, "d": text})
        except Exception:
            pass
        if proc.poll() is not None:
            # drain once more
            try:
                with open(path, "rb") as f:
                    f.seek(pos)
                    chunk = f.read()
                    if chunk:
                        socketio.emit("job_log", {"id": job_id, "d": chunk.decode("utf-8", errors="replace")})
            except Exception:
                pass
            break
        stop_ev.wait(0.4)
    rc = proc.poll()
    with _jobs_lock:
        d, it = _job_get(job_id)
        if it:
            it["status"] = "done" if rc == 0 else "failed"
            it["exit_code"] = rc
            it["ended"] = int(time.time())
            _jobs_save(d)
    nc_push(
        "Scan finished" if rc == 0 else "Scan failed",
        f"Job #{job_id} exit {rc}",
        "ok" if rc == 0 else "err",
    )
    socketio.emit("job_done", {"id": job_id, "exit_code": rc, "status": "done" if rc == 0 else "failed"})


def _start_job(body):
    cmd, target_label, extra_files = _build_cmd(body)
    with _jobs_lock:
        d = _jobs_load()
        running = [x for x in d["items"] if x.get("status") == "running"]
        if running:
            raise ValueError("A scan is already running. Stop it first.")
        jid = d.get("seq", 1)
        d["seq"] = jid + 1
        log_path = str(LOGS_DIR / f"job_{jid}.log")
        item = {
            "id": jid,
            "target": target_label,
            "mode": body.get("mode") or "r",
            "options": body.get("options") or {},
            "cmd": cmd,
            "cmd_show": " ".join(shlex.quote(x) for x in cmd),
            "status": "running",
            "pid": None,
            "started": int(time.time()),
            "ended": None,
            "log": log_path,
            "output": str(OUTPUT_DIR),
        }
        d["items"].insert(0, item)
        _jobs_save(d)

    logf = open(log_path, "ab", buffering=0)
    logf.write(f"$ {' '.join(cmd)}\n\n".encode())
    try:
        proc = subprocess.Popen(
            cmd,
            cwd=str(RECONFTW_DIR),
            stdout=logf,
            stderr=subprocess.STDOUT,
            env=_scan_env(),
            start_new_session=True,
        )
    except Exception as e:
        logf.close()
        with _jobs_lock:
            d, it = _job_get(jid)
            if it:
                it["status"] = "failed"
                it["ended"] = int(time.time())
                it["error"] = str(e)
                _jobs_save(d)
        raise
    with _jobs_lock:
        d, it = _job_get(jid)
        if it:
            it["pid"] = proc.pid
            _jobs_save(d)
    stop_ev = threading.Event()
    _followers[jid] = (stop_ev, proc, logf)
    t = threading.Thread(target=_follow_log, args=(jid, log_path, proc, stop_ev), daemon=True)
    t.start()
    nc_push("Scan started", f"Job #{jid} · {target_label}", "info")
    return item


def _stop_job(jid):
    with _jobs_lock:
        d, it = _job_get(jid)
        if not it:
            raise ValueError("Job not found")
        pid = it.get("pid")
        if it.get("status") != "running":
            return it
        it["status"] = "stopped"
        it["ended"] = int(time.time())
        _jobs_save(d)
    if pid:
        try:
            os.killpg(pid, signal.SIGTERM)
        except Exception:
            try:
                os.kill(pid, signal.SIGTERM)
            except Exception:
                pass
    pack = _followers.get(jid)
    if pack:
        pack[0].set()
    nc_push("Scan stopped", f"Job #{jid} stopped from the panel", "warn")
    return it


def _delete_target_report(target):
    domain = _validate_domain(target)
    if not domain:
        return False
    removed = False
    roots = []
    for cand in (OUTPUT_DIR, RECONFTW_DIR / "Recon"):
        if cand.is_dir() and cand not in roots:
            roots.append(cand)
    for root in roots:
        folder = (root / domain).resolve()
        safe = _safe_under(str(folder), [str(root)])
        if not safe:
            continue
        if Path(safe) == Path(root).resolve():
            continue
        if os.path.isdir(safe):
            shutil.rmtree(safe)
            removed = True
        zpath = LOGS_DIR / f"{domain}.zip"
        if zpath.is_file():
            try:
                zpath.unlink()
            except Exception:
                pass
    return removed


def _delete_job(jid):
    with _jobs_lock:
        d, it = _job_get(jid)
        if not it:
            raise ValueError("Job not found")
        running = it.get("status") == "running"
        target = it.get("target") or ""
        log_path = it.get("log")
        pid = it.get("pid")
        d["items"] = [x for x in d["items"] if str(x.get("id")) != str(jid)]
        _jobs_save(d)
    if running and pid:
        try:
            os.killpg(pid, signal.SIGTERM)
        except Exception:
            try:
                os.kill(pid, signal.SIGTERM)
            except Exception:
                pass
    pack = _followers.pop(jid, None)
    if pack:
        pack[0].set()
        try:
            pack[2].close()
        except Exception:
            pass
    if log_path and os.path.isfile(log_path):
        try:
            os.remove(log_path)
        except Exception:
            pass
    report_removed = _delete_target_report(target)
    nc_push("Job deleted", f"Job #{jid} · {target}", "warn")
    try:
        socketio.emit("job_deleted", {"id": jid, "target": target})
    except Exception:
        pass
    return {"id": jid, "target": target, "report_removed": report_removed}


# ── health ───────────────────────────────────────────────────────────────────
_cpu_sample = None
_net_sample = None
_health_lock = threading.Lock()
_health_cache = {"t": 0.0, "data": None}


def _fmt_bytes(n):
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB"):
        if n < 1024.0:
            return "%.1f %s" % (n, u)
        n /= 1024.0
    return "%.1f TB" % n


def _cpu_times():
    with open("/proc/stat") as f:
        parts = f.readline().split()
    nums = [int(x) for x in parts[1:]]
    idle = nums[3] + (nums[4] if len(nums) > 4 else 0)
    return sum(nums), idle


def _net_bytes():
    rx = tx = 0
    with open("/proc/net/dev") as f:
        for line in f:
            if ":" not in line:
                continue
            name, rest = line.split(":", 1)
            name = name.strip()
            if not name or name == "lo":
                continue
            cols = rest.split()
            if len(cols) < 10:
                continue
            rx += int(cols[0])
            tx += int(cols[8])
    return rx, tx


def _meminfo():
    info = {}
    with open("/proc/meminfo") as f:
        for line in f:
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            info[k] = int(v.strip().split()[0]) * 1024
    total = info.get("MemTotal", 0)
    avail = info.get("MemAvailable", info.get("MemFree", 0))
    used = max(0, total - avail)
    pct = (used / total * 100.0) if total else 0.0
    return total, used, avail, pct


def _disk_root():
    st = os.statvfs("/")
    total = st.f_frsize * st.f_blocks
    free = st.f_frsize * st.f_bavail
    used = max(0, total - free)
    pct = (used / total * 100.0) if total else 0.0
    return total, used, free, pct


def _loadavg():
    with open("/proc/loadavg") as f:
        a, b, c = f.read().split()[:3]
    return float(a), float(b), float(c)


def _cpu_model():
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.lower().startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return ""


def _uptime_sec():
    with open("/proc/uptime") as f:
        return float(f.read().split()[0])


def _health_grade(pct):
    if pct >= 92:
        return "critical"
    if pct >= 78:
        return "warning"
    return "healthy"


def _health_collect():
    global _cpu_sample, _net_sample
    t0 = time.monotonic()
    total, idle = _cpu_times()
    rx, tx = _net_bytes()
    now = time.monotonic()
    cpu_pct = 0.0
    if _cpu_sample is None:
        time.sleep(0.04)
        total2, idle2 = _cpu_times()
        now = time.monotonic()
        dt, di = total2 - total, idle2 - idle
        cpu_pct = 0.0 if dt <= 0 else max(0.0, min(100.0, (1.0 - (di / float(dt))) * 100.0))
        _cpu_sample = (now, total2, idle2)
    else:
        pt, ptot, pidle = _cpu_sample
        dt, di = total - ptot, idle - pidle
        cpu_pct = 0.0 if dt <= 0 else max(0.0, min(100.0, (1.0 - (di / float(dt))) * 100.0))
        _cpu_sample = (now, total, idle)
    net_in_bps = net_out_bps = 0.0
    if _net_sample is not None:
        pt, prx, ptx = _net_sample
        dt = max(0.001, now - pt)
        net_in_bps = max(0.0, (rx - prx) / dt)
        net_out_bps = max(0.0, (tx - ptx) / dt)
    _net_sample = (now, rx, tx)
    mem_total, mem_used, mem_avail, mem_pct = _meminfo()
    disk_total, disk_used, disk_free, disk_pct = _disk_root()
    l1, l5, l15 = _loadavg()
    cores = os.cpu_count() or 1
    cpu_status = _health_grade(cpu_pct)
    ram_status = _health_grade(mem_pct)
    disk_status = _health_grade(disk_pct)
    net_busy = (net_in_bps + net_out_bps) > (50 * 1024 * 1024)
    net_status = "warning" if net_busy else "healthy"
    worst = "healthy"
    for s in (cpu_status, ram_status, disk_status, net_status):
        if s == "critical":
            worst = "critical"
        elif s == "warning" and worst != "critical":
            worst = "warning"
    if worst == "critical":
        summary = "System under pressure"
    elif worst == "warning":
        summary = "Some metrics are elevated"
    else:
        summary = "All systems nominal — everything is running smoothly"
    return {
        "status": worst,
        "summary": summary,
        "took_ms": round((time.monotonic() - t0) * 1000, 1),
        "ts": int(time.time()),
        "hostname": os.uname().nodename,
        "uptime": _uptime_sec(),
        "cores": cores,
        "cpu_model": _cpu_model(),
        "load": [round(l1, 2), round(l5, 2), round(l15, 2)],
        "cpu_pct": round(cpu_pct, 1),
        "cpu_status": cpu_status,
        "ram": {
            "total": mem_total, "used": mem_used, "free": mem_avail,
            "pct": round(mem_pct, 1), "status": ram_status,
            "total_h": _fmt_bytes(mem_total), "used_h": _fmt_bytes(mem_used),
        },
        "disk": {
            "total": disk_total, "used": disk_used, "free": disk_free,
            "pct": round(disk_pct, 1), "status": disk_status,
            "total_h": _fmt_bytes(disk_total), "used_h": _fmt_bytes(disk_used),
            "free_h": _fmt_bytes(disk_free),
        },
        "net": {
            "in_bps": round(net_in_bps), "out_bps": round(net_out_bps),
            "in_h": _fmt_bytes(net_in_bps) + "/s",
            "out_h": _fmt_bytes(net_out_bps) + "/s",
            "rx_total_h": _fmt_bytes(rx), "tx_total_h": _fmt_bytes(tx),
            "status": net_status,
        },
    }


# ── results ──────────────────────────────────────────────────────────────────
def _result_targets():
    roots = []
    for cand in (OUTPUT_DIR, RECONFTW_DIR / "Recon"):
        if cand.is_dir() and cand not in roots:
            roots.append(cand)
    items = []
    seen = set()
    for root in roots:
        try:
            for child in sorted(root.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True):
                if not child.is_dir():
                    continue
                key = child.name.lower()
                if key in seen:
                    continue
                seen.add(key)
                report = None
                for rp in (
                    child / "report" / "index.html",
                    child / "index.html",
                    child / "reconftw_report.html",
                ):
                    if rp.is_file():
                        report = str(rp.relative_to(child))
                        break
                st = child.stat()
                nfiles = 0
                try:
                    nfiles = sum(1 for _ in child.rglob("*") if _.is_file())
                except Exception:
                    pass
                items.append({
                    "name": child.name,
                    "path": str(child),
                    "mtime": int(st.st_mtime),
                    "size": sum(f.stat().st_size for f in child.rglob("*") if f.is_file()) if nfiles < 5000 else 0,
                    "files": nfiles,
                    "report": report,
                })
        except Exception:
            continue
    return items


def _result_item(name):
    name = os.path.basename(name or "")
    if not name or name in {".", ".."}:
        return None
    for it in _result_targets():
        if it["name"] == name:
            return it
    return None


def _result_file_page(name, rel, inner, status=200):
    back = f"/api/results/{name}/report"
    body = (
        "<!doctype html><html><head><meta charset='utf-8'><title>"
        f"{_html_esc(rel or name)}</title><style>"
        "body{margin:0;font-family:Inter,system-ui,sans-serif;background:#0a0e17;color:#e2e8f0}"
        ".bar{position:sticky;top:0;z-index:2;display:flex;align-items:center;gap:12px;"
        "padding:12px 16px;background:#111827;border-bottom:1px solid rgba(0,255,136,.12)}"
        ".bar a{color:#0a0e17;background:#00ff88;font-weight:700;text-decoration:none;"
        "padding:7px 14px;border-radius:8px}"
        ".bar span{color:#94a3b8;font-family:ui-monospace,monospace;font-size:12px;word-break:break-all}"
        "pre{padding:18px;white-space:pre-wrap;word-break:break-word;font:13px/1.55 ui-monospace,monospace}"
        "ul{padding:16px 28px}a.f{color:#22d3ee;font-family:ui-monospace,monospace}"
        "</style></head><body>"
        f"<div class='bar'><a href='{back}'>← Back</a><span>{_html_esc(rel or name)}</span></div>"
        f"{inner}</body></html>"
    )
    return Response(body, status=status, mimetype="text/html; charset=utf-8")


def _result_file_response(folder, rel, name):
    rel = (rel or "").replace("\\", "/").lstrip("/")
    if any(p in {".", ".."} for p in rel.split("/")):
        return Response("bad path", status=400, mimetype="text/plain")
    target = folder if not rel else os.path.join(folder, rel)
    full = _safe_under(target, [folder])
    if not full:
        return Response("bad path", status=400, mimetype="text/plain")
    if os.path.isdir(full):
        rows = []
        try:
            kids = sorted(os.listdir(full), key=str.lower)
        except Exception:
            kids = []
        prefix = f"/api/results/{name}/files/" + (rel.rstrip("/") + "/" if rel else "")
        if rel:
            parent = rel.rsplit("/", 1)[0] if "/" in rel else ""
            rows.append(f'<li><a class="f" href="/api/results/{name}/files/{parent}">..</a></li>')
        for kid in kids:
            href = prefix + kid
            rows.append(f'<li><a class="f" href="{href}">{_html_esc(kid)}</a></li>')
        return _result_file_page(name, rel or ".", f"<ul>{''.join(rows) or '<li>empty</li>'}</ul>")
    if not os.path.isfile(full):
        return _result_file_page(
            name,
            rel,
            f"<pre>This path was not produced for {_html_esc(name)}.\n{_html_esc(rel)}</pre>",
            status=404,
        )
    low = full.lower()
    if low.endswith((".html", ".htm")):
        return send_file(full)
    if low.endswith((".png", ".jpg", ".jpeg", ".webp", ".gif", ".svg")):
        inner = f"<div style='padding:16px'><img src='?raw=1' style='max-width:100%;border-radius:8px'></div>"
        if request.args.get("raw") == "1":
            return send_file(full)
        return _result_file_page(name, rel, inner)
    if low.endswith((".txt", ".jsonl", ".log", ".csv", ".md", ".cfg", ".list", ".json")):
        raw = Path(full).read_bytes()
        note = ""
        if len(raw) > 1_200_000:
            raw = raw[:800_000]
            note = "\n\n[truncated]"
        text = raw.decode("utf-8", errors="replace") + note
        return _result_file_page(name, rel, f"<pre>{_html_esc(text)}</pre>")
    return send_file(full, as_attachment=False)


def _html_esc(s):
    return (
        str(s or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _safe_under(path, allowed_roots):
    real = os.path.realpath(path)
    for root in allowed_roots:
        r = os.path.realpath(root)
        if real == r or real.startswith(r + os.sep):
            return real
    return None


# ── pages ────────────────────────────────────────────────────────────────────
@app.route("/favicon.ico")
def favicon():
    static = os.path.join(app.root_path, "static")
    ico = os.path.join(static, "favicon.svg")
    if os.path.isfile(ico):
        return send_from_directory(static, "favicon.svg", mimetype="image/svg+xml")
    return ("", 404)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        d = request.get_json(silent=True) or request.form
        if d.get("username") == PANEL_USER and d.get("password") == PANEL_PASS:
            session["ok"] = True
            session.permanent = True
            return jsonify(ok=True)
        return jsonify(error="ACCESS DENIED"), 401
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


@app.route("/")
@auth
def index():
    return render_template("index.html")


@app.route("/api/meta")
@auth
def api_meta():
    return jsonify(
        version=PANEL_VERSION,
        modes=MODES,
        options=SCAN_OPTIONS,
        custom_funcs=CUSTOM_FUNCS,
        module_groups=[{"id": g, "keys": ks} for g, ks in MODULE_GROUPS],
        secret_fields=[{k: f[k] for k in f if k != "file"} for f in SECRET_FIELDS],
        ram_gb=round(_meminfo()[0] / (1024 ** 3), 1),
    )


@app.route("/api/dashboard")
@auth
def api_dashboard():
    inst = _install_status()
    jobs = _jobs_load()["items"]
    running_jobs = [j for j in jobs if j.get("status") == "running"]
    running = running_jobs[0] if running_jobs else None
    health = _health_collect()
    results = _result_targets()
    return jsonify(
        install=inst,
        running=running,
        running_count=len(running_jobs),
        jobs_total=len(jobs),
        jobs_done=sum(1 for j in jobs if j.get("status") == "done"),
        jobs_failed=sum(1 for j in jobs if j.get("status") == "failed"),
        results=len(results),
        recent=jobs[:8],
        uptime=health["uptime"],
        hostname=health["hostname"],
        cpu_pct=health["cpu_pct"],
        ram=health["ram"],
        disk=health["disk"],
        version=inst.get("version"),
        ready=inst.get("ready"),
        state=inst.get("state"),
    )


@app.route("/api/health")
@auth
def api_health():
    now = time.monotonic()
    with _health_lock:
        if _health_cache["data"] is not None and (now - _health_cache["t"]) < 0.9:
            return jsonify(_health_cache["data"])
        data = _health_collect()
        _health_cache["t"] = time.monotonic()
        _health_cache["data"] = data
        return jsonify(data)


@app.route("/api/install")
@auth
def api_install_status():
    return jsonify(_install_status())


@app.route("/api/install/start", methods=["POST"])
@auth
def api_install_start():
    if _install_running():
        return jsonify(ok=True, already=True)
    RECONFTW_DIR.mkdir(parents=True, exist_ok=True)
    if not (RECONFTW_DIR / ".git").is_dir():
        subprocess.Popen(
            ["git", "clone", "--depth", "1", "https://github.com/six2dez/reconftw.git", str(RECONFTW_DIR)],
            stdout=open(INSTALL_LOG, "ab"),
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        nc_push("Cloning reconFTW", "Repository clone started", "info")
        return jsonify(ok=True, cloning=True)
    logf = open(INSTALL_LOG, "ab", buffering=0)
    subprocess.Popen(
        ["bash", "./install.sh"],
        cwd=str(RECONFTW_DIR),
        stdout=logf,
        stderr=subprocess.STDOUT,
        env={**os.environ, "DEBIAN_FRONTEND": "noninteractive", "VERBOSE": "true", "PYTHONUNBUFFERED": "1"},
        start_new_session=True,
    )
    nc_push("Installing reconFTW", "install.sh started — this takes a while", "info")
    return jsonify(ok=True)


@app.route("/api/tools/health-check", methods=["POST"])
@auth
def api_tools_health():
    if not _recon_ready():
        return jsonify(error="reconFTW is not installed yet"), 400
    try:
        out = subprocess.check_output(
            ["bash", str(RECONFTW_SH), "--health-check"],
            cwd=str(RECONFTW_DIR),
            env=_scan_env(),
            stderr=subprocess.STDOUT,
            timeout=120,
            text=True,
        )
        return jsonify(ok=True, output=out[-8000:])
    except subprocess.CalledProcessError as e:
        return jsonify(ok=False, output=(e.output or "")[-8000:])
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.route("/api/jobs", methods=["GET"])
@auth
def api_jobs():
    return jsonify(_jobs_load()["items"])


@app.route("/api/jobs", methods=["POST"])
@auth
def api_jobs_start():
    body = request.get_json(silent=True) or {}
    if not body.get("authorized"):
        return jsonify(error="Confirm you are authorized to test this target"), 400
    try:
        item = _start_job(body)
        return jsonify(ok=True, job=item)
    except ValueError as e:
        return jsonify(error=str(e)), 400
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.route("/api/jobs/<int:jid>/stop", methods=["POST"])
@auth
def api_jobs_stop(jid):
    try:
        return jsonify(ok=True, job=_stop_job(jid))
    except ValueError as e:
        return jsonify(error=str(e)), 404


@app.route("/api/jobs/<int:jid>", methods=["DELETE"])
@auth
def api_jobs_delete(jid):
    try:
        return jsonify(ok=True, **_delete_job(jid))
    except ValueError as e:
        return jsonify(error=str(e)), 404


@app.route("/api/jobs/<int:jid>/log")
@auth
def api_jobs_log(jid):
    _, it = _job_get(jid)
    if not it:
        return jsonify(error="not found"), 404
    path = it.get("log")
    text = ""
    if path and os.path.isfile(path):
        with open(path, "rb") as f:
            data = f.read()[-200_000:]
        text = _strip_ansi(data.decode("utf-8", errors="replace"))
    return jsonify(id=jid, status=it.get("status"), log=text, job=it)


_FIND_CATS = frozenset({"vulns", "subdomains", "webs", "screenshots", "osint", "hosts", "fuzzing", "cms", "js"})


@app.route("/api/jobs/<int:jid>/findings")
@auth
def api_job_findings(jid):
    _, it = _job_get(jid)
    if not it:
        return jsonify(error="not found"), 404
    root, data = _job_collect(it)
    if not data:
        empty = {k: 0 for k in F.SEV_ORDER}
        return jsonify(
            job=it,
            domain=it.get("target") or "",
            path=None,
            runtime="",
            summary={},
            severities=empty,
            categories=[
                {"id": "vulns", "title": "Vulnerabilities", "icon": "fa-bug", "count": 0, "cves": 0},
                {"id": "subdomains", "title": "Subdomains", "icon": "fa-sitemap", "count": 0},
                {"id": "webs", "title": "Web hosts", "icon": "fa-globe", "count": 0},
                {"id": "screenshots", "title": "Screenshots", "icon": "fa-camera", "count": 0},
                {"id": "osint", "title": "OSINT", "icon": "fa-user-secret", "count": 0},
                {"id": "hosts", "title": "Hosts & ports", "icon": "fa-server", "count": 0},
                {"id": "fuzzing", "title": "Fuzzing", "icon": "fa-bolt", "count": 0},
                {"id": "cms", "title": "CMS", "icon": "fa-cubes", "count": 0},
                {"id": "js", "title": "JavaScript", "icon": "fa-js", "count": 0},
            ],
        )
    return jsonify(
        job=it,
        domain=data["domain"],
        path=str(root),
        runtime=data["runtime"],
        summary=data["summary"],
        severities=data["severities"],
        categories=data["categories"],
    )


@app.route("/api/jobs/<int:jid>/findings/<cat>")
@auth
def api_job_findings_cat(jid, cat):
    cat = (cat or "").strip().lower()
    if cat not in _FIND_CATS:
        return jsonify(error="unknown category"), 404
    _, it = _job_get(jid)
    if not it:
        return jsonify(error="not found"), 404
    root, data = _job_collect(it)
    if not data:
        return jsonify(title=cat, kind="empty", items=[])
    sev = (request.args.get("severity") or "").strip().lower() or None
    if sev and sev not in F.SEV_ORDER:
        sev = None
    payload = F.category_payload(data, cat, sev)
    payload["domain"] = data["domain"]
    payload["path"] = str(root)
    return jsonify(payload)


@app.route("/api/jobs/<int:jid>/asset")
@auth
def api_job_asset(jid):
    _, it = _job_get(jid)
    if not it:
        return jsonify(error="not found"), 404
    root = F.recon_dir(it.get("target"), OUTPUT_DIR, RECONFTW_DIR / "Recon")
    if not root:
        return jsonify(error="no recon folder"), 404
    rel = (request.args.get("path") or "").replace("\\", "/").lstrip("/")
    if not rel or ".." in rel.split("/"):
        return jsonify(error="bad path"), 400
    full = _safe_under(str(root / rel), [str(root)])
    if not full or not os.path.isfile(full):
        return jsonify(error="not found"), 404
    return send_file(full)


@app.route("/api/jobs/<int:jid>/export")
@auth
def api_job_export(jid):
    fmt = (request.args.get("fmt") or "html").strip().lower()
    if fmt not in ("html", "md"):
        return jsonify(error="fmt must be html or md"), 400
    _, it = _job_get(jid)
    if not it:
        return jsonify(error="not found"), 404
    root, data = _job_collect(it)
    if not data:
        return jsonify(error="no recon folder for this target yet"), 404
    domain = data.get("domain") or it.get("target") or f"job{jid}"
    if fmt == "md":
        body = F.render_md(data)
        bio = io.BytesIO(body.encode("utf-8"))
        bio.seek(0)
        return send_file(
            bio,
            as_attachment=True,
            download_name=f"{domain}_reconftw.md",
            mimetype="text/markdown; charset=utf-8",
        )
    body = F.render_html(data)
    bio = io.BytesIO(body.encode("utf-8"))
    bio.seek(0)
    return send_file(
        bio,
        as_attachment=True,
        download_name=f"{domain}_reconftw.html",
        mimetype="text/html; charset=utf-8",
    )


@app.route("/api/results")
@auth
def api_results():
    items = _result_targets()
    for it in items:
        it["size_h"] = _fmt_bytes(it.get("size") or 0)
        it["mtime_h"] = datetime.utcfromtimestamp(it["mtime"]).strftime("%Y-%m-%d %H:%M")
    return jsonify(items)


@app.route("/api/results/<name>/zip")
@auth
def api_results_zip(name):
    name = os.path.basename(name)
    folder = None
    for it in _result_targets():
        if it["name"] == name:
            folder = it["path"]
            break
    if not folder or not os.path.isdir(folder):
        return jsonify(error="not found"), 404
    zpath = LOGS_DIR / f"{name}.zip"
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for root, dirs, files in os.walk(folder):
            dirs[:] = [d for d in dirs if d not in (".git",)]
            for fn in files:
                fp = os.path.join(root, fn)
                z.write(fp, os.path.relpath(fp, folder))
    return send_file(zpath, as_attachment=True, download_name=f"{name}.zip")


@app.route("/api/results/<name>/files/", defaults={"rel": ""})
@app.route("/api/results/<name>/files/<path:rel>")
@auth
def api_results_file(name, rel):
    it = _result_item(name)
    if not it:
        return jsonify(error="not found"), 404
    return _result_file_response(it["path"], rel, it["name"])


@app.route("/api/results/<name>/report")
@auth
def api_results_report(name):
    it = _result_item(name)
    if not it or not it.get("report"):
        return jsonify(error="no HTML report yet"), 404
    folder = it["path"]
    report = it["report"]
    path = os.path.join(folder, report)
    if not os.path.isfile(path):
        return jsonify(error="no HTML report yet"), 404
    html = Path(path).read_text(encoding="utf-8", errors="replace")
    base = f"/api/results/{it['name']}/files/report/"
    if "<base" not in html.lower():
        html = html.replace("<head>", f'<head>\n  <base href="{base}">', 1)
    try:
        data = F.collect(Path(folder))
        sev = {k: int((data.get("severities") or {}).get(k, 0)) for k in ("critical", "high", "medium", "low", "info")}
        html = re.sub(
            r'"severities"\s*:\s*\{[^}]*\}',
            '"severities":' + json.dumps(sev, separators=(",", ":")),
            html,
            count=1,
        )
        html = re.sub(
            r'"findings_total"\s*:\s*\d+',
            '"findings_total":' + str(len(data.get("vulns") or [])),
            html,
            count=1,
        )
    except Exception:
        pass
    return Response(html, mimetype="text/html; charset=utf-8")


@app.route("/api/modules", methods=["GET"])
@auth
def api_modules_get():
    bools = _cfg_bools()
    groups = []
    for title, keys in MODULE_GROUPS:
        groups.append({
            "id": title,
            "items": [{"key": k, "on": bool(bools.get(k, False)), "present": k in bools} for k in keys],
        })
    return jsonify(groups=groups, raw_count=len(bools), cfg=str(RECONFTW_CFG), exists=RECONFTW_CFG.is_file())


@app.route("/api/modules", methods=["POST"])
@auth
def api_modules_set():
    body = request.get_json(silent=True) or {}
    updates = body.get("updates") or {}
    clean = {}
    allowed = {k for _, ks in MODULE_GROUPS for k in ks}
    for k, v in updates.items():
        if k in allowed:
            clean[k] = bool(v)
    if not clean:
        return jsonify(error="Nothing to change"), 400
    try:
        known = _cfg_set_bools(clean)
        return jsonify(ok=True, updated=known)
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.route("/api/secrets", methods=["GET"])
@auth
def api_secrets_get():
    vals = _secrets_read()
    out = {}
    for f in SECRET_FIELDS:
        v = vals.get(f["id"]) or ""
        if f.get("multiline"):
            v = v.strip("\n")
        out[f["id"]] = v
        out[f["id"] + "__set"] = bool(v)
    return jsonify(values=out, fields=SECRET_FIELDS)


@app.route("/api/secrets", methods=["POST"])
@auth
def api_secrets_set():
    body = request.get_json(silent=True) or {}
    current = _secrets_read()
    merged = dict(current)
    for f in SECRET_FIELDS:
        k = f["id"]
        if k in body:
            val = body[k]
            if not f.get("multiline") and val and "•" in str(val):
                continue  # keep existing, UI sent mask
            merged[k] = val
    _secrets_write(merged)
    nc_push("API keys saved", "Secrets updated from the panel", "ok")
    return jsonify(ok=True)


@app.route("/api/fs")
@auth
def api_fs():
    path = request.args.get("path") or str(OUTPUT_DIR)
    real = _safe_under(path, FE_ROOTS)
    if not real:
        return jsonify(error="path not allowed"), 403
    if not os.path.isdir(real):
        return jsonify(error="not a directory"), 400
    entries = []
    try:
        for name in sorted(os.listdir(real), key=str.lower):
            fp = os.path.join(real, name)
            try:
                st = os.stat(fp)
            except Exception:
                continue
            entries.append({
                "name": name,
                "path": fp,
                "dir": os.path.isdir(fp),
                "size": st.st_size,
                "size_h": _fmt_bytes(st.st_size),
                "mtime": int(st.st_mtime),
            })
    except Exception as e:
        return jsonify(error=str(e)), 500
    crumbs = []
    acc = ""
    for part in Path(real).parts:
        acc = "/" if part == "/" else (acc.rstrip("/") + "/" + part if acc != "/" else "/" + part)
        crumbs.append({"name": part or "/", "path": acc})
    return jsonify(path=real, entries=entries, crumbs=crumbs)


@app.route("/api/fs/read")
@auth
def api_fs_read():
    path = request.args.get("path") or ""
    real = _safe_under(path, FE_ROOTS)
    if not real or not os.path.isfile(real):
        return jsonify(error="not found"), 404
    if os.path.getsize(real) > 2_000_000:
        return jsonify(error="file too large to preview"), 400
    data = Path(real).read_bytes()
    try:
        text = data.decode("utf-8")
    except Exception:
        text = data.decode("utf-8", errors="replace")
    return jsonify(path=real, text=text, name=os.path.basename(real))


@app.route("/api/fs/download")
@auth
def api_fs_download():
    path = request.args.get("path") or ""
    real = _safe_under(path, FE_ROOTS)
    if not real or not os.path.isfile(real):
        return jsonify(error="not found"), 404
    return send_file(real, as_attachment=True, download_name=os.path.basename(real))


@app.route("/api/nc")
@auth
def api_nc():
    d = _nc_load()
    items = d.get("items") or []
    unread = sum(1 for i in items if not i.get("read"))
    return jsonify(items=items[:80], unread=unread)


@app.route("/api/nc/read", methods=["POST"])
@auth
def api_nc_read():
    body = request.get_json(silent=True) or {}
    with _nc_lock:
        d = _nc_load()
        nid = body.get("id")
        if nid is not None and not body.get("all"):
            for i in d.get("items") or []:
                if str(i.get("id")) == str(nid):
                    i["read"] = True
                    break
        else:
            for i in d.get("items") or []:
                i["read"] = True
        _nc_save(d)
    return jsonify(ok=True)


@app.route("/api/nc/clear", methods=["POST"])
@auth
def api_nc_clear():
    with _nc_lock:
        d = _nc_load()
        d["items"] = [i for i in (d.get("items") or []) if not i.get("read")]
        _nc_save(d)
    return jsonify(ok=True)


@app.route("/api/notifications", methods=["GET", "POST"])
@auth
def api_notifications():
    if request.method == "GET":
        ns = _notif_load()
        if ns.get("bot_token"):
            ns = dict(ns)
            tok = ns["bot_token"]
            ns["bot_token"] = tok[:6] + "•" * 10
            ns["bot_token_set"] = True
        return jsonify(ns)
    body = request.get_json(silent=True) or {}
    cur = _notif_load()
    tok = body.get("bot_token") or ""
    if "•" in tok:
        tok = cur.get("bot_token") or ""
    cur["enabled"] = bool(body.get("enabled"))
    cur["bot_token"] = tok
    cur["chat_id"] = str(body.get("chat_id") or "").strip()
    NOTIF_FILE.write_text(json.dumps(cur), encoding="utf-8")
    return jsonify(ok=True)


@app.route("/api/notifications/test", methods=["POST"])
@auth
def api_notifications_test():
    ns = _notif_load()
    if not (ns.get("bot_token") and ns.get("chat_id")):
        return jsonify(error="Save a Telegram bot token and chat id first"), 400
    try:
        _send_telegram(ns["bot_token"], ns["chat_id"], "<b>reconFTW panel</b>\nTest message from the control panel.")
        return jsonify(ok=True)
    except Exception as e:
        return jsonify(error=str(e)), 500


def _svc_ok(name):
    return bool(re.match(r"^[a-zA-Z0-9_@.-]+$", name or ""))


@app.route("/api/services")
@auth
def api_services():
    names = ["reconftw-panel"]
    try:
        out = subprocess.check_output(
            ["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--no-pager"],
            text=True, timeout=8,
        )
        for line in out.splitlines():
            unit = line.split()[0] if line.split() else ""
            if "reconftw" in unit and unit.endswith(".service"):
                n = unit.replace(".service", "")
                if n not in names:
                    names.append(n)
    except Exception:
        pass
    items = []
    for n in names:
        try:
            show = subprocess.check_output(
                ["systemctl", "show", n, "-p", "ActiveState", "-p", "SubState", "-p", "MainPID", "-p", "Description", "-p", "FragmentPath"],
                text=True, timeout=5,
            )
            info = dict(ln.split("=", 1) for ln in show.splitlines() if "=" in ln)
        except Exception:
            info = {}
        items.append({
            "name": n,
            "active": info.get("ActiveState", "unknown"),
            "sub": info.get("SubState", ""),
            "pid": info.get("MainPID", "0"),
            "desc": info.get("Description", n),
            "path": info.get("FragmentPath", ""),
        })
    return jsonify(items)


@app.route("/api/services/<name>/<action>", methods=["POST"])
@auth
def api_services_action(name, action):
    if not _svc_ok(name) or action not in ("start", "stop", "restart"):
        return jsonify(error="bad request"), 400
    if name == "reconftw-panel" and action == "stop":
        return jsonify(error="Stopping the panel from itself would lock you out"), 400
    try:
        subprocess.check_call(["systemctl", action, name], timeout=20)
        return jsonify(ok=True)
    except Exception as e:
        return jsonify(error=str(e)), 500


@app.route("/api/services/<name>/logs")
@auth
def api_services_logs(name):
    if not _svc_ok(name):
        return jsonify(error="bad name"), 400
    try:
        out = subprocess.check_output(
            ["journalctl", "-u", name, "-n", "200", "--no-pager", "-o", "short-iso"],
            text=True, timeout=10,
        )
        return jsonify(log=out)
    except Exception as e:
        return jsonify(error=str(e)), 500


@socketio.on("connect")
def ws_connect():
    if not session.get("ok"):
        return False


@socketio.on("job_follow")
def ws_job_follow(data):
    if not session.get("ok"):
        return
    jid = (data or {}).get("id")
    _, it = _job_get(jid)
    if not it:
        return
    path = it.get("log")
    if path and os.path.isfile(path):
        with open(path, "rb") as f:
            text = f.read()[-80_000:].decode("utf-8", errors="replace")
        emit("job_log", {"id": it["id"], "d": text, "reset": True})


class _PidWatch:
    def __init__(self, pid):
        self.pid = int(pid)

    def poll(self):
        try:
            os.kill(self.pid, 0)
            return None
        except OSError:
            return 0


def _recover_running_jobs():
    """Reattach follow threads after a panel restart so an in-flight scan is not orphaned."""
    with _jobs_lock:
        items = list((_jobs_load().get("items") or []))
    for it in items:
        if it.get("status") != "running":
            continue
        jid = it.get("id")
        pid = it.get("pid")
        log_path = it.get("log")
        if not pid:
            continue
        try:
            os.kill(int(pid), 0)
        except OSError:
            with _jobs_lock:
                d, cur = _job_get(jid)
                if cur and cur.get("status") == "running":
                    cur["status"] = "failed"
                    cur["ended"] = int(time.time())
                    cur["error"] = "scan process gone after panel restart"
                    _jobs_save(d)
            continue
        if jid in _followers:
            continue
        stop_ev = threading.Event()
        watch = _PidWatch(pid)
        _followers[jid] = (stop_ev, watch, None)
        t = threading.Thread(target=_follow_log, args=(jid, log_path, watch, stop_ev), daemon=True)
        t.start()
        print(f"[*] reattached running job #{jid} pid={pid}")


if __name__ == "__main__":
    print(f"\n[*] reconFTW Control Panel v{PANEL_VERSION}")
    print(f"[*] http://0.0.0.0:{PANEL_PORT}\n")
    _recover_running_jobs()
    socketio.run(app, host=PANEL_HOST, port=PANEL_PORT, allow_unsafe_werkzeug=True)
