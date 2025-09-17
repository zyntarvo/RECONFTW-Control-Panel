#!/usr/bin/env python3
"""
reconFTW Control Panel installer (tkinter GUI).

  INSTALL          — fresh server: Go (apt, not broken go.dev tarball),
                     clone six2dez/reconftw, install.sh, PATH glue, panel, systemd.
  INSTALL ONLY CP  — panel only, attach to reconFTW already on the box.

Usage:  python reconftw_setup.py
"""

from __future__ import annotations

import io
import os
import sys
import time
import shlex
import threading
import traceback
import webbrowser

def _ensure_paramiko():
    try:
        import paramiko  # noqa: F401
        return
    except ImportError:
        pass
    print("[*] Installing paramiko...")
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "paramiko"])


_ensure_paramiko()
import paramiko  # noqa: E402

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

HERE = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))
if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
    HERE = sys._MEIPASS
PAYLOAD = os.path.join(HERE, "payload")
PANEL_BUILD = "1.0.0"
REMOTE_RECON = "/root/reconftw"
REMOTE_PANEL = "/root/reconftw-panel"
REMOTE_TOOLS = "/root/Tools"
RECON_REPO = "https://github.com/six2dez/reconftw.git"


class SSH:
    def __init__(self, host, port, user, password, log):
        self.host = host
        self.port = int(port)
        self.user = user
        self.password = password
        self.log = log
        self.client = None
        self.sftp = None
        self.is_root = user == "root"

    def connect(self):
        self.log(f"[*] SSH {self.user}@{self.host}:{self.port}")
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(
            self.host,
            port=self.port,
            username=self.user,
            password=self.password,
            timeout=25,
            allow_agent=False,
            look_for_keys=False,
            banner_timeout=30,
            auth_timeout=30,
        )
        c.get_transport().set_keepalive(15)
        self.client = c
        self.sftp = c.open_sftp()
        self.log("[+] SSH connected")

    def close(self):
        try:
            if self.sftp:
                self.sftp.close()
        except Exception:
            pass
        try:
            if self.client:
                self.client.close()
        except Exception:
            pass

    def _wrap(self, cmd: str) -> str:
        if self.is_root:
            return cmd
        pw = self.password.replace("'", "'\"'\"'")
        return f"echo '{pw}' | sudo -S -p '' bash -lc {shlex.quote(cmd)}"

    def run(self, cmd: str, timeout=180, check=False, pty=True, quiet=False):
        wrapped = self._wrap(cmd)
        stdin, stdout, stderr = self.client.exec_command(wrapped, timeout=timeout, get_pty=pty)
        out = stdout.read().decode("utf-8", "replace")
        err = stderr.read().decode("utf-8", "replace")
        code = stdout.channel.recv_exit_status()
        text = (out + "\n" + err).strip()
        if code != 0 and not quiet:
            self.log(f"    exit={code}  {cmd[:140]}")
            if text:
                for line in text.splitlines()[-10:]:
                    self.log(f"    {line}")
            if check:
                raise RuntimeError(f"Command failed ({code}): {cmd}\n{text[-1500:]}")
        elif code != 0 and check:
            raise RuntimeError(f"Command failed ({code}): {cmd}\n{text[-1500:]}")
        return code, text

    def write_text(self, remote, text):
        bio = io.BytesIO(text.encode("utf-8"))
        self.sftp.putfo(bio, remote)

    def put_file(self, local, remote):
        self.log(f"    upload {os.path.basename(local)} -> {remote}")
        self.sftp.put(local, remote)

    def mkdir_p(self, path):
        parts = [p for p in path.strip("/").split("/") if p]
        cur = ""
        for p in parts:
            cur += "/" + p
            try:
                self.sftp.stat(cur)
            except FileNotFoundError:
                try:
                    self.sftp.mkdir(cur)
                except OSError:
                    self.run(f"mkdir -p {shlex.quote(cur)}")


class Installer:
    def __init__(self, ssh: SSH, user: str, password: str, panel_port: int, progress):
        self.ssh = ssh
        self.user = user
        self.password = password
        self.panel_port = int(panel_port)
        self.progress = progress
        self.log = ssh.log
        self.os_id = "ubuntu"
        self.os_ver = "22.04"
        self.goroot = "/usr/lib/go"
        self.gopath = "/root/go"

    def set_pct(self, n):
        self.progress(n)

    def detect(self):
        self.set_pct(3)
        self.log("[*] Detecting OS")
        _, out = self.ssh.run("cat /etc/os-release; echo ---; uname -m; free -m | head -2")
        for line in out.splitlines():
            if line.startswith("ID="):
                self.os_id = line.split("=", 1)[1].strip().strip('"')
            if line.startswith("VERSION_ID="):
                self.os_ver = line.split("=", 1)[1].strip().strip('"')
        self.log(f"[+] {self.os_id} {self.os_ver}")
        self.log(out.split("---")[-1].strip()[:200])

    def ensure_swap(self):
        self.set_pct(6)
        code, out = self.ssh.run("awk '/MemTotal/{print $2}' /proc/meminfo; swapon --show | wc -l")
        lines = [x.strip() for x in out.splitlines() if x.strip()]
        mem_kb = int(lines[0]) if lines and lines[0].isdigit() else 0
        swap_rows = int(lines[-1]) if lines and lines[-1].isdigit() else 1
        if mem_kb and mem_kb < 5_500_000 and swap_rows <= 1:
            self.log("[*] RAM < 5.5G — adding 4G swap (install.sh compiles a lot of Go)")
            self.ssh.run(
                "if [ ! -f /swapfile ]; then "
                "fallocate -l 4G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=4096; "
                "chmod 600 /swapfile; mkswap /swapfile; swapon /swapfile; "
                "grep -q /swapfile /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab; "
                "fi",
                timeout=120,
            )

    def apt_base(self):
        self.set_pct(10)
        self.log("[*] apt update + base packages")
        self.ssh.run(
            "export DEBIAN_FRONTEND=noninteractive; "
            "apt-get update -y && apt-get install -y "
            "git curl wget ca-certificates python3 python3-venv python3-pip python3-full "
            "build-essential unzip jq libpcap-dev gcc make sudo",
            timeout=600,
            check=True,
        )

    def install_go(self):
        self.set_pct(18)
        self.log("[*] Go — apt golang-go first (official go.dev tarball 404s on some VPS)")
        self.ssh.run(
            "export DEBIAN_FRONTEND=noninteractive; apt-get install -y golang-go || true",
            timeout=300,
        )
        code, _ = self.ssh.run("command -v go")
        if code != 0:
            self.log("[*] apt Go missing — trying go.dev tarball go1.22.12")
            self.ssh.run(
                "curl -fL https://go.dev/dl/go1.22.12.linux-amd64.tar.gz -o /tmp/go.tgz "
                "&& rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tgz "
                "&& ln -sfn /usr/local/go/bin/go /usr/local/bin/go",
                timeout=180,
                check=True,
            )
        _, goroot = self.ssh.run("go env GOROOT")
        self.goroot = (goroot or "").strip().splitlines()[-1].strip()
        if not self.goroot:
            self.goroot = "/usr/local/go"
        self.gopath = "/root/go"
        self.log(f"[+] Go ready  GOROOT={self.goroot}")
        self.ssh.run(
            f"ln -sfn {shlex.quote(self.goroot)} /usr/local/go; "
            "mkdir -p /root/go/bin /root/.local/bin; "
            f"cat > /etc/profile.d/golang.sh <<'EOF'\n"
            f"export GOROOT={self.goroot}\n"
            f"export GOPATH={self.gopath}\n"
            f"export PATH=\"{self.goroot}/bin:{self.gopath}/bin:/root/.local/bin:$PATH\"\n"
            "EOF\n"
            "grep -q '^GOROOT=' /etc/environment || "
            f"printf '\\nGOROOT={self.goroot}\\nGOPATH={self.gopath}\\n' >> /etc/environment",
            timeout=30,
            check=True,
        )

    def path_env(self):
        return (
            f"export GOROOT={shlex.quote(self.goroot)} GOPATH={shlex.quote(self.gopath)} "
            f"PATH={shlex.quote(self.goroot)}/bin:{shlex.quote(self.gopath)}/bin:"
            "/root/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin "
            "DEBIAN_FRONTEND=noninteractive HOME=/root"
        )

    def clone_reconftw(self):
        self.set_pct(24)
        code, _ = self.ssh.run(f"test -f {REMOTE_RECON}/reconftw.sh", quiet=True)
        if code == 0:
            self.log("[+] reconFTW already present — skip clone")
            return
        self.log(f"[*] Cloning {RECON_REPO}")
        self.ssh.run(
            f"rm -rf {REMOTE_RECON}.partial; "
            f"git clone --depth 1 {RECON_REPO} {REMOTE_RECON}.partial && "
            f"mv {REMOTE_RECON}.partial {REMOTE_RECON}",
            timeout=300,
            check=True,
        )

    def _tail_new(self, path, last_n):
        _, out = self.ssh.run(
            f"wc -l < {shlex.quote(path)} 2>/dev/null || echo 0",
            pty=False, quiet=True,
        )
        try:
            n = int((out or "0").replace("\r", "").strip().splitlines()[-1])
        except ValueError:
            n = last_n
        if n > last_n:
            _, tail = self.ssh.run(
                f"sed -n '{last_n + 1},{n}p' {shlex.quote(path)}",
                pty=False, quiet=True,
            )
            for line in tail.splitlines():
                s = line.replace("\r", "").rstrip()
                if s:
                    self.log("    " + s[:220])
            blob = tail.lower()
            if "installing system packages" in blob:
                self.set_pct(38)
            elif "golang" in blob:
                self.set_pct(45)
            elif "installing tools" in blob or "go install" in blob:
                self.set_pct(58)
            elif "finished" in blob:
                self.set_pct(70)
        return n

    def _read_exit(self, path):
        _, ex = self.ssh.run(f"cat {shlex.quote(path)} 2>/dev/null || echo MISSING", pty=False, quiet=True)
        raw = (ex or "").replace("\r", "").strip().splitlines()
        val = raw[-1] if raw else "MISSING"
        if val == "MISSING" or not val:
            return None
        try:
            return int(val)
        except ValueError:
            return None

    def run_logged(self, title, cmd, logfile, timeout=9000):
        """Run a long job in its own session so SSH PTY close cannot SIGHUP it."""
        self.log(f"[*] {title}  (this can take 20–60 min — log is tailed live)")
        unit = "rftw-" + os.path.basename(logfile).replace(".", "-")
        wrapper = f"{REMOTE_RECON}/_panel_{unit}.sh"
        exit_file = f"{logfile}.exit"
        outer = f"{logfile}.outer"
        body = (
            "#!/bin/bash\n"
            "set +e\n"
            f"{cmd}\n"
            f"echo $? > {exit_file}\n"
        )
        self.ssh.write_text(wrapper, body)
        self.ssh.run(
            f"chmod +x {wrapper}; rm -f {exit_file}; : > {outer}",
            pty=False, quiet=True,
        )
        start = (
            f"systemctl stop {unit} 2>/dev/null || true; "
            f"systemctl reset-failed {unit} 2>/dev/null || true; "
            f"systemd-run --no-block --collect --unit={unit} "
            f"--working-directory={REMOTE_RECON} "
            f"--property=StandardOutput=append:{outer} "
            f"--property=StandardError=append:{outer} "
            f"/bin/bash {wrapper} ; echo START:$?"
        )
        code, out = self.ssh.run(start, timeout=30, pty=False, quiet=True)
        blob = (out or "").replace("\r", "").replace(" ", "")
        if "START:0" not in blob:
            self.log("[!] systemd-run unavailable — falling back to setsid")
            code, out = self.ssh.run(
                f"nohup setsid /bin/bash {wrapper} </dev/null >> {outer} 2>&1 & echo PID:$!",
                timeout=20, pty=False, quiet=True,
            )
            pid = ""
            for line in (out or "").replace("\r", "").splitlines():
                if line.startswith("PID:"):
                    pid = line.split(":", 1)[-1].strip()
            if not pid:
                raise RuntimeError(f"Could not start: {title}\n{out}")
            self.log(f"    pid {pid}  log {logfile}")
            return self._wait_exit(title, logfile, outer, exit_file, timeout, pid=pid)
        self.log(f"    systemd unit {unit}  log {logfile}")
        return self._wait_exit(title, logfile, outer, exit_file, timeout, unit=unit)

    def _wait_exit(self, title, logfile, outer, exit_file, timeout, pid=None, unit=None):
        last = 0
        last_outer = 0
        deadline = time.time() + timeout
        started = time.time()
        while time.time() < deadline:
            last = self._tail_new(logfile, last)
            last_outer = self._tail_new(outer, last_outer)
            rc = self._read_exit(exit_file)
            if rc is not None:
                last = self._tail_new(logfile, last)
                last_outer = self._tail_new(outer, last_outer)
                if rc != 0:
                    self.log(f"[!] {title} exited {rc}")
                    return rc
                self.log(f"[+] {title} — OK")
                return 0
            if pid:
                _, live = self.ssh.run(
                    f"kill -0 {pid} 2>/dev/null; echo LIVE:$?",
                    pty=False, quiet=True,
                )
                alive = "LIVE:0" in (live or "").replace("\r", "").replace(" ", "")
                if not alive and time.time() - started > 8:
                    rc = self._read_exit(exit_file)
                    return 1 if rc is None else rc
            if unit:
                _, st = self.ssh.run(
                    f"systemctl is-active {unit} 2>/dev/null || true",
                    pty=False, quiet=True,
                )
                state = (st or "").replace("\r", "").strip().splitlines()
                state = state[-1] if state else ""
                if state in ("failed",) and time.time() - started > 8:
                    rc = self._read_exit(exit_file)
                    return 1 if rc is None else rc
            time.sleep(8)
        raise RuntimeError(f"{title} timed out after {timeout}s")

    def install_engine(self):
        self.set_pct(30)
        self.ssh.run(
            f"test -f {REMOTE_RECON}/reconftw.cfg && "
            "sed -i 's/^install_golang=true/install_golang=false/' "
            f"{REMOTE_RECON}/reconftw.cfg || true",
            timeout=20, quiet=True,
        )
        env = self.path_env()
        log = f"{REMOTE_RECON}/install.log"
        rc = self.run_logged(
            "reconFTW install.sh (repos + apt + tools)",
            f"{env}; cd {REMOTE_RECON}; bash ./install.sh --verbose",
            log,
            timeout=9000,
        )
        if rc != 0:
            self.log("[!] first install.sh was not clean — continuing with --tools (same recovery as the first VPS)")
        self.set_pct(72)
        self.log("[*] install.sh --tools (Go bins)")
        rc2 = self.run_logged(
            "reconFTW install.sh --tools",
            f"{env}; cd {REMOTE_RECON}; bash ./install.sh --tools --verbose",
            f"{REMOTE_RECON}/install-tools.log",
            timeout=5400,
        )
        self.symlink_bins()
        self.ssh.run(f"touch {REMOTE_RECON}/.panel_install_done", quiet=True)
        code, _ = self.ssh.run("command -v subfinder && command -v nuclei", quiet=True)
        if code != 0:
            raise RuntimeError(
                "subfinder/nuclei not on PATH after install. "
                f"install.sh exit={rc}, --tools exit={rc2}. See /root/reconftw/install.log"
            )
        self.log("[+] Engine tools on PATH (subfinder, nuclei)")

    def symlink_bins(self):
        self.set_pct(80)
        self.log("[*] Symlink /root/go/bin and ~/.local/bin -> /usr/local/bin")
        self.ssh.run(
            "for d in /root/go/bin /root/.local/bin; do "
            "  [ -d \"$d\" ] || continue; "
            "  for f in \"$d\"/*; do "
            "    [ -f \"$f\" ] && [ -x \"$f\" ] && ln -sfn \"$f\" \"/usr/local/bin/$(basename \"$f\")\"; "
            "  done; "
            "done",
            timeout=30,
            check=True,
        )

    def upload_panel(self):
        self.set_pct(84)
        self.log("[*] Uploading control panel")
        if not os.path.isdir(PAYLOAD):
            raise RuntimeError(f"payload folder missing: {PAYLOAD}")
        need = ["app.py", "findings.py", "severity.py", "requirements.txt"]
        for n in need:
            if not os.path.isfile(os.path.join(PAYLOAD, n)):
                raise RuntimeError(f"Missing payload/{n}")
        self.ssh.run(f"mkdir -p {REMOTE_PANEL}/templates {REMOTE_PANEL}/static {REMOTE_PANEL}/data")
        for dirpath, _dns, filenames in os.walk(PAYLOAD):
            rel = os.path.relpath(dirpath, PAYLOAD)
            remote = REMOTE_PANEL if rel == "." else f"{REMOTE_PANEL}/{rel.replace(os.sep, '/')}"
            self.ssh.mkdir_p(remote)
            for fn in filenames:
                if fn.endswith((".pyc", ".pyo")) or fn == ".env":
                    continue
                self.ssh.put_file(os.path.join(dirpath, fn), f"{remote}/{fn}")

    def write_env(self):
        secret = os.urandom(16).hex()
        pw = self.password.replace("\\", "\\\\").replace('"', '\\"')
        body = (
            f"PANEL_HOST=0.0.0.0\n"
            f"PANEL_PORT={self.panel_port}\n"
            f"PANEL_USER={self.user}\n"
            f"PANEL_PASS={pw}\n"
            f"PANEL_SECRET={secret}\n"
            f"RECONFTW_DIR={REMOTE_RECON}\n"
            f"RECONFTW_OUTPUT={REMOTE_RECON}/Recon\n"
            f"RECONFTW_TOOLS={REMOTE_TOOLS}\n"
            f"GOROOT={self.goroot}\n"
            f"GOPATH={self.gopath}\n"
        )
        remote = f"{REMOTE_PANEL}/.env"
        self.log("[*] Writing panel .env")
        self.ssh.run(f"cat > {remote} <<'ENVEOF'\n{body}ENVEOF\nchmod 600 {remote}", check=True)

    def panel_venv(self):
        self.set_pct(88)
        self.log("[*] Python venv + pip")
        self.ssh.run(
            f"python3 -m venv {REMOTE_PANEL}/venv && "
            f"{REMOTE_PANEL}/venv/bin/pip install -U pip && "
            f"{REMOTE_PANEL}/venv/bin/pip install -r {REMOTE_PANEL}/requirements.txt",
            timeout=300,
            check=True,
        )

    def systemd(self):
        self.set_pct(92)
        path = (
            f"{self.goroot}/bin:{self.gopath}/bin:/root/.local/bin:"
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
        )
        unit = f"""[Unit]
Description=reconFTW Control Panel
After=network.target

[Service]
User=root
WorkingDirectory={REMOTE_PANEL}
EnvironmentFile={REMOTE_PANEL}/.env
ExecStart={REMOTE_PANEL}/venv/bin/python3 -u {REMOTE_PANEL}/app.py
Restart=always
RestartSec=5
KillMode=process
Environment=PYTHONUNBUFFERED=1
Environment=GOROOT={self.goroot}
Environment=GOPATH={self.gopath}
Environment=PATH={path}

[Install]
WantedBy=multi-user.target
"""
        self.log("[*] systemd reconftw-panel")
        self.ssh.run(
            "cat > /etc/systemd/system/reconftw-panel.service <<'EOF'\n"
            + unit
            + "EOF\n"
            "mkdir -p /etc/systemd/system/reconftw-panel.service.d\n"
            "cat > /etc/systemd/system/reconftw-panel.service.d/kill.conf <<'K'\n"
            "[Service]\nKillMode=process\nK\n"
            "systemctl daemon-reload\n"
            "systemctl enable reconftw-panel\n"
            "systemctl restart reconftw-panel",
            timeout=40,
            check=True,
        )
        self.ssh.run(
            f"if command -v ufw >/dev/null; then ufw allow {self.panel_port}/tcp || true; fi"
        )
        time.sleep(2)
        code, out = self.ssh.run("systemctl is-active reconftw-panel")
        if "active" not in out:
            _, j = self.ssh.run("journalctl -u reconftw-panel -n 30 --no-pager")
            raise RuntimeError("panel unit is not active\n" + j[-2000:])
        self.log("[+] reconftw-panel is active")

    def detect_go_if_present(self):
        code, out = self.ssh.run("command -v go && go env GOROOT")
        if code == 0:
            lines = [x.strip() for x in out.splitlines() if x.strip()]
            for line in reversed(lines):
                if line.startswith("/"):
                    self.goroot = line
                    break

    def run(self):
        self.detect()
        self.ensure_swap()
        self.apt_base()
        self.install_go()
        self.clone_reconftw()
        self.install_engine()
        self.upload_panel()
        self.write_env()
        self.panel_venv()
        self.systemd()
        self.set_pct(100)
        self._done()

    def run_panel_only(self):
        self.detect()
        code, _ = self.ssh.run(f"test -f {REMOTE_RECON}/reconftw.sh", quiet=True)
        if code != 0:
            raise RuntimeError(
                "reconFTW not found at /root/reconftw. Use INSTALL (full stack), "
                "or put the engine there first."
            )
        self.detect_go_if_present()
        self.ssh.run(
            "export DEBIAN_FRONTEND=noninteractive; "
            "apt-get update -y && apt-get install -y python3 python3-venv python3-pip python3-full",
            timeout=300,
            check=True,
        )
        if self.goroot:
            self.symlink_bins()
        self.upload_panel()
        self.write_env()
        self.panel_venv()
        self.systemd()
        self.set_pct(100)
        self._done()

    def _done(self):
        url = f"http://{self.ssh.host}:{self.panel_port}"
        self.log("")
        self.log("=" * 54)
        self.log("  INSTALL COMPLETE")
        self.log(f"  Panel:    {url}")
        self.log(f"  Login:    {self.user}")
        self.log("  Password: (the SSH password you entered)")
        self.log("  Engine:   /root/reconftw")
        self.log("  Paste API keys in the panel (Shodan / GitHub / …) before a full scan.")
        self.log("  Tools page is for Health check / repair — not a second install.")
        self.log("=" * 54)


BG = "#0a0e17"
BG2 = "#111827"
BG3 = "#1a2332"
ACCENT = "#00ff88"
CYAN = "#22d3ee"
ORANGE = "#f59e0b"
TEXT = "#ffffff"
MUTED = "#94a3b8"
FONT = ("Segoe UI", 11)
MONO = ("Consolas", 10)
TITLE = ("Segoe UI", 18, "bold")


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"RECONFTW  //  INSTALLER v{PANEL_BUILD}")
        self.configure(bg=BG)
        self.geometry("760x740")
        self.minsize(680, 620)
        self.installing = False
        self._set_icons()
        self._build()

    def _icon_path(self, name):
        for base in (HERE, os.path.dirname(os.path.abspath(__file__)), PAYLOAD):
            p = os.path.join(base, name)
            if os.path.isfile(p):
                return p
        nested = os.path.join(PAYLOAD, "static", name)
        return nested if os.path.isfile(nested) else ""

    def _set_icons(self):
        ico = self._icon_path("icon.ico")
        png = self._icon_path("icon.png")
        try:
            if ico:
                self.iconbitmap(ico)
        except Exception:
            pass
        try:
            if png:
                self._wm_icon = tk.PhotoImage(file=png)
                self.iconphoto(True, self._wm_icon)
        except Exception:
            pass

    def _build(self):
        pad = {"padx": 18, "pady": 6}
        head = tk.Frame(self, bg=BG)
        head.pack(pady=(18, 0))
        mark = self._icon_path("icon.png")
        if mark:
            try:
                self._logo_img = tk.PhotoImage(file=mark)
                tk.Label(head, image=self._logo_img, bg=BG).pack()
            except Exception:
                pass
        tk.Label(head, text="RECONFTW", fg=ACCENT, bg=BG, font=TITLE).pack(pady=(8, 0))
        tk.Label(
            head,
            text=f"CONTROL PANEL INSTALLER v{PANEL_BUILD}  ·  Ubuntu 22.04 / 24.04 / 26.04",
            fg=CYAN, bg=BG, font=("Segoe UI", 9),
        ).pack(pady=(4, 2))
        credit = tk.Frame(head, bg=BG)
        credit.pack(pady=(0, 8))
        tk.Label(credit, text="Created by ", fg=ORANGE, bg=BG, font=("Segoe UI", 8)).pack(side="left")
        tk.Label(credit, text="ZynTarvo", fg=ACCENT, bg=BG, font=("Segoe UI", 8, "bold")).pack(side="left")

        form = tk.Frame(self, bg=BG)
        form.pack(fill="x", **pad)
        self.var_ip = tk.StringVar()
        self.var_port = tk.StringVar(value="22")
        self.var_user = tk.StringVar(value="root")
        self.var_pass = tk.StringVar()
        self.var_panel = tk.StringVar(value="8443")

        def row(r, label, var, show=None):
            tk.Label(form, text=label, fg=ACCENT, bg=BG, font=("Segoe UI", 9, "bold")).grid(
                row=r, column=0, sticky="w", pady=6, padx=(0, 12)
            )
            e = tk.Entry(
                form, textvariable=var, font=FONT, bg=BG3, fg=TEXT,
                insertbackground=ACCENT, relief="flat", highlightthickness=1,
                highlightbackground="#1e3a2f", highlightcolor=ACCENT, show=show or "",
            )
            e.grid(row=r, column=1, sticky="ew", ipady=7)
            return e

        form.columnconfigure(1, weight=1)
        row(0, "SERVER IP", self.var_ip)
        row(1, "SSH PORT", self.var_port)
        row(2, "LOGIN", self.var_user)
        row(3, "PASSWORD", self.var_pass, show="•")
        row(4, "PANEL PORT", self.var_panel)

        self.btn_row = tk.Frame(self, bg=BG)
        self.btn_row.pack(fill="x", padx=18, pady=(10, 8))
        self.btn = tk.Button(
            self.btn_row, text="INSTALL", command=self.start, font=("Segoe UI", 12, "bold"),
            bg=ACCENT, fg=BG, activebackground="#4ade80", activeforeground=BG,
            relief="flat", cursor="hand2", pady=10,
        )
        self.btn.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.btn_cp = tk.Button(
            self.btn_row, text="INSTALL ONLY CP", command=self.start_panel_only,
            font=("Segoe UI", 12, "bold"),
            bg=CYAN, fg=BG, activebackground="#67e8f9", activeforeground=BG,
            relief="flat", cursor="hand2", pady=10,
        )
        self.btn_cp.pack(side="left", fill="x", expand=True, padx=(6, 0))

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("RF.Horizontal.TProgressbar", troughcolor=BG3, background=ACCENT, bordercolor=BG)
        self.pb = ttk.Progressbar(self, style="RF.Horizontal.TProgressbar", mode="determinate", maximum=100)
        self.pb.pack(fill="x", padx=18, pady=(0, 8))

        self.logbox = scrolledtext.ScrolledText(
            self, height=16, bg=BG2, fg=ACCENT, insertbackground=ACCENT,
            font=MONO, relief="flat", wrap="word",
        )
        self.logbox.pack(fill="both", expand=True, padx=18, pady=(0, 18))
        self.logbox.tag_configure("okmark", foreground=ACCENT, font=("Segoe UI", 18, "bold"))
        self.logbox.configure(state="disabled")
        self._log(f"[*] Installer v{PANEL_BUILD} — panel payload packed in payload/")
        self._log("[*] INSTALL = Go + clone reconFTW + install.sh + panel (20–60 min)")
        self._log("[*] INSTALL ONLY CP = panel only, engine must already be at /root/reconftw")
        self._log("[*] After INSTALL you do NOT need Tools → Install. Paste API keys and scan.")

    def _log(self, msg):
        def _append():
            self.logbox.configure(state="normal")
            self.logbox.insert("end", msg + "\n")
            self.logbox.see("end")
            self.logbox.configure(state="disabled")
        self.after(0, _append)

    def _log_done(self):
        def _append():
            self.logbox.configure(state="normal")
            self.logbox.insert("end", "Installation process fully complete  ")
            self.logbox.insert("end", "✔\n", "okmark")
            self.logbox.see("end")
            self.logbox.configure(state="disabled")
        self.after(0, _append)

    def _progress(self, n):
        self.after(0, lambda: self.pb.configure(value=n))

    def _on_success(self, url):
        try:
            webbrowser.open(url, new=2)
        except Exception as e:
            self._log(f"[!] Could not open browser: {e}")

    def start(self):
        self._begin("full")

    def start_panel_only(self):
        self._begin("panel")

    def _set_busy(self, busy: bool, mode: str = "full"):
        if busy:
            self.btn.configure(state="disabled", text="INSTALLING...")
            self.btn_cp.configure(state="disabled", text="WAIT...")
            if mode == "panel":
                self.btn_cp.configure(text="INSTALLING CP...")
        else:
            self.btn.configure(state="normal", text="INSTALL")
            self.btn_cp.configure(state="normal", text="INSTALL ONLY CP")

    def _begin(self, mode: str):
        if self.installing:
            return
        ip = self.var_ip.get().strip()
        port = self.var_port.get().strip() or "22"
        user = self.var_user.get().strip()
        pw = self.var_pass.get()
        pport = self.var_panel.get().strip() or "8443"
        if not ip or not user or not pw:
            messagebox.showerror("Missing fields", "IP, login and password are required.")
            return
        try:
            pport_i = int(pport)
        except ValueError:
            messagebox.showerror("Panel port", "Panel port must be a number.")
            return
        if not os.path.isdir(PAYLOAD):
            messagebox.showerror("Payload missing", f"Folder not found:\n{PAYLOAD}")
            return
        self.installing = True
        self._set_busy(True, mode)
        self.pb.configure(value=1)
        t = threading.Thread(target=self._worker, args=(ip, port, user, pw, pport_i, mode), daemon=True)
        t.start()

    def _worker(self, ip, port, user, pw, pport, mode="full"):
        ssh = None
        try:
            ssh = SSH(ip, port, user, pw, self._log)
            ssh.connect()
            inst = Installer(ssh, user, pw, pport, self._progress)
            if mode == "panel":
                inst.run_panel_only()
            else:
                inst.run()
            url = f"http://{ip}:{pport}"
            self._log(f"[*] Opening browser: {url}")
            self._log_done()
            self.after(0, lambda u=url: self._on_success(u))
        except Exception as e:
            self._log("")
            self._log("[ERROR] " + str(e))
            self._log(traceback.format_exc().splitlines()[-1])
            self.after(0, lambda: messagebox.showerror("Install failed", str(e)[:800]))
        finally:
            if ssh:
                ssh.close()
            self.installing = False
            self.after(0, lambda: self._set_busy(False))


def main():
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
