#!/usr/bin/env python3
"""Parse reconFTW output folders into panel findings."""
from __future__ import annotations

import csv
import html
import json
import re
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from severity import classify as classify_severity

CVE_RE = re.compile(r"CVE-\d{4}-\d+", re.I)
SEV_ORDER = ("critical", "high", "medium", "low", "info", "unknown")
SEV_LABEL = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Info",
    "unknown": "Unknown",
}


def recon_dir(target, *roots):
    t = (target or "").strip().lower()
    if not t or " " in t or ".." in t:
        return None
    t = t.split("/")[0]
    for root in roots:
        p = Path(root) / t
        if p.is_dir():
            return p
    return None


def _read_lines(path, limit=5000):
    p = Path(path)
    if not p.is_file() or p.stat().st_size == 0:
        return []
    out = []
    with p.open("r", encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f):
            s = line.strip()
            if s:
                out.append(s)
            if len(out) >= limit:
                break
    return out


def _json_load(path):
    p = Path(path)
    if not p.is_file() or p.stat().st_size == 0:
        return None
    try:
        return json.loads(p.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        return None


def _iter_jsonl(path, limit=4000):
    p = Path(path)
    if not p.is_file():
        return
    with p.open("r", encoding="utf-8", errors="replace") as f:
        n = 0
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
                n += 1
                if n >= limit:
                    return
            except Exception:
                continue


def _norm_sev(s):
    s = (s or "unknown").strip().lower()
    if s in SEV_ORDER:
        return s
    return "unknown"


def _cves(*parts):
    found = []
    seen = set()
    for part in parts:
        if part is None:
            continue
        if isinstance(part, (list, tuple)):
            text = " ".join(str(x) for x in part)
        else:
            text = str(part)
        for m in CVE_RE.findall(text):
            u = m.upper()
            if u not in seen:
                seen.add(u)
                found.append(u)
    return found


def _nuclei_items(root: Path):
    items = []
    njson = root / "nuclei_output"
    files = []
    if njson.is_dir():
        files = sorted(njson.glob("*_json.txt")) + sorted(njson.glob("*.jsonl"))
    extra = root / ".tmp" / "nuclei_combined_json.txt"
    if extra.is_file():
        files.append(extra)
    seen = set()
    for fp in files:
        for obj in _iter_jsonl(fp):
            blob = json.dumps(obj, sort_keys=True, default=str)
            if blob in seen:
                continue
            seen.add(blob)
            info = obj.get("info") or {}
            tid = obj.get("template-id") or obj.get("template_id") or ""
            matched = obj.get("matched-at") or obj.get("matched") or obj.get("host") or ""
            classif = info.get("classification") or {}
            cves = _cves(
                classif.get("cve-id"),
                classif.get("cve_id"),
                tid,
                info.get("name"),
                info.get("description"),
                obj.get("extracted-results"),
            )
            item = {
                "id": f"{tid}|{matched}|{len(items)}",
                "template_id": tid,
                "name": info.get("name") or tid or "Finding",
                "severity": _norm_sev(info.get("severity") or obj.get("severity")),
                "host": obj.get("host") or "",
                "target": matched,
                "type": obj.get("type") or obj.get("finding_type") or "",
                "matcher": obj.get("matcher-name") or "",
                "tags": info.get("tags") or [],
                "description": (info.get("description") or "").strip(),
                "impact": (info.get("impact") or "").strip(),
                "reference": info.get("reference") or [],
                "cve": cves,
                "cwe": classif.get("cwe-id") or classif.get("cwe_id") or [],
                "cvss": classif.get("cvss-score") or classif.get("cvss_score"),
                "extracted": obj.get("extracted-results") or [],
                "curl": obj.get("curl-command") or "",
                "ip": obj.get("ip") or "",
            }
            item.update(classify_severity(item))
            items.append(item)
    if items:
        return items
    # fallback csv
    csvp = root / "report" / "findings.csv"
    if csvp.is_file():
        with csvp.open("r", encoding="utf-8", errors="replace") as f:
            r = csv.DictReader(f)
            for i, row in enumerate(r):
                item = {
                    "id": f"csv-{i}",
                    "template_id": row.get("template_id") or "",
                    "name": row.get("name") or row.get("template_id") or "Finding",
                    "severity": _norm_sev(row.get("severity")),
                    "host": row.get("host") or "",
                    "target": row.get("target") or "",
                    "type": row.get("finding_type") or "",
                    "matcher": row.get("matcher_name") or "",
                    "tags": [],
                    "description": "",
                    "impact": "",
                    "reference": [],
                    "cve": _cves(row.get("name"), row.get("template_id")),
                    "cwe": [],
                    "cvss": None,
                    "extracted": [],
                    "curl": "",
                    "ip": "",
                }
                item.update(classify_severity(item))
                items.append(item)
    return items


def _fuzz_summary(root: Path, cap=180):
    p = root / "fuzzing" / "fuzzing_full.txt"
    if not p.is_file():
        return {"total": 0, "counts": {}, "items": []}
    counts = Counter()
    items = []
    seen = set()
    with p.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            parts = line.split()
            if len(parts) < 3:
                continue
            code, size, url = parts[0], parts[1], parts[-1]
            if not code.isdigit():
                continue
            counts[code] += 1
            if url in seen:
                continue
            if code in {"200", "201", "204", "301", "302", "401", "403", "500"} and len(items) < cap:
                seen.add(url)
                items.append({"status": code, "size": size, "url": url})
    return {"total": int(sum(counts.values())), "counts": dict(counts.most_common(12)), "items": items}


def collect(root: Path):
    root = Path(root)
    vulns = _nuclei_items(root)
    sev = {k: 0 for k in SEV_ORDER}
    cve_n = 0
    for v in vulns:
        sev[v["severity"]] = sev.get(v["severity"], 0) + 1
        if v.get("cve"):
            cve_n += 1

    subs = _read_lines(root / "subdomains" / "subdomains.txt")
    webs = _read_lines(root / "webs" / "webs_all.txt") or _read_lines(root / "webs" / "webs.txt")
    emails = [x for x in _read_lines(root / "osint" / "emails.txt") if "@" in x]
    ips = _read_lines(root / "hosts" / "ips.txt")
    shots = []
    sdir = root / "screenshots"
    if sdir.is_dir():
        for p in sorted(sdir.iterdir()):
            if p.suffix.lower() in {".png", ".jpg", ".jpeg", ".webp"}:
                label = p.stem.replace(":__", "://")
                shots.append({"file": p.name, "rel": f"screenshots/{p.name}", "label": label})

    js = _read_lines(root / "js" / "url_extract_js.txt")
    cms = []
    cdir = root / "cms"
    if cdir.is_dir():
        for p in cdir.rglob("cms.json"):
            obj = _json_load(p) or {}
            cms.append({
                "url": obj.get("url") or obj.get("target_url") or str(p.parent.name),
                "cms": obj.get("cms_name") or "unknown",
                "rel": str(p.relative_to(root)).replace("\\", "/"),
            })

    osint_files = []
    odir = root / "osint"
    if odir.is_dir():
        for p in sorted(odir.iterdir()):
            if p.is_file() and p.stat().st_size:
                osint_files.append({"name": p.name, "size": p.stat().st_size, "rel": f"osint/{p.name}"})

    fuzz = _fuzz_summary(root)
    report = _json_load(root / "report" / "report.json") or {}
    summary = dict(report.get("summary") or {})
    summary["findings_total"] = len(vulns)
    runtime = report.get("runtime") or ""

    cats = [
        {"id": "vulns", "title": "Vulnerabilities", "icon": "fa-bug", "count": len(vulns), "cves": cve_n},
        {"id": "subdomains", "title": "Subdomains", "icon": "fa-sitemap", "count": len(subs)},
        {"id": "webs", "title": "Web hosts", "icon": "fa-globe", "count": len(webs)},
        {"id": "screenshots", "title": "Screenshots", "icon": "fa-camera", "count": len(shots)},
        {"id": "osint", "title": "OSINT", "icon": "fa-user-secret", "count": len(emails) + len(osint_files)},
        {"id": "hosts", "title": "Hosts & ports", "icon": "fa-server", "count": len(ips)},
        {"id": "fuzzing", "title": "Fuzzing", "icon": "fa-bolt", "count": fuzz["total"]},
        {"id": "cms", "title": "CMS", "icon": "fa-cubes", "count": len(cms)},
        {"id": "js", "title": "JavaScript", "icon": "fa-js", "count": len(js)},
    ]
    return {
        "domain": root.name,
        "runtime": runtime,
        "summary": summary,
        "severities": sev,
        "categories": cats,
        "vulns": vulns,
        "subdomains": subs,
        "webs": webs,
        "screenshots": shots,
        "emails": emails,
        "osint_files": osint_files,
        "ips": ips,
        "ipinfo": "\n".join(_read_lines(root / "hosts" / "ipinfo.txt", 80)),
        "ports": "\n".join(_read_lines(root / "hosts" / "portscan_shodan.txt", 80)),
        "cms": cms,
        "js": js,
        "fuzz": fuzz,
        "dorks": _read_lines(root / "osint" / "dorks.txt", 80),
        "misconfig": _read_lines(root / "osint" / "3rdparts_misconfigurations.txt", 80),
    }


def category_payload(data, cat, severity=None):
    if cat == "vulns":
        items = data["vulns"]
        if severity:
            items = [x for x in items if x["severity"] == severity]
        return {"title": "Vulnerabilities", "kind": "vulns", "items": items, "filter": severity}
    if cat == "subdomains":
        return {"title": "Subdomains", "kind": "list", "items": [{"title": x} for x in data["subdomains"]]}
    if cat == "webs":
        return {"title": "Web hosts", "kind": "list", "items": [{"title": x} for x in data["webs"]]}
    if cat == "screenshots":
        return {"title": "Screenshots", "kind": "shots", "items": data["screenshots"]}
    if cat == "osint":
        return {
            "title": "OSINT",
            "kind": "osint",
            "emails": data["emails"],
            "files": data["osint_files"],
            "dorks": data["dorks"],
            "misconfig": data["misconfig"],
        }
    if cat == "hosts":
        return {
            "title": "Hosts & ports",
            "kind": "hosts",
            "ips": data["ips"],
            "ipinfo": data["ipinfo"],
            "ports": data["ports"],
        }
    if cat == "fuzzing":
        return {"title": "Fuzzing", "kind": "fuzz", **data["fuzz"]}
    if cat == "cms":
        return {"title": "CMS", "kind": "cms", "items": data["cms"]}
    if cat == "js":
        return {"title": "JavaScript", "kind": "list", "items": [{"title": x} for x in data["js"]]}
    return {"title": cat, "kind": "empty", "items": []}


def render_md(data):
    d = data["domain"]
    lines = [
        f"# reconFTW report — `{d}`",
        "",
        f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"Runtime: {data.get('runtime') or '—'}",
        "",
        "## Severity",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]
    for k in SEV_ORDER:
        n = data["severities"].get(k, 0)
        if n or k in ("critical", "high", "medium", "low", "info"):
            lines.append(f"| **{SEV_LABEL[k]}** | {n} |")
    lines += ["", "## Vulnerabilities", ""]
    if not data["vulns"]:
        lines.append("_No nuclei findings._")
    for v in data["vulns"]:
        cve = ", ".join(f"**{c}**" for c in (v.get("cve") or [])) or "—"
        lines += [
            f"### {v['name']}",
            "",
            f"- Severity: **{v['severity'].upper()}**",
            f"- Template: `{v['template_id']}`",
            f"- Target: `{v['target']}`",
            f"- CVE: {cve}",
        ]
        if v.get("description"):
            lines += ["", v["description"].strip()]
        if v.get("impact"):
            lines += ["", f"**Impact:** {v['impact'].strip()}"]
        lines.append("")
    lines += ["## Subdomains", ""]
    lines += [f"- `{x}`" for x in data["subdomains"]] or ["_none_"]
    lines += ["", "## Web hosts", ""]
    lines += [f"- {x}" for x in data["webs"]] or ["_none_"]
    lines += ["", "## Emails", ""]
    lines += [f"- `{x}`" for x in data["emails"]] or ["_none_"]
    lines += ["", "## Fuzzing", f"Total responses: **{data['fuzz']['total']}**", ""]
    for it in data["fuzz"]["items"][:80]:
        lines.append(f"- `{it['status']}` {it['url']}")
    return "\n".join(lines) + "\n"


def render_html(data):
    d = html.escape(data["domain"])
    sev_html = []
    colors = {
        "critical": "#ef4444",
        "high": "#f97316",
        "medium": "#f59e0b",
        "low": "#22d3ee",
        "info": "#94a3b8",
        "unknown": "#64748b",
    }
    for k in SEV_ORDER:
        n = data["severities"].get(k, 0)
        sev_html.append(
            f'<div class="sev" style="border-color:{colors[k]}"><div class="n" style="color:{colors[k]}">{n}</div><div class="l">{SEV_LABEL[k]}</div></div>'
        )
    rows = []
    for v in data["vulns"]:
        cves = " ".join(f'<b class="cve">{html.escape(c)}</b>' for c in (v.get("cve") or [])) or "—"
        desc = html.escape((v.get("description") or "")[:500])
        rows.append(
            f"<tr class='{html.escape(v['severity'])}'><td><span class='pill {html.escape(v['severity'])}'>{html.escape(v['severity'].upper())}</span></td>"
            f"<td><strong>{html.escape(v['name'])}</strong><div class='muted'>{html.escape(v.get('template_id') or '')}</div></td>"
            f"<td><code>{html.escape(v.get('target') or '')}</code></td><td>{cves}</td><td>{desc}</td></tr>"
        )
    subs = "".join(f"<li><code>{html.escape(x)}</code></li>" for x in data["subdomains"]) or "<li>—</li>"
    webs = "".join(f"<li>{html.escape(x)}</li>" for x in data["webs"]) or "<li>—</li>"
    fuzz = "".join(
        f"<tr><td>{html.escape(it['status'])}</td><td><code>{html.escape(it['url'])}</code></td></tr>"
        for it in data["fuzz"]["items"][:120]
    )
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>reconFTW — {d}</title>
<style>
body{{margin:0;font-family:Inter,system-ui,sans-serif;background:#0a0e17;color:#e2e8f0}}
.wrap{{max-width:1100px;margin:0 auto;padding:32px 20px}}
h1{{color:#00ff88;letter-spacing:1px}} h2{{margin-top:32px;color:#fff}}
.muted{{color:#94a3b8;font-size:12px}}
.grid{{display:flex;gap:10px;flex-wrap:wrap;margin:16px 0}}
.sev{{background:#111827;border:1px solid;border-radius:12px;padding:14px 18px;min-width:110px;text-align:center}}
.sev .n{{font-size:28px;font-weight:700}} .sev .l{{font-size:11px;letter-spacing:1px;text-transform:uppercase;color:#94a3b8}}
table{{width:100%;border-collapse:collapse;background:#111827;border-radius:10px;overflow:hidden}}
th,td{{padding:10px 12px;border-bottom:1px solid rgba(255,255,255,.06);text-align:left;vertical-align:top;font-size:13px}}
th{{color:#00ff88;font-size:11px;letter-spacing:1px;text-transform:uppercase}}
.pill{{display:inline-block;padding:3px 8px;border-radius:6px;font-size:11px;font-weight:700}}
.pill.critical{{background:rgba(239,68,68,.15);color:#ef4444}}
.pill.high{{background:rgba(249,115,22,.15);color:#f97316}}
.pill.medium{{background:rgba(245,158,11,.15);color:#f59e0b}}
.pill.low{{background:rgba(34,211,238,.15);color:#22d3ee}}
.pill.info{{background:rgba(148,163,184,.15);color:#94a3b8}}
.cve{{color:#00ff88;font-family:ui-monospace,monospace}}
code{{color:#22d3ee;font-size:12px}}
ul{{line-height:1.7}}
</style></head><body><div class="wrap">
<h1>reconFTW report</h1>
<p class="muted">{d} · {html.escape(data.get('runtime') or '')} · {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</p>
<div class="grid">{''.join(sev_html)}</div>
<h2>Vulnerabilities</h2>
<table><thead><tr><th>Sev</th><th>Name</th><th>Target</th><th>CVE</th><th>Description</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan="5">None</td></tr>'}</tbody></table>
<h2>Subdomains</h2><ul>{subs}</ul>
<h2>Web hosts</h2><ul>{webs}</ul>
<h2>Fuzzing</h2><p class="muted">Total {data['fuzz']['total']} responses</p>
<table><thead><tr><th>Status</th><th>URL</th></tr></thead><tbody>{fuzz or '<tr><td colspan="2">None</td></tr>'}</tbody></table>
</div></body></html>
"""
