#!/usr/bin/env python3
"""Map recon/nuclei findings to DAST-style severity.

Rules are taken from CWE + typical Acunetix / OWASP ratings - not invented
per-scan. Nuclei's own High/Critical/Medium is never downgraded.
"""
from __future__ import annotations

import re

SEV_RANK = {
    "info": 0,
    "unknown": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# Session-ish cookie names → cookie-flag issues become more serious.
_SESSION_COOKIE = re.compile(
    r"(session|sessid|phpsessid|jsessionid|asp\.net_sessionid|jwt|token|auth|sid|remember|csrf)",
    re.I,
)

# Acunetix-class template / matcher map. Keys: (template_id, matcher_or_None).
# matcher None = any matcher for that template.
_TEMPLATE = {
    ("cookies-without-httponly", None): (
        "low",
        "CWE-1004 - cookie without HttpOnly. Acunetix/OWASP rate this Low "
        "(session theft via XSS). Upgraded to Medium if the cookie looks like a session.",
    ),
    ("cookies-without-secure", None): (
        "low",
        "CWE-614 - cookie without Secure. Acunetix rates this Low; Medium if it is a session cookie on HTTPS.",
    ),
    ("missing-cookie-samesite-strict", None): (
        "low",
        "CWE-693 - SameSite=Strict missing. Lax is the modern default; Acunetix-class Low.",
    ),
    ("http-missing-security-headers", "strict-transport-security"): (
        "medium",
        "CWE-693 / OWASP A02 - missing HSTS. Acunetix 'HSTS not enabled' is Medium.",
    ),
    ("http-missing-security-headers", "x-frame-options"): (
        "low",
        "CWE-1021 - missing X-Frame-Options / frame-ancestors. Acunetix clickjacking header = Low.",
    ),
    ("http-missing-security-headers", "content-security-policy"): (
        "low",
        "CWE-693 - missing CSP. Acunetix/OWASP treat CSP absence as Low hardening.",
    ),
    ("http-missing-security-headers", "x-content-type-options"): (
        "low",
        "CWE-693 - missing X-Content-Type-Options (nosniff). Standard DAST Low.",
    ),
    ("http-missing-security-headers", "referrer-policy"): (
        "info",
        "Privacy header only - no direct exploit. Kept Informational.",
    ),
    ("http-missing-security-headers", "permissions-policy"): (
        "info",
        "Feature-policy hardening. Informational.",
    ),
    ("http-missing-security-headers", "cross-origin-embedder-policy"): (
        "info",
        "COEP isolation header. Informational.",
    ),
    ("http-missing-security-headers", "cross-origin-opener-policy"): (
        "info",
        "COOP isolation header. Informational.",
    ),
    ("http-missing-security-headers", "cross-origin-resource-policy"): (
        "info",
        "CORP isolation header. Informational.",
    ),
    ("http-missing-security-headers", "x-permitted-cross-domain-policies"): (
        "info",
        "Adobe cross-domain policy header. Informational.",
    ),
    ("missing-sri", None): (
        "medium",
        "CWE-353 - third-party JS/CSS without Subresource Integrity. Supply-chain Medium.",
    ),
    ("https-to-http-redirect", None): (
        "high",
        "HTTPS-to-HTTP redirect enables SSL-stripping / MITM. Treated as High (transport downgrade).",
    ),
    ("rdap-whois", None): ("info", "OSINT/WHOIS inventory (CWE-200). Not a vulnerability."),
    ("tech-detect", None): ("info", "Technology fingerprint. Discovery only."),
    ("waf-detect", None): ("info", "WAF fingerprint. Discovery only."),
    ("tls-version", None): ("info", "TLS version inventory. TLS 1.0/1.1 would be Medium."),
    ("nameserver-fingerprint", None): ("info", "DNS NS inventory. Discovery only."),
    ("robots-txt", None): ("info", "robots.txt present. Discovery only."),
    ("robots-txt-endpoint", None): ("info", "robots.txt path. Discovery only."),
    ("dns-saas-service-detection", None): ("info", "DNS/SaaS fingerprint. Discovery only."),
    ("ssl-issuer", None): ("info", "Certificate issuer. Discovery only."),
    ("ssl-dns-names", None): ("info", "Certificate SAN list. Discovery only."),
    ("wildcard-tls", None): ("info", "Wildcard certificate observed. Inventory, not a vuln by itself."),
}

# If nuclei already assigned these, keep at least this rank.
_CWE = {
    "cwe-78": ("high", "CWE-78 OS command injection"),
    "cwe-89": ("critical", "CWE-89 SQL injection"),
    "cwe-79": ("high", "CWE-79 XSS"),
    "cwe-22": ("high", "CWE-22 path traversal"),
    "cwe-94": ("critical", "CWE-94 code injection"),
    "cwe-918": ("high", "CWE-918 SSRF"),
    "cwe-611": ("high", "CWE-611 XXE"),
    "cwe-352": ("medium", "CWE-352 CSRF"),
    "cwe-601": ("medium", "CWE-601 open redirect"),
    "cwe-1004": ("low", "CWE-1004 cookie without HttpOnly"),
    "cwe-614": ("low", "CWE-614 cookie without Secure"),
    "cwe-353": ("medium", "CWE-353 missing integrity check"),
}

_TAG_CRITICAL = {"rce", "unauth-rce", "remote-code-execution"}
_TAG_HIGH = {
    "sqli", "sql-injection", "ssti", "lfi", "rfi", "ssrf", "xxe",
    "xss", "reflected-xss", "stored-xss", "takeover", "default-login",
    "unauth", "deserialization", "jwt-none",
}
_WEAK_TLS = re.compile(r"\btls(10|11|1\.0|1\.1)\b", re.I)


def _norm_cwe(cwe):
    out = []
    if not cwe:
        return out
    if isinstance(cwe, str):
        cwe = [cwe]
    for x in cwe:
        s = str(x).strip().lower().replace("_", "-")
        if s and not s.startswith("cwe-"):
            s = "cwe-" + s
        if s:
            out.append(s)
    return out


def _cookie_names(extracted):
    names = []
    if not extracted:
        return names
    blob = extracted if isinstance(extracted, (list, tuple)) else [extracted]
    for item in blob:
        text = str(item)
        for part in re.split(r"[\s,;]+", text):
            if "=" in part:
                names.append(part.split("=", 1)[0].strip())
            elif part.strip():
                names.append(part.strip())
    return names


def _has_session_cookie(extracted):
    return any(_SESSION_COOKIE.search(n or "") for n in _cookie_names(extracted))


def _pick(a, b):
    """Return the higher of two (sev, reason) pairs."""
    if not a:
        return b
    if not b:
        return a
    if SEV_RANK.get(b[0], 0) > SEV_RANK.get(a[0], 0):
        return b
    return a


def classify(finding: dict) -> dict:
    src = (finding.get("severity") or finding.get("source_severity") or "info").strip().lower()
    if src not in SEV_RANK:
        src = "info"
    tid = (finding.get("template_id") or "").strip().lower()
    matcher = (finding.get("matcher") or "").strip().lower()
    tags = [str(t).strip().lower() for t in (finding.get("tags") or [])]
    cwes = _norm_cwe(finding.get("cwe"))
    extracted = finding.get("extracted") or []
    chosen = (src, f"Nuclei template severity ({src}).")

    hit = _TEMPLATE.get((tid, matcher)) or _TEMPLATE.get((tid, None))
    if hit:
        if SEV_RANK[src] > SEV_RANK[hit[0]]:
            chosen = (src, f"Nuclei rated {src} (kept; table would be {hit[0]}).")
        else:
            chosen = hit

    for cwe in cwes:
        rule = _CWE.get(cwe)
        if rule:
            if SEV_RANK[rule[0]] > SEV_RANK[chosen[0]]:
                chosen = rule

    tagset = set(tags)
    if tagset & _TAG_CRITICAL:
        chosen = _pick(chosen, ("critical", "Nuclei tags indicate remote code execution / unauth RCE."))
    elif tagset & _TAG_HIGH:
        chosen = _pick(chosen, ("high", "Nuclei tags indicate a high-impact class (XSS/SQLi/SSRF/LFI/takeover)."))

    try:
        cvss = finding.get("cvss")
        if cvss is not None:
            score = float(cvss)
            if score >= 9.0:
                chosen = _pick(chosen, ("critical", f"CVSS {score} ≥ 9.0"))
            elif score >= 7.0:
                chosen = _pick(chosen, ("high", f"CVSS {score} ≥ 7.0"))
            elif score >= 4.0:
                chosen = _pick(chosen, ("medium", f"CVSS {score} ≥ 4.0"))
            elif score > 0:
                chosen = _pick(chosen, ("low", f"CVSS {score} > 0"))
    except (TypeError, ValueError):
        pass

    if tid == "tls-version":
        blob = " ".join(str(x) for x in (extracted if isinstance(extracted, (list, tuple)) else [extracted]))
        if _WEAK_TLS.search(blob):
            chosen = _pick(chosen, ("medium", "TLS 1.0/1.1 is deprecated (PCI / OWASP)."))

    if tid in {"cookies-without-httponly", "cookies-without-secure"} and _has_session_cookie(extracted):
        if tid == "cookies-without-secure":
            chosen = _pick(chosen, ("medium", "Session-like cookie without Secure (CWE-614)."))
        else:
            chosen = _pick(chosen, ("medium", "Session-like cookie without HttpOnly (CWE-1004)."))

    return {
        "severity": chosen[0],
        "severity_reason": chosen[1],
        "source_severity": src,
    }
