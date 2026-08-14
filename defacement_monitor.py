#!/usr/bin/env python3
"""
defacement_monitor.py — Website Defacement Monitor v1.0
=========================================================
A lightweight CLI security tool to monitor websites for unauthorized
changes, defacement indicators, and content integrity violations.

Usage:
  python defacement_monitor.py add <url> [url2 ...] [--label "My Site"]
  python defacement_monitor.py baseline --all
  python defacement_monitor.py check --all [--diff]
  python defacement_monitor.py monitor [--interval 300]
  python defacement_monitor.py list
  python defacement_monitor.py report
  python defacement_monitor.py clear-alerts <url>

Author: Generated for VAPT use
"""

import os
import sys
import json
import hashlib
import difflib
import argparse
import ssl
import socket
import time
import re
import signal
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timezone
from urllib.parse import urlparse

# ─── dependency check ────────────────────────────────────────────────────────
try:
    import requests
    from bs4 import BeautifulSoup
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("\n[!] Missing dependencies. Install with:")
    print("    pip install requests beautifulsoup4 --break-system-packages\n")
    sys.exit(1)

# =============================================================================
# CONSTANTS
# =============================================================================
VERSION         = "1.0.0"
_SCRIPT_DIR     = os.path.dirname(os.path.abspath(__file__))
DATA_DIR        = os.path.join(_SCRIPT_DIR, "defacement_data")
URLS_FILE       = os.path.join(DATA_DIR, "monitored_urls.json")
SETT_FILE       = os.path.join(DATA_DIR, "settings.json")
LOG_FILE        = os.path.join(DATA_DIR, "monitor.log")
SCREENSHOTS_DIR = os.path.join(DATA_DIR, "screenshots")

# Only report CONTENT_CHANGED if at least this % of text changed.
# Suppresses visitor-counter / timestamp noise (typically < 1% change).
CONTENT_CHANGE_THRESHOLD = 3.0

# Domains where "owned by" / "cracked by" are expected legitimate language
TRUSTED_DOMAINS = [".gov.in", ".nic.in", ".gov", ".mil", ".edu.in", ".ac.in", ".org.in"]

# Patterns that are highly ambiguous on government / institutional sites
AMBIGUOUS_PATTERNS = {r"owned\s+by\b", r"cracked\s+by\b"}

# Surrounding-context phrases that indicate legitimate ownership language
LEGITIMATE_CONTEXT = [
    r"ministr",
    r"government",
    r"govt",
    r"department",
    r"official\s+(website|portal|web\s*site|site)",
    r"copyright",
    r"©",
    r"gov\.in",
    r"nic\.in",
    r"national\s+(informatics|defence|defense|security|portal)",
    r"public\s+(sector|service)",
    r"defence|defense",
    r"content\s+(on\s+this|of\s+this)\s+(website|site|portal)",
    r"all\s+rights\s+reserved",
    r"union\s+(of\s+)?india",
    r"republic\s+of\s+india",
    r"bharat",
    r"army|navy|air\s*force|military",
    r"nda\.nic\.in|ndma|mha|mod\.gov",
]

# Defacement signature patterns (regex, case-insensitive)
DEFACEMENT_PATTERNS = [
    r"hacked\s+by\b",
    r"owned\s+by\b",
    r"defaced\s+by\b",
    r"pwned\s+by\b",
    r"hack3d\s+by\b",
    r"0wned\s+by\b",
    r"cracked\s+by\b",
    r"\br00ted\b",
    r"\bpwn3d\b",
    r"we\s+are\s+anonymous",
    r"anonymous\s+(hacked|owned|defaced|was here)",
    r"cyber\s+(army|attack\s+team|war\s+team)",
    r"\bdeface\b",
    r"greetz?\s+to\b",
    r"shout\s*out\s+to\b",
    r"you\s+have\s+been\s+(hacked|owned|pwned|compromised|defaced)",
    r"this\s+site\s+has\s+been\s+(hacked|defaced|compromised|breached)",
    r"security\s+(fail|pwned|breached)\b",
    r"\bh4ck3d\b",
    r"\bl0l\s+owned\b",
]

# Headers to mimic a real browser (avoids trivial bot blocks)
FETCH_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate",
    "Connection": "keep-alive",
}

# ANSI colours
C = {
    "R":  "\033[91m",   # red
    "G":  "\033[92m",   # green
    "Y":  "\033[93m",   # yellow
    "B":  "\033[94m",   # blue
    "M":  "\033[95m",   # magenta
    "C":  "\033[96m",   # cyan
    "W":  "\033[97m",   # white
    "BD": "\033[1m",    # bold
    "DM": "\033[2m",    # dim
    "X":  "\033[0m",    # reset
}

def clr(text, *codes):
    prefix = "".join(C.get(c, "") for c in codes)
    return f"{prefix}{text}{C['X']}"


# =============================================================================
# DATA LAYER
# =============================================================================

def ensure_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)
    if not os.path.exists(URLS_FILE):
        _save_urls({})


def _load_urls() -> dict:
    ensure_data_dir()
    try:
        with open(URLS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return {}


def _save_urls(data: dict):
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(URLS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


def _url_key(url: str) -> str:
    """Stable 12-char key for a URL."""
    return hashlib.md5(url.encode()).hexdigest()[:12]


def _log(message: str):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {message}\n"
    ensure_data_dir()
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_settings() -> dict:
    try:
        with open(SETT_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return {"interval": 300}




# =============================================================================
# EMAIL ALERTS
# =============================================================================

# Auto-detected SMTP settings per email domain (host, port)
_SMTP_PRESETS = {
    "gmail.com":      ("smtp.gmail.com",        587),
    "googlemail.com": ("smtp.gmail.com",        587),
    "yahoo.com":      ("smtp.mail.yahoo.com",   587),
    "yahoo.in":       ("smtp.mail.yahoo.com",   587),
    "yahoo.co.in":    ("smtp.mail.yahoo.com",   587),
    "outlook.com":    ("smtp-mail.outlook.com", 587),
    "hotmail.com":    ("smtp-mail.outlook.com", 587),
    "live.com":       ("smtp-mail.outlook.com", 587),
    "icloud.com":     ("smtp.mail.me.com",      587),
    "protonmail.com": ("smtp.protonmail.com",   587),
    "zoho.com":       ("smtp.zoho.com",         587),
}


def _smtp_preset(email: str):
    """Return (host, port) for a given email domain, or a sensible default."""
    domain = email.split("@")[-1].lower() if "@" in email else ""
    return _SMTP_PRESETS.get(domain, (f"smtp.{domain}", 587))


_SEV_COLORS = {
    "CRITICAL": ("#ef4444", "#fef2f2", "🔴"),
    "HIGH":     ("#f97316", "#fff7ed", "🟠"),
    "MEDIUM":   ("#d29922", "#fffbeb", "🟡"),
    "INFO":     ("#58a6ff", "#eff6ff", "🔵"),
}


def _build_alert_email_html(url: str, label: str, findings: list) -> str:
    max_sev = "INFO"
    for priority in ("CRITICAL", "HIGH", "MEDIUM", "INFO"):
        if any(f.get("severity") == priority for f in findings):
            max_sev = priority
            break

    banner_map = {
        "CRITICAL": ("#b91c1c", "⚠ CRITICAL DEFACEMENT ALERT"),
        "HIGH":     ("#c2410c", "⚠ HIGH SEVERITY ALERT"),
        "MEDIUM":   ("#92400e", "⚡ WARNING ALERT"),
        "INFO":     ("#1e3a5f", "ℹ Information"),
    }
    banner_color, banner_title = banner_map.get(max_sev, banner_map["INFO"])

    rows_html = ""
    for f in findings:
        sev  = f.get("severity", "INFO")
        col, bg, _ = _SEV_COLORS.get(sev, _SEV_COLORS["INFO"])
        ftype  = f.get("type", "—")
        detail = f.get("detail", "")
        ts     = (f.get("timestamp") or "")[:19].replace("T", " ")
        rows_html += f"""
        <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
               style="margin-bottom:10px;background-color:#21262d;border:1px solid #30363d;border-radius:7px;overflow:hidden">
          <tr>
            <td style="padding:12px 14px">
              <span style="display:inline-block;padding:2px 8px;border-radius:4px;
                           font-size:10px;font-weight:700;letter-spacing:0.4px;
                           background-color:{col};color:#ffffff">{sev}</span>
              <span style="display:inline-block;margin-left:8px;font-size:13px;
                           font-weight:600;color:#c9d1d9">{ftype}</span>
              <p style="margin:8px 0 0;font-size:11px;color:#8b949e;
                        font-family:Consolas,'Courier New',monospace;
                        word-break:break-word;line-height:1.6">{detail}</p>
              <p style="margin:6px 0 0;font-size:10px;color:#6e7681">{ts} UTC</p>
            </td>
          </tr>
        </table>"""

    gen_ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Defacement Alert — {label}</title></head>
<body style="margin:0;padding:0;background-color:#0d1117;
             font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;
             -webkit-text-size-adjust:100%">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0"
       style="background-color:#0d1117;padding:24px 16px">
  <tr><td align="center">
    <table role="presentation" width="580" cellpadding="0" cellspacing="0" border="0"
           style="max-width:580px;width:100%;background-color:#161b22;
                  border:1px solid #30363d;border-radius:10px;overflow:hidden">

      <!-- Header -->
      <tr>
        <td style="padding:20px 24px 16px;border-bottom:1px solid #30363d">
          <p style="margin:0;font-size:14px;font-weight:700;color:#c9d1d9;letter-spacing:0.5px">
            🛡 DEFACEMENT MONITOR
          </p>
          <p style="margin:4px 0 0;font-size:11px;color:#8b949e">Security Alert Notification</p>
        </td>
      </tr>

      <!-- Alert banner -->
      <tr>
        <td style="background-color:{banner_color};padding:16px 24px">
          <p style="margin:0;font-size:15px;font-weight:700;color:#ffffff">{banner_title}</p>
          <p style="margin:6px 0 0;font-size:11px;color:rgba(255,255,255,0.85);
                    font-family:Consolas,'Courier New',monospace;word-break:break-all">
            {url}
          </p>
        </td>
      </tr>

      <!-- Site info -->
      <tr>
        <td style="padding:16px 24px 0">
          <table role="presentation" cellpadding="0" cellspacing="0" border="0"
                 style="background-color:#21262d;border:1px solid #30363d;
                        border-radius:7px;width:100%;overflow:hidden">
            <tr>
              <td style="padding:12px 14px">
                <p style="margin:0;font-size:11px;color:#8b949e;
                          text-transform:uppercase;letter-spacing:0.7px;font-weight:600">
                  Site Label
                </p>
                <p style="margin:4px 0 0;font-size:13px;color:#c9d1d9;font-weight:600">
                  {label or url}
                </p>
              </td>
            </tr>
          </table>
        </td>
      </tr>

      <!-- Findings -->
      <tr>
        <td style="padding:16px 24px 0">
          <p style="margin:0 0 10px;font-size:11px;font-weight:600;color:#8b949e;
                    letter-spacing:0.8px;text-transform:uppercase">
            Detected Findings ({len(findings)})
          </p>
          {rows_html}
        </td>
      </tr>

      <!-- CTA -->
      <tr>
        <td style="padding:16px 24px 20px">
          <a href="{url}"
             style="display:inline-block;padding:10px 22px;background-color:#238636;
                    color:#ffffff;font-size:12px;font-weight:600;text-decoration:none;
                    border-radius:6px;border:1px solid rgba(255,255,255,0.15)">
            Inspect Site →
          </a>
          <p style="margin:12px 0 0;font-size:11px;color:#8b949e;line-height:1.6">
            Review this alert in your Defacement Monitor dashboard and take action immediately
            if this is a confirmed defacement.
          </p>
        </td>
      </tr>

      <!-- Footer -->
      <tr>
        <td style="padding:14px 24px;border-top:1px solid #30363d;background-color:#0d1117">
          <p style="margin:0;font-size:10px;color:#8b949e;line-height:1.6">
            Defacement Monitor — Automated Security Alert<br>
            Generated: {gen_ts} UTC<br>
            Do not reply to this email.
          </p>
        </td>
      </tr>

    </table>
  </td></tr>
</table>
</body>
</html>"""


def _build_alert_email_text(url: str, label: str, findings: list) -> str:
    lines = [
        "DEFACEMENT MONITOR — SECURITY ALERT",
        "=" * 50,
        f"Site : {label or url}",
        f"URL  : {url}",
        f"Time : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC",
        "",
        f"FINDINGS ({len(findings)} detected):",
        "-" * 50,
    ]
    for f in findings:
        ts = (f.get("timestamp") or "")[:19].replace("T", " ")
        lines += [
            f"[{f.get('severity','?')}] {f.get('type','?')}",
            f"  Detail : {f.get('detail','')}",
            f"  Time   : {ts} UTC",
            "",
        ]
    lines += [
        "-" * 50,
        "This is an automated alert from Defacement Monitor.",
        "Review and take action immediately if this is a confirmed defacement.",
    ]
    return "\n".join(lines)


def _send_alert_email(url: str, label: str, findings: list, settings: dict) -> bool:
    """
    Send an HTML alert email via SMTP.
    alert_email = recipient (and sender, unless smtp_user overrides it).
    smtp_pass   = App Password for the sender account.
    smtp_host/smtp_port are auto-detected from the email domain if not set.
    Returns True on success; raises on configuration/connection errors.
    """
    recipient = (settings.get("alert_email") or "").strip()
    smtp_pass = settings.get("smtp_pass", "")
    smtp_user = (settings.get("smtp_user") or recipient).strip()
    smtp_host = (settings.get("smtp_host") or "").strip()
    smtp_port = int(settings.get("smtp_port") or 0)

    if not recipient:
        raise ValueError("No email address set — add one in Settings → Email Alerts")
    if not smtp_pass:
        raise ValueError("No App Password set — add one in Settings → Email Alerts")

    # Auto-detect SMTP host/port from the sender email domain
    if not smtp_host or not smtp_port:
        auto_host, auto_port = _smtp_preset(smtp_user)
        smtp_host = smtp_host or auto_host
        smtp_port = smtp_port or auto_port

    max_sev = "INFO"
    for p in ("CRITICAL", "HIGH", "MEDIUM", "INFO"):
        if any(f.get("severity") == p for f in findings):
            max_sev = p
            break

    subject_prefix = {"CRITICAL": "[CRITICAL ALERT]", "HIGH": "[HIGH ALERT]",
                      "MEDIUM": "[WARNING]", "INFO": "[INFO]"}.get(max_sev, "[ALERT]")
    subject = f"{subject_prefix} Defacement Monitor — {label or url}"

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = f"Defacement Monitor <{smtp_user}>"
    msg["To"]      = recipient

    msg.attach(MIMEText(_build_alert_email_text(url, label, findings), "plain", "utf-8"))
    msg.attach(MIMEText(_build_alert_email_html(url, label, findings), "html",  "utf-8"))

    if smtp_port == 465:
        with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=15) as srv:
            if smtp_pass:
                srv.login(smtp_user, smtp_pass)
            srv.sendmail(smtp_user, [recipient], msg.as_bytes())
    else:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as srv:
            srv.ehlo()
            srv.starttls()
            srv.ehlo()
            if smtp_pass:
                srv.login(smtp_user, smtp_pass)
            srv.sendmail(smtp_user, [recipient], msg.as_bytes())

    return True


# =============================================================================
# NETWORK / PAGE FETCHING
# =============================================================================

def fetch_page(url: str, timeout: int = 15) -> dict:
    """Fetch a page and return status, HTML, timing, and any error."""
    result = {
        "url":             url,
        "timestamp":       _now_iso(),
        "status_code":     None,
        "html":            None,
        "error":           None,
        "response_time_ms": None,
        "final_url":       url,
        "server_header":   None,
        "content_length":  0,
    }
    try:
        t0 = time.monotonic()
        try:
            resp = requests.get(
                url, headers=FETCH_HEADERS, timeout=timeout,
                allow_redirects=True, verify=True,
            )
        except requests.exceptions.SSLError:
            resp = requests.get(
                url, headers=FETCH_HEADERS, timeout=timeout,
                allow_redirects=True, verify=False,
            )
        elapsed_ms = round((time.monotonic() - t0) * 1000, 1)
        result.update({
            "status_code":     resp.status_code,
            "html":            resp.text,
            "response_time_ms": elapsed_ms,
            "final_url":       resp.url,
            "server_header":   resp.headers.get("Server"),
            "content_length":  len(resp.content),
        })
    except requests.exceptions.ConnectionError as e:
        result["error"] = f"CONNECTION_ERROR: {e}"
    except requests.exceptions.Timeout:
        result["error"] = "TIMEOUT"
    except Exception as e:
        result["error"] = str(e)
    return result


def get_ssl_cert_info(hostname: str, port: int = 443) -> dict:
    """Return SSL certificate fingerprint + basic fields."""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as raw:
            with ctx.wrap_socket(raw, server_hostname=hostname) as ssock:
                cert     = ssock.getpeercert()
                der      = ssock.getpeercert(binary_form=True)
                fp       = hashlib.sha256(der).hexdigest()
                subject  = dict(x[0] for x in cert.get("subject", []))
                issuer   = dict(x[0] for x in cert.get("issuer", []))
                return {
                    "fingerprint_sha256": fp,
                    "common_name": subject.get("commonName", ""),
                    "issuer_org":  issuer.get("organizationName", ""),
                    "not_after":   cert.get("notAfter", ""),
                }
    except Exception as e:
        return {"error": str(e)}


# =============================================================================
# PAGE ANALYSIS
# =============================================================================

def extract_page_info(html: str) -> dict:
    """Parse HTML → extract meaningful signals for comparison."""
    soup = BeautifulSoup(html, "html.parser")

    # --- title ---
    title = ""
    t = soup.find("title")
    if t:
        title = t.get_text(strip=True)

    # --- visible text (strip scripts/style/head) ---
    for tag in soup(["script", "style", "meta", "link", "head", "noscript"]):
        tag.decompose()
    visible = re.sub(r"\s+", " ", soup.get_text(separator=" ")).strip()

    # --- external scripts ---
    scripts = []
    for s in BeautifulSoup(html, "html.parser").find_all("script", src=True):
        src = s.get("src", "")
        if src and (src.startswith("http") or src.startswith("//")):
            scripts.append(src)

    # --- iframes ---
    iframes = []
    for fr in BeautifulSoup(html, "html.parser").find_all("iframe", src=True):
        src = fr.get("src", "")
        if src:
            iframes.append(src)

    # --- hashes ---
    html_hash = hashlib.sha256(html.encode("utf-8", errors="replace")).hexdigest()
    text_hash = hashlib.sha256(visible.encode("utf-8", errors="replace")).hexdigest()

    return {
        "title":              title,
        "html_hash":          html_hash,
        "text_hash":          text_hash,
        "visible_text":       visible[:8000],     # cap stored snapshot
        "visible_text_len":   len(visible),
        "html_len":           len(html),
        "word_count":         len(visible.split()),
        "external_scripts":   scripts,
        "iframes":            iframes,
    }


def detect_defacement_keywords(html: str, visible: str, url: str = "") -> list:
    """Return list of matched defacement patterns, suppressing false positives."""
    haystack = (html + " " + visible).lower()
    findings = []

    domain  = urlparse(url).netloc.lower() if url else ""
    trusted = any(domain.endswith(td) for td in TRUSTED_DOMAINS)

    for pattern in DEFACEMENT_PATTERNS:
        # Skip ambiguous ownership-language patterns on known gov/institutional domains
        if trusted and pattern in AMBIGUOUS_PATTERNS:
            continue

        raw = list(re.finditer(pattern, haystack, re.IGNORECASE))
        if not raw:
            continue

        confirmed = []
        for m in raw:
            # Extract ±200 chars of surrounding context
            ctx = haystack[max(0, m.start() - 200): m.end() + 200]
            if any(re.search(lp, ctx, re.IGNORECASE) for lp in LEGITIMATE_CONTEXT):
                continue   # legitimate attribution/ownership context — skip
            confirmed.append(m.group())

        if confirmed:
            findings.append({
                "type":     "DEFACEMENT_KEYWORD",
                "pattern":  pattern,
                "matches":  list(set(confirmed))[:5],
                "severity": "CRITICAL",
            })

    return findings


def detect_new_resources(baseline_scripts, cur_scripts, baseline_iframes, cur_iframes) -> list:
    """Flag any new external scripts or iframes since baseline."""
    findings = []
    for url in set(cur_scripts) - set(baseline_scripts):
        findings.append({"type": "NEW_EXTERNAL_SCRIPT", "url": url, "severity": "HIGH"})
    for url in set(cur_iframes) - set(baseline_iframes):
        findings.append({"type": "NEW_IFRAME", "url": url, "severity": "HIGH"})
    return findings


def detect_traffic_spike(baseline_text: str, current_text: str) -> list:
    """
    Compare large numbers in baseline vs current text.
    A 5× jump of 10 000+ units suggests a DoS or viral traffic event.
    """
    num_re = re.compile(r'\b(\d[\d,]+)\b')

    def parse(text):
        out = []
        for m in num_re.finditer(text):
            try:
                n = int(m.group().replace(",", ""))
                if n >= 1000:
                    out.append(n)
            except ValueError:
                pass
        return out[:20]

    for b, c in zip(parse(baseline_text), parse(current_text)):
        if b > 0 and c > b:
            ratio = c / b
            diff  = c - b
            if ratio >= 5 and diff >= 10000:
                return [_finding(
                    "TRAFFIC_SPIKE", "MEDIUM",
                    f"Counter spiked {ratio:.1f}× ({b:,} → {c:,}) — possible DoS or viral traffic event",
                )]
    return []


def similarity_ratio(a: str, b: str) -> float:
    return difflib.SequenceMatcher(None, a, b).ratio()


def make_diff(old: str, new: str, max_lines: int = 60) -> str:
    d = difflib.unified_diff(
        old.splitlines(keepends=True),
        new.splitlines(keepends=True),
        fromfile="baseline",
        tofile="current",
        n=3,
    )
    return "".join(list(d)[:max_lines])


# =============================================================================
# COMMANDS
# =============================================================================

def cmd_add(args):
    urls = _load_urls()
    for raw in args.urls:
        url = raw if raw.startswith(("http://", "https://")) else "https://" + raw
        key = _url_key(url)
        if key in urls:
            print(clr(f"  ~ Already monitoring: {url}", "Y"))
            continue
        label = args.label or urlparse(url).netloc
        urls[key] = {
            "url":         url,
            "label":       label,
            "added":       _now_iso(),
            "status":      "PENDING_BASELINE",
            "baseline":    None,
            "last_check":  None,
            "check_count": 0,
            "alerts":      [],
        }
        print(clr(f"  + Added:  {url}", "G"))
        _log(f"ADD {url}")
    _save_urls(urls)
    print()
    print(clr("  Next step → take a baseline:", "C"))
    print(clr("    python defacement_monitor.py baseline --all", "DM"))


def cmd_remove(args):
    urls = _load_urls()
    for raw in args.urls:
        url = raw if raw.startswith(("http://", "https://")) else "https://" + raw
        key = _url_key(url)
        if key in urls:
            del urls[key]
            print(clr(f"  - Removed: {url}", "R"))
            _log(f"REMOVE {url}")
        else:
            print(clr(f"  ! Not found: {url}", "Y"))
    _save_urls(urls)


def cmd_list(args):
    urls = _load_urls()
    if not urls:
        print(clr("  [i] No URLs monitored yet.  Use: add <url>", "Y"))
        return

    _header("MONITORED URLS", f"{len(urls)} total")
    SC = {"OK": "G", "ALERT": "R", "WARNING": "Y",
          "OFFLINE": "M", "PENDING_BASELINE": "C"}
    for d in urls.values():
        st    = d.get("status", "?")
        col   = SC.get(st, "W")
        lc    = d.get("last_check") or "—"
        if lc != "—":
            lc = lc[:19].replace("T", " ") + " UTC"
        na    = len(d.get("alerts", []))
        dot   = clr("●", col)
        print(f"\n  {dot}  {clr(d['url'], 'BD')}")
        print(f"       Label      {d.get('label', '—')}")
        print(f"       Status     {clr(st, col)}")
        print(f"       Last check {lc}")
        print(f"       Alerts     {clr(str(na), 'R' if na else 'G')}")
        print(f"       Checks run {d.get('check_count', 0)}")
    print()


def cmd_baseline(args):
    urls  = _load_urls()
    keys  = _resolve_targets(urls, args)
    if not keys:
        return

    for key in keys:
        d   = urls[key]
        url = d["url"]
        print(clr(f"\n  * Taking baseline: {url}", "C"))

        fetch = fetch_page(url)
        if fetch["error"]:
            print(clr(f"    ! Fetch failed: {fetch['error']}", "R"))
            d["status"] = "OFFLINE"
            continue

        info  = extract_page_info(fetch["html"])
        parsed = urlparse(url)
        ssl_info = None
        if parsed.scheme == "https":
            ssl_info = get_ssl_cert_info(parsed.hostname)

        d["baseline"] = {
            "timestamp":        fetch["timestamp"],
            "status_code":      fetch["status_code"],
            "final_url":        fetch["final_url"],
            "html_hash":        info["html_hash"],
            "text_hash":        info["text_hash"],
            "title":            info["title"],
            "visible_text":     info["visible_text"],
            "visible_text_len": info["visible_text_len"],
            "html_len":         info["html_len"],
            "word_count":       info["word_count"],
            "external_scripts": info["external_scripts"],
            "iframes":          info["iframes"],
            "response_time_ms": fetch["response_time_ms"],
            "ssl_info":         ssl_info,
        }
        d["status"]     = "OK"
        d["last_check"] = fetch["timestamp"]
        _log(f"BASELINE {url}  hash={info['html_hash'][:12]}")

        print(clr(f"    ✓ HTTP {fetch['status_code']}  {fetch['response_time_ms']}ms", "G"))
        print(clr(f"    ✓ Title:    {info['title'] or '(empty)'}", "G"))
        print(clr(f"    ✓ HTML hash {info['html_hash'][:16]}…", "G"))
        print(clr(f"    ✓ Words:    {info['word_count']}", "G"))
        print(clr(f"    ✓ Ext scripts: {len(info['external_scripts'])}", "G"))
        if ssl_info and "fingerprint_sha256" in ssl_info:
            print(clr(f"    ✓ SSL cert: {ssl_info['fingerprint_sha256'][:16]}…", "G"))

    _save_urls(urls)
    print(clr("\n  [+] Baseline complete.\n", "G"))


def cmd_check(args):
    urls  = _load_urls()
    keys  = _resolve_targets(urls, args)
    if not keys:
        return

    ok_count = alert_count = 0
    _header("CHECKING", f"{len(keys)} URL(s)")

    for key in keys:
        d           = urls[key]
        url         = d["url"]
        baseline    = d.get("baseline")
        prev_status = d.get("status", "OK")

        if not baseline:
            print(clr(f"\n  ! No baseline for {url} — run baseline first.", "Y"))
            continue

        print(clr(f"\n  › {url}", "BD"))
        fetch = fetch_page(url)
        d["check_count"] = d.get("check_count", 0) + 1
        d["last_check"]  = _now_iso()

        findings = []

        # ── OFFLINE ───────────────────────────────────────────────────────────
        if fetch["error"]:
            print(clr(f"    [OFFLINE] {fetch['error']}", "R"))
            d["status"] = "OFFLINE"
            offline_finding = {
                "timestamp": d["last_check"],
                "severity":  "HIGH",
                "type":      "OFFLINE",
                "detail":    fetch["error"],
            }
            findings.append(offline_finding)
            d["alerts"] += findings
            # Email: notify when site goes offline for the first time
            if prev_status != "OFFLINE":
                sett = _load_settings()
                if sett.get("email_enabled") and sett.get("alert_email"):
                    try:
                        _send_alert_email(url, d.get("label", ""), findings, sett)
                        print(clr(f"    ✉  Alert email sent → {sett['alert_email']}", "G"))
                        _log(f"EMAIL_SENT {url} (OFFLINE) → {sett['alert_email']}")
                    except Exception as ex:
                        print(clr(f"    ! Email error: {ex}", "Y"))
                        _log(f"EMAIL_ERROR {url}: {ex}")
            _save_urls(urls)
            alert_count += 1
            continue

        info = extract_page_info(fetch["html"])

        # ── HTTP STATUS ───────────────────────────────────────────────────────
        if fetch["status_code"] != baseline["status_code"]:
            findings.append(_finding(
                "HTTP_STATUS_CHANGE", "HIGH",
                f"{baseline['status_code']} → {fetch['status_code']}",
            ))

        # ── TITLE ─────────────────────────────────────────────────────────────
        if info["title"] != baseline["title"]:
            findings.append(_finding(
                "TITLE_CHANGE", "HIGH",
                f"'{baseline['title']}' → '{info['title']}'",
            ))

        # ── CONTENT CHANGE ────────────────────────────────────────────────────
        if info["html_hash"] != baseline["html_hash"]:
            sim     = similarity_ratio(baseline.get("visible_text", ""), info["visible_text"])
            chg_pct = round((1 - sim) * 100, 1)

            if chg_pct >= CONTENT_CHANGE_THRESHOLD:
                # Real content shift — report it
                sev = "INFO"
                if chg_pct >= 60: sev = "CRITICAL"
                elif chg_pct >= 20: sev = "HIGH"
                elif chg_pct >= 5:  sev = "MEDIUM"
                f = _finding(
                    "CONTENT_CHANGED", sev,
                    f"~{chg_pct}% of content changed (similarity {round(sim*100,1)}%)",
                )
                f["old_html_hash"] = baseline["html_hash"]
                f["new_html_hash"] = info["html_hash"]
                if getattr(args, "diff", False):
                    f["diff"] = make_diff(baseline.get("visible_text", ""), info["visible_text"])
                findings.append(f)

            # Always check for numeric spikes even when overall change is tiny
            for tf in detect_traffic_spike(baseline.get("visible_text", ""), info["visible_text"]):
                findings.append(tf)

        # ── DEFACEMENT KEYWORDS ───────────────────────────────────────────────
        for kw in detect_defacement_keywords(fetch["html"], info["visible_text"], url):
            findings.append(_finding(
                "DEFACEMENT_KEYWORD", "CRITICAL",
                f"Pattern: {kw['pattern']}  matched: {kw['matches']}",
            ))

        # ── NEW EXTERNAL RESOURCES ────────────────────────────────────────────
        for rf in detect_new_resources(
            baseline.get("external_scripts", []), info["external_scripts"],
            baseline.get("iframes", []),          info["iframes"],
        ):
            findings.append(_finding(rf["type"], rf["severity"], rf["url"]))

        # ── SSL CERT CHANGE ───────────────────────────────────────────────────
        parsed = urlparse(url)
        if parsed.scheme == "https" and baseline.get("ssl_info") and \
                "fingerprint_sha256" in baseline["ssl_info"]:
            cur_ssl = get_ssl_cert_info(parsed.hostname)
            if cur_ssl.get("fingerprint_sha256") != baseline["ssl_info"]["fingerprint_sha256"]:
                findings.append(_finding("SSL_CERT_CHANGED", "MEDIUM",
                                         "Certificate fingerprint has changed"))

        # ── STATUS ROLLUP ─────────────────────────────────────────────────────
        if any(f["severity"] == "CRITICAL" for f in findings):
            d["status"] = "ALERT"
        elif any(f["severity"] in ("HIGH", "MEDIUM") for f in findings):
            d["status"] = "WARNING"
        elif findings:
            d["status"] = "WARNING"
        else:
            d["status"] = "OK"

        if not findings:
            print(clr("    ✓  OK — no changes detected", "G"))
            ok_count += 1
        else:
            alert_count += 1
            d["alerts"] += findings
            SEV_COL = {"CRITICAL": "R", "HIGH": "R", "MEDIUM": "Y", "INFO": "C"}
            for f in findings:
                col = SEV_COL.get(f["severity"], "W")
                print(clr(f"    ⚑  [{f['severity']}] {f['type']}: {f['detail']}", col))
                if f.get("diff"):
                    print(clr("         ─── diff ───", "B"))
                    for line in f["diff"].splitlines()[:25]:
                        if line.startswith("+") and not line.startswith("+++"):
                            print(clr(f"         {line}", "G"))
                        elif line.startswith("-") and not line.startswith("---"):
                            print(clr(f"         {line}", "R"))
                        else:
                            print(clr(f"         {line}", "DM"))

            # Email: only alert when status escalates (avoids repeat emails on every cycle)
            new_status = d["status"]
            if new_status in ("ALERT", "WARNING") and prev_status not in ("ALERT", "WARNING"):
                sett = _load_settings()
                if sett.get("email_enabled") and sett.get("alert_email"):
                    try:
                        _send_alert_email(url, d.get("label", ""), findings, sett)
                        print(clr(f"    ✉  Alert email sent → {sett['alert_email']}", "G"))
                        _log(f"EMAIL_SENT {url} ({new_status}) → {sett['alert_email']}")
                    except Exception as ex:
                        print(clr(f"    ! Email error: {ex}", "Y"))
                        _log(f"EMAIL_ERROR {url}: {ex}")

    _save_urls(urls)
    _header("SUMMARY", f"{ok_count} OK  |  {alert_count} changed / alerted")


def cmd_monitor(args):
    interval = getattr(args, "interval", 300) or 300
    print(clr(f"\n  [*] Continuous monitoring started  (interval {interval}s)", "C"))
    print(clr("  [*] Press Ctrl+C to stop\n", "DM"))

    def _run():
        a = argparse.Namespace(urls=[], all=True, diff=False)
        cmd_check(a)

    def _sigint(_s, _f):
        print(clr("\n\n  [*] Monitoring stopped.", "Y"))
        sys.exit(0)

    signal.signal(signal.SIGINT, _sigint)
    while True:
        _run()
        print(clr(f"\n  … next check in {interval}s …\n", "DM"))
        time.sleep(interval)


def cmd_report(args):
    urls  = _load_urls()
    if not urls:
        print(clr("  [!] No URLs to report on.", "Y"))
        return

    ts          = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = os.path.join(DATA_DIR, f"report_{ts}.html")
    sc          = {"OK":"#22c55e","ALERT":"#ef4444","WARNING":"#f59e0b",
                   "OFFLINE":"#a855f7","PENDING_BASELINE":"#64748b"}

    rows = ""
    for d in urls.values():
        st    = d.get("status","?")
        col   = sc.get(st,"#94a3b8")
        alerts = d.get("alerts",[])
        alert_html = ""
        for a in alerts[-3:]:
            ac = "#ef4444" if a.get("severity") in ("CRITICAL","HIGH") else "#f59e0b"
            alert_html += (
                f'<div style="color:{ac};font-size:11px;margin:2px 0;">'
                f'[{a["severity"]}] {a["type"]}: {str(a.get("detail",""))[:80]}</div>'
            )
        lc = (d.get("last_check") or "—")[:19].replace("T"," ")
        rows += f"""
        <tr>
          <td><a href="{d['url']}" target="_blank">{d['url']}</a></td>
          <td>{d.get('label','—')}</td>
          <td><span style="color:{col};font-weight:600;">{st}</span></td>
          <td>{lc}</td>
          <td>{len(alerts)}</td>
          <td>{d.get('check_count',0)}</td>
          <td>{alert_html or '<span style="color:#22c55e;">None</span>'}</td>
        </tr>"""

    html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">
<title>Defacement Monitor — Report {ts}</title>
<style>
*{{box-sizing:border-box}}
body{{font-family:'Courier New',monospace;background:#0a0f1e;color:#e2e8f0;margin:0;padding:24px}}
h1{{color:#38bdf8;margin:0 0 4px;font-size:22px}}
.meta{{color:#475569;font-size:13px;margin-bottom:24px}}
table{{width:100%;border-collapse:collapse;font-size:13px}}
th{{background:#1e293b;color:#94a3b8;text-align:left;padding:10px 12px;border-bottom:1px solid #0f172a}}
td{{padding:10px 12px;border-bottom:1px solid #1e293b;vertical-align:top}}
tr:hover td{{background:#1e293b}}
a{{color:#38bdf8;text-decoration:none}}
a:hover{{text-decoration:underline}}
.badge{{display:inline-block;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:600}}
</style></head><body>
<h1>🔍 Defacement Monitor — Security Report</h1>
<div class="meta">Generated {datetime.now().strftime('%Y-%m-%d %H:%M')} UTC &nbsp;|&nbsp;
{len(urls)} URL(s) monitored</div>
<table>
<tr><th>URL</th><th>Label</th><th>Status</th><th>Last Check</th>
    <th>Alert Count</th><th>Checks Run</th><th>Recent Alerts</th></tr>
{rows}
</table></body></html>"""

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(clr(f"  [+] Report saved → {report_path}", "G"))


def cmd_clear_alerts(args):
    urls = _load_urls()
    for raw in args.urls:
        url = raw if raw.startswith(("http://", "https://")) else "https://" + raw
        key = _url_key(url)
        if key in urls:
            n = len(urls[key].get("alerts", []))
            urls[key]["alerts"] = []
            urls[key]["status"] = "OK"
            print(clr(f"  [+] Cleared {n} alert(s) for {url}", "G"))
            _log(f"CLEAR_ALERTS {url}")
        else:
            print(clr(f"  [!] Not found: {url}", "Y"))
    _save_urls(urls)


def cmd_export(args):
    """Dump the full state as JSON for external tooling / the dashboard."""
    urls = _load_urls()
    print(json.dumps(urls, indent=2, default=str))


# =============================================================================
# SCREENSHOT
# =============================================================================

def take_screenshot(url: str) -> dict:
    """Capture a full-page browser screenshot. Requires playwright + chromium."""
    result = {"filename": None, "error": None, "timestamp": _now_iso()}
    try:
        from playwright.sync_api import sync_playwright
        os.makedirs(SCREENSHOTS_DIR, exist_ok=True)
        safe  = re.sub(r"[^\w\-]", "_", urlparse(url).netloc)
        ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = f"{safe}_{ts}.png"
        fpath = os.path.join(SCREENSHOTS_DIR, fname)
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page    = browser.new_page(viewport={"width": 1280, "height": 800})
            page.goto(url, timeout=30000, wait_until="domcontentloaded")
            page.wait_for_timeout(1500)
            page.screenshot(path=fpath)
            browser.close()
        result["filename"] = fname
    except ImportError:
        result["error"] = (
            "playwright not installed — run: "
            "pip install playwright && playwright install chromium"
        )
    except Exception as e:
        result["error"] = str(e)
    return result


def cmd_screenshot(args):
    urls = _load_urls()
    for raw in args.urls:
        url = raw if raw.startswith(("http://", "https://")) else "https://" + raw
        key = _url_key(url)
        if key not in urls:
            print(clr(f"  [!] Not monitored: {url} — add it first.", "Y"))
            continue
        print(clr(f"\n  * Screenshot: {url}", "C"))
        r = take_screenshot(url)
        if r["error"]:
            print(clr(f"    ! {r['error']}", "R"))
        else:
            print(clr(f"    ✓ Saved: {r['filename']}", "G"))
            d = urls[key]
            d.setdefault("screenshots", []).append(
                {"filename": r["filename"], "timestamp": r["timestamp"]}
            )
            _save_urls(urls)


# =============================================================================
# HELPERS
# =============================================================================

def _finding(ftype: str, severity: str, detail: str) -> dict:
    return {"timestamp": _now_iso(), "type": ftype, "severity": severity, "detail": detail}


def _resolve_targets(urls: dict, args) -> list:
    if getattr(args, "all", False) or not getattr(args, "urls", []):
        return list(urls.keys())
    keys = []
    for raw in args.urls:
        url = raw if raw.startswith(("http://", "https://")) else "https://" + raw
        key = _url_key(url)
        if key not in urls:
            print(clr(f"  [!] Not monitored: {url} — add it first.", "Y"))
        else:
            keys.append(key)
    return keys


def _header(title: str, subtitle: str = ""):
    w = 64
    print(clr(f"\n  {'─'*w}", "B"))
    line = f"  {title}"
    if subtitle:
        line += f"  ·  {subtitle}"
    print(clr(line, "BD"))
    print(clr(f"  {'─'*w}", "B"))


# =============================================================================
# ENTRY POINT
# =============================================================================

def main():
    banner = f"""
  +------------------------------------------+
  |  Defacement Monitor  v{VERSION}               |
  |  Website Integrity Surveillance Tool     |
  +------------------------------------------+"""
    print(clr(banner, "C", "BD"))

    parser = argparse.ArgumentParser(
        prog="defacement_monitor",
        description="Monitor websites for defacement and integrity changes.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python defacement_monitor.py add https://agency.gov https://portal.gov
  python defacement_monitor.py baseline --all
  python defacement_monitor.py check --all --diff
  python defacement_monitor.py monitor --interval 300
  python defacement_monitor.py report
  python defacement_monitor.py list
        """,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # add
    p = sub.add_parser("add",     help="Add URL(s) to the watch list")
    p.add_argument("urls",  nargs="+")
    p.add_argument("--label", help="Human-friendly label (uses hostname if omitted)")

    # remove
    p = sub.add_parser("remove",  help="Stop monitoring a URL")
    p.add_argument("urls", nargs="+")

    # list
    sub.add_parser("list",        help="Print all monitored URLs and their status")

    # baseline
    p = sub.add_parser("baseline", help="Capture a fresh baseline snapshot")
    p.add_argument("urls",  nargs="*")
    p.add_argument("--all", action="store_true", help="Baseline every monitored URL")

    # check
    p = sub.add_parser("check",   help="Compare current state against baseline")
    p.add_argument("urls",  nargs="*")
    p.add_argument("--all", action="store_true")
    p.add_argument("--diff", action="store_true", help="Print unified diff on content change")

    # monitor
    p = sub.add_parser("monitor", help="Run checks continuously")
    p.add_argument("--interval", type=int, default=300, help="Seconds between checks (default 300)")

    # report
    sub.add_parser("report",      help="Generate an HTML report")

    # clear-alerts
    p = sub.add_parser("clear-alerts", help="Acknowledge / clear alerts for a URL")
    p.add_argument("urls", nargs="+")

    # export (machine-readable)
    sub.add_parser("export",      help="Dump full state as JSON (for dashboards / SIEM)")

    # screenshot
    p = sub.add_parser("screenshot", help="Take a browser screenshot of a monitored URL")
    p.add_argument("urls", nargs="+")

    args = parser.parse_args()
    dispatch = {
        "add":          cmd_add,
        "remove":       cmd_remove,
        "list":         cmd_list,
        "baseline":     cmd_baseline,
        "check":        cmd_check,
        "monitor":      cmd_monitor,
        "report":       cmd_report,
        "clear-alerts": cmd_clear_alerts,
        "export":       cmd_export,
        "screenshot":   cmd_screenshot,
    }
    dispatch[args.command](args)


if __name__ == "__main__":
    main()
