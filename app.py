"""
Defacement Monitor — Flask Dashboard
Run:  python app.py
Open: http://localhost:5000
"""

from flask import Flask, render_template, jsonify, request, send_from_directory
from pathlib import Path
import os, subprocess, sys, json, threading, re, time, hashlib
from datetime import datetime, timezone
from urllib.parse import urlparse

app = Flask(__name__)

BASE_DIR         = Path(__file__).parent
SCRIPT           = BASE_DIR / "defacement_monitor.py"
DATA_DIR         = BASE_DIR / "defacement_data"
URLS_FILE        = DATA_DIR / "monitored_urls.json"
SETT_FILE        = DATA_DIR / "settings.json"
SCREENSHOTS_DIR  = DATA_DIR / "screenshots"
SCREENSHOTS_FILE = DATA_DIR / "screenshots.json"

def _url_key(url: str) -> str:
    return hashlib.md5(url.encode()).hexdigest()[:12]

_ANSI = re.compile(r'\x1b\[[0-9;]*[mGKHFJK]')

# ── Settings ──────────────────────────────────────────────────────────────────
def load_settings():
    if not SETT_FILE.exists():
        return {'interval': 300}
    try:
        return json.loads(SETT_FILE.read_text('utf-8'))
    except Exception:
        return {'interval': 300}

def save_settings(s):
    DATA_DIR.mkdir(exist_ok=True)
    SETT_FILE.write_text(json.dumps(s, indent=2), encoding='utf-8')

# ── Site data ─────────────────────────────────────────────────────────────────
def load_sites():
    if not URLS_FILE.exists():
        return {}
    try:
        return json.loads(URLS_FILE.read_text('utf-8'))
    except Exception:
        return {}

# ── Screenshot index (separate file — never written by the CLI subprocess) ────
def load_screenshots() -> dict:
    if not SCREENSHOTS_FILE.exists():
        return {}
    try:
        return json.loads(SCREENSHOTS_FILE.read_text('utf-8'))
    except Exception:
        return {}

def save_screenshots(data: dict):
    DATA_DIR.mkdir(exist_ok=True)
    SCREENSHOTS_FILE.write_text(json.dumps(data, indent=2, default=str), encoding='utf-8')

# ── CLI helper ────────────────────────────────────────────────────────────────
def cli(*args, timeout=60):
    # Force UTF-8 I/O in the subprocess — critical on Windows where default is cp1252
    env = os.environ.copy()
    env['PYTHONIOENCODING'] = 'utf-8'
    env['PYTHONUTF8']       = '1'
    try:
        r = subprocess.run(
            [sys.executable, str(SCRIPT)] + list(args),
            capture_output=True, text=True, encoding='utf-8', errors='replace',
            timeout=timeout, env=env
        )
        return r.returncode == 0, (r.stdout + r.stderr)
    except subprocess.TimeoutExpired:
        return False, 'Timed out'

# ── Background monitor ────────────────────────────────────────────────────────
_wake  = threading.Event()
_state = {'scanning': None, 'next_scan_at': None}

def _monitor_loop():
    while True:
        sites    = load_sites()
        interval = load_settings().get('interval', 300)

        for site in sites.values():
            url = site['url']
            _state['scanning'] = url
            try:
                if not site.get('baseline'):
                    cli('baseline', url, timeout=90)
                else:
                    cli('check', url, '--diff', timeout=60)
            except Exception:
                pass

        _state['scanning']     = None
        _state['next_scan_at'] = time.time() + interval
        _wake.wait(timeout=interval)
        _wake.clear()

threading.Thread(target=_monitor_loop, daemon=True).start()

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/sites')
def sites():
    data  = load_sites()
    shots = load_screenshots()
    for key, s in data.items():
        s['screenshots'] = shots.get(key, [])
    return jsonify(data)

@app.route('/api/status')
def status():
    nxt = _state.get('next_scan_at')
    return jsonify(
        scanning     = _state.get('scanning'),
        next_scan_in = max(0, int(nxt - time.time())) if nxt else None,
        interval     = load_settings().get('interval', 300)
    )

@app.route('/api/add', methods=['POST'])
def add():
    d     = request.json or {}
    url   = (d.get('url') or '').strip()
    label = (d.get('label') or '').strip()
    if not url:
        return jsonify(ok=False, error='URL is required'), 400
    # Normalise — add https:// if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    args = ['add', url] + (['--label', label] if label else [])
    ok, out = cli(*args)
    if ok:
        _wake.set()   # wake monitor thread → baselines immediately
        key = _url_key(url)
        threading.Thread(target=_take_screenshot_bg, args=(url, key), daemon=True).start()
    err = None if ok else (out.strip() or "CLI error")
    return jsonify(ok=ok, output=out, url=url, error=err)

@app.route('/api/remove', methods=['POST'])
def remove():
    d   = request.json or {}
    url = (d.get('url') or '').strip()
    if not url:
        return jsonify(ok=False, error='URL required'), 400
    key   = _url_key(url)
    shots = load_screenshots()
    if key in shots:
        del shots[key]
        save_screenshots(shots)
    ok, _ = cli('remove', url)
    return jsonify(ok=ok)

@app.route('/api/clear-alerts', methods=['POST'])
def clear_alerts():
    d   = request.json or {}
    url = (d.get('url') or '').strip()
    if not url:
        return jsonify(ok=False, error='URL required'), 400
    ok, _ = cli('clear-alerts', url)
    return jsonify(ok=ok)

@app.route('/api/alert-action', methods=['POST'])
def alert_action():
    d      = request.json or {}
    url    = (d.get('url') or '').strip()
    ts     = d.get('timestamp', '')
    action = d.get('action', '')
    if not url or not ts or action not in ('mitigate', 'remove'):
        return jsonify(ok=False, error='Bad params'), 400
    sites = load_sites()
    key   = next((k for k, s in sites.items() if s['url'] == url), None)
    if not key:
        return jsonify(ok=False, error='URL not found'), 404
    alerts = sites[key].get('alerts', [])
    if action == 'remove':
        sites[key]['alerts'] = [a for a in alerts if a.get('timestamp') != ts]
    else:
        for a in alerts:
            if a.get('timestamp') == ts:
                a['mitigated'] = True
    # Recompute status — if no active (non-mitigated) high-severity alerts, reset to OK
    active = [a for a in sites[key]['alerts']
              if not a.get('mitigated') and a.get('severity') in ('CRITICAL', 'HIGH', 'MEDIUM')]
    if not active:
        sites[key]['status'] = 'OK' if sites[key].get('baseline') else 'PENDING_BASELINE'
    DATA_DIR.mkdir(exist_ok=True)
    URLS_FILE.write_text(json.dumps(sites, indent=2, default=str), encoding='utf-8')
    return jsonify(ok=True)

@app.route('/api/force-check', methods=['POST'])
def force_check():
    """Immediately wake the monitor and re-check everything."""
    _wake.set()
    return jsonify(ok=True)

@app.route('/api/settings', methods=['GET'])
def get_settings():
    return jsonify(load_settings())

@app.route('/api/settings', methods=['POST'])
def set_settings():
    d = request.json or {}
    s = load_settings()
    if 'interval' in d:
        s['interval'] = max(30, int(d['interval']))
    if 'email_enabled' in d:
        s['email_enabled'] = bool(d['email_enabled'])
    if 'alert_email' in d:
        s['alert_email'] = (d['alert_email'] or '').strip()
    if 'smtp_pass' in d:
        s['smtp_pass'] = d['smtp_pass'] or ''
    save_settings(s)
    _wake.set()
    return jsonify(ok=True, settings=s)


@app.route('/api/test-email', methods=['POST'])
def test_email():
    sett = load_settings()
    if not sett.get('email_enabled'):
        return jsonify(ok=False, error='Enable email alerts first'), 400
    if not sett.get('alert_email'):
        return jsonify(ok=False, error='Enter an email address first'), 400
    if not sett.get('smtp_pass'):
        return jsonify(ok=False, error='Enter your App Password first'), 400
    try:
        from defacement_monitor import _send_alert_email
        test_findings = [{
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'type':      'TEST_NOTIFICATION',
            'severity':  'INFO',
            'detail':    'This is a test alert from Defacement Monitor. Email is working correctly.',
        }]
        _send_alert_email('https://example.com', 'Test Site', test_findings, sett)
        return jsonify(ok=True, message=f"Test email sent to {sett['alert_email']}")
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 500

def _take_screenshot_bg(url: str, key: str):
    """Run playwright screenshot in background thread.
    Writes to screenshots.json — never touches URLS_FILE, so no race with CLI subprocess."""
    try:
        from playwright.sync_api import sync_playwright
        SCREENSHOTS_DIR.mkdir(exist_ok=True)
        safe   = re.sub(r'[^\w\-]', '_', urlparse(url).netloc)
        ts_str = datetime.now().strftime('%Y%m%d_%H%M%S')
        fname  = f"{safe}_{ts_str}.png"
        fpath  = SCREENSHOTS_DIR / fname
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page    = browser.new_page(viewport={'width': 1280, 'height': 800})
            page.goto(url, timeout=30000, wait_until='domcontentloaded')
            page.wait_for_timeout(1500)
            page.screenshot(path=str(fpath))
            browser.close()
        ts_iso = datetime.now(timezone.utc).isoformat()
        shots  = load_screenshots()
        shots.setdefault(key, []).append({'filename': fname, 'timestamp': ts_iso})
        save_screenshots(shots)
    except Exception:
        pass   # playwright not installed or site unreachable — silently skip


@app.route('/api/screenshot', methods=['POST'])
def screenshot():
    d   = request.json or {}
    url = (d.get('url') or '').strip()
    if not url:
        return jsonify(ok=False, error='URL required'), 400
    key   = _url_key(url)
    sites = load_sites()
    if key not in sites:
        return jsonify(ok=False, error='URL not monitored'), 404
    threading.Thread(target=_take_screenshot_bg, args=(url, key), daemon=True).start()
    return jsonify(ok=True, message='Screenshot started in background')


@app.route('/screenshots/<path:filename>')
def serve_screenshot(filename):
    return send_from_directory(str(SCREENSHOTS_DIR), filename)


if __name__ == '__main__':
    print('\n  Defacement Monitor')
    print('  http://localhost:5000\n')
    app.run(port=5000, use_reloader=False)
