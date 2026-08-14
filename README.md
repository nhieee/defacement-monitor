# Defacement Monitor

A lightweight CLI tool to monitor websites for defacement, content integrity changes, injected scripts, SSL certificate changes, and keyword-based attack signatures.

Built for VAPT/blue team use. No external services required — runs entirely locally.

---

## Requirements

- Python 3.8+
- Network access to target URLs

---

## Quick Setup

```bash
# 1. Clone / extract this folder, then:
cd defacement-monitor

# 2. Create a virtual environment
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Verify installation
python defacement_monitor.py --help
```

---

## Usage

### Add URLs to watch
```bash
python defacement_monitor.py add https://example.gov.in --label "Main Portal"
python defacement_monitor.py add https://portal.gov.in --label "Citizen Portal"

# Add multiple at once
python defacement_monitor.py add https://site1.gov.in https://site2.gov.in
```

### Capture baselines
> Must be done before any checks. This is the "known good" snapshot.

```bash
python defacement_monitor.py baseline --all

# Or for a specific URL
python defacement_monitor.py baseline https://example.gov.in
```

### Run a check
```bash
# Check all sites
python defacement_monitor.py check --all

# Check with unified diff output
python defacement_monitor.py check --all --diff

# Check a single site
python defacement_monitor.py check https://example.gov.in --diff
```

### List monitored sites
```bash
python defacement_monitor.py list
```

### Continuous monitoring
```bash
# Poll every 5 minutes (default)
python defacement_monitor.py monitor

# Custom interval (seconds)
python defacement_monitor.py monitor --interval 120

# Ctrl+C to stop cleanly
```

### Generate HTML report
```bash
python defacement_monitor.py report
# Saves to defacement_data/report_<timestamp>.html
```

### Export state as JSON (for SIEM/dashboards)
```bash
python defacement_monitor.py export > state.json
```

### Acknowledge / clear alerts
```bash
python defacement_monitor.py clear-alerts https://example.gov.in
```

### Remove a site
```bash
python defacement_monitor.py remove https://example.gov.in
```

---

## What It Detects

| Check | Severity |
|---|---|
| Defacement keywords (`hacked by`, `owned`, `r00ted`, etc.) | CRITICAL |
| Page title changed | HIGH |
| New external scripts injected | HIGH |
| New iframes injected | HIGH |
| SSL certificate fingerprint changed | HIGH |
| Content similarity dropped significantly | HIGH / MEDIUM |
| HTML hash changed | MEDIUM |
| HTTP status code changed | MEDIUM |
| Site offline / unreachable | CRITICAL |

---

## File Structure

```
defacement-monitor/
├── defacement_monitor.py       # Main script
├── requirements.txt
├── README.md
├── .gitignore
├── systemd/
│   └── defacement-monitor.service   # systemd unit (Linux)
└── defacement_data/            # Auto-created on first run
    ├── monitored_urls.json     # All state / alerts
    └── monitor.log             # Per-check log
```

---

## Running as a Background Service (Linux)

See `systemd/defacement-monitor.service`. Edit the paths inside, then:

```bash
sudo cp systemd/defacement-monitor.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable defacement-monitor
sudo systemctl start defacement-monitor

# Check logs
sudo journalctl -u defacement-monitor -f
```

---

## Running via Cron (alternative)

```bash
crontab -e

# Add — checks every 10 minutes, logs to file
*/10 * * * * cd /path/to/defacement-monitor && venv/bin/python defacement_monitor.py check --all >> defacement_data/cron.log 2>&1
```

---

## Tips

- **Behind a proxy?** Set `HTTP_PROXY` / `HTTPS_PROXY` env vars before running — `requests` picks them up automatically.
- **Intranet targets?** Run the script from a machine with LAN access to those hosts.
- **Re-baseline after planned changes** to the site to avoid false positives.
- **State file** is `defacement_data/monitored_urls.json` — back it up or commit it (it's just JSON).

---

## License

Internal use. Not for distribution outside authorised engagements.
