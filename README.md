# ShieldScan — aaPanel Plugin for Malware Detection

Real-time malware detection plugin for aaPanel with 55+ signatures, YARA rules, entropy analysis, WordPress core verification, and auto-quarantine.

![aaPanel Plugin](https://img.shields.io/badge/aaPanel-Plugin-blue)
![Python](https://img.shields.io/badge/Python-3.7+-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

> **aaPanel security plugin** — Protect your websites from webshells, backdoors, and malware with automated scanning and real-time file monitoring.

---

## Overview

ShieldScan is a free aaPanel plugin that provides enterprise-level malware scanning for your server.

|                |                                                   |
| -------------- | ------------------------------------------------- |
| **Signatures** | 55+ regex patterns, YARA rules, hash matching     |
| **ML Engine**  | Shannon entropy + statistical classifier          |
| **Real-time**  | Inotify watcher with auto-quarantine              |
| **WordPress**  | Core checksums, plugin CVEs, DB scan, auto-update |
| **Integrity**  | Baseline diffing for tamper detection             |
| **Reporting**  | PDF export, scan history, dashboard               |

---

## Installation

### Via aaPanel (Recommended)

1. Download the plugin as a `.zip` file
2. Log in to your aaPanel dashboard
3. Go to **App Store** from the left sidebar
4. Click **Import** (top-right corner)
5. Upload the `.zip` file
6. Click **Install** — done

### Requirements

All optional — the scanner works standalone with regex signatures:

| Package     | Purpose              |
| ----------- | -------------------- |
| yara-python | YARA rule engine     |
| requests    | WP API, webhooks     |
| reportlab   | PDF reports          |
| pymysql     | WP database scan     |
| inotify     | Real-time monitoring |
| WP-CLI      | Plugin auto-update   |

---

## Detection

### Categories

| Category             | Count | Covers                                                            |
| -------------------- | ----- | ----------------------------------------------------------------- |
| Webshell             | 10    | eval injection, known shells (c99, r57, b374k, WSO, Alfa)         |
| Backdoor             | 5     | RFI/LFI, reverse shell, upload exploits                           |
| Obfuscation          | 8     | base64/hex/chr chains, gzinflate, pack()                          |
| Malware              | 6     | miners, mailers, phishing kits, skimmers, keyloggers              |
| WordPress            | 20+   | fake plugins, cron backdoors, REST exploits, WooCommerce skimmers |
| Evasion              | 4     | string concat, variable variables, reflection API                 |
| Privilege Escalation | 2     | symlink attacks, sensitive file reads                             |
| Exfiltration         | 2     | DNS exfil, WebSocket theft                                        |

### ML Classifier

Extracts 8 statistical features per file:

- Shannon entropy
- Chi-square distribution
- ASCII ratio
- Non-printable byte ratio
- Longest line length
- Compression ratio
- Keyword density
- Line length variance

Classifies as: `clean` / `suspicious` / `malicious` / `legitimate_obfuscated`

Recognizes legitimate tools: ionCube, SourceGuardian, Zend Guard, phpSHIELD.

---

## WordPress Scanner

| Check          | Method                                                            |
| -------------- | ----------------------------------------------------------------- |
| Core integrity | Verifies files against WordPress.org checksum API                 |
| Plugin CVEs    | Checks versions against vulnerability database                    |
| Database scan  | Detects injected JS/iframes in wp_options, wp_posts               |
| Config audit   | Debug mode, file editing, table prefix, key strength, permissions |
| Upload dir     | PHP files in uploads, images with embedded PHP                    |
| mu-plugins     | Auto-loaded backdoors                                             |
| .htaccess      | External redirects, PHP execution in uploads                      |
| Admin audit    | Lists admin users, flags recent creations                         |
| Auto-update    | Updates vulnerable plugins via WP-CLI                             |

---

## Real-time Protection

- Monitors configured paths via Linux inotify
- Scans new/modified PHP files instantly
- Auto-quarantine mode (optional)
- Webhook alerts: Telegram, Discord, Slack

---

## File Structure

```
malwarescan/
├── info.json
├── install.sh
├── malwarescan_main.py      # Core engine (60 API methods)
├── ml_classifier.py         # ML entropy classifier
├── realtime_watcher.py      # Inotify file watcher
├── report_generator.py      # PDF report generator
├── wp_advanced.py           # WordPress advanced scanner
├── index.html               # 10-tab UI
└── ico-malwarescan.png      # Plugin icon
```

---

## UI

| Tab        | Function                                         |
| ---------- | ------------------------------------------------ |
| Dashboard  | Stats, last scan, capabilities overview          |
| Scan       | Background scan with live progress               |
| Integrity  | Baseline creation, change detection              |
| Quarantine | Restore or permanently delete isolated files     |
| Schedule   | Recurring scans (6h / 12h / daily / weekly)      |
| Reports    | History, PDF export                              |
| Whitelist  | Path exclusions                                  |
| WordPress  | Deep scan, checksums, CVEs, DB scan, auto-update |
| Realtime   | File watcher, auto-quarantine, webhook config    |
| ML Scan    | Entropy classification, feature breakdown        |

---

## API

All endpoints: `POST /plugin?action=a&name=malwarescan&s={method}`

**Scanning** — `scan_path`, `scan_status`, `scan_file`

**WordPress** — `wp_scan`, `wp_verify_checksums`, `wp_check_vulns`, `wp_scan_database`, `wp_auto_update`

**ML** — `ml_classify_file`, `ml_classify_path`, `ml_train`

**Realtime** — `watcher_start`, `watcher_stop`, `watcher_status`, `watcher_events`, `watcher_config`

**Quarantine** — `quarantine_file`, `restore_file`, `delete_quarantined`, `list_quarantine`

**Reports** — `generate_pdf_report`, `list_pdf_reports`, `delete_pdf_report`

**Integrity** — `integrity_create_baseline`, `integrity_check`

**Schedule** — `schedule_add`, `schedule_list`, `schedule_remove`, `schedule_toggle`

---

## Configuration

### Scheduled Scans

Hourly cron checks for due scans (installed automatically):

```
0 * * * * cd /www/server/panel && python3 -c "..." >> logs/cron.log 2>&1
```

### Real-time Watcher

Configure via UI or API:

```json
{
  "watch_paths": ["/www/wwwroot/site1.com", "/www/wwwroot/site2.com"],
  "auto_quarantine": true,
  "alert_webhook": "https://hooks.slack.com/services/..."
}
```

### Custom YARA Rules

Drop `.yar` files into `/www/server/panel/plugin/malwarescan/rules/`

---

## Security

- Runs as root (aaPanel context)
- Quarantine directory: `chmod 700`
- Python modules: `chmod 600`
- Auto-quarantine disabled by default
- Whitelist supports file and directory paths
- No external data transmission without explicit webhook config

---

## License

MIT

---

### Keywords

`aapanel` `aapanel-plugin` `malware-scanner` `webshell-detection` `wordpress-security` `php-malware` `server-security` `file-integrity` `yara-rules` `real-time-protection` `baota` `bt-panel` `security-plugin`
