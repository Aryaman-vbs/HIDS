# 🛡️ HIDS — Host Intrusion Detection System

A terminal-based host intrusion detection tool built with Python and [Textual](https://github.com/Textualize/textual). It baselines and monitors critical system files for tampering, watches them in real time, flags SSH brute-force attempts, scans shell history for suspicious commands, and generates HTML security reports — all from a TUI.

![Python](https://img.shields.io/badge/python-3.13-blue) ![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-lightgrey)

## Origin

Originally built and tested on a Linux VM, relying on Linux-specific APIs — `inotify` for real-time file watching and direct reads of `/var/log/auth.log` for SSH log analysis. It's since been extended to run natively on macOS as well, with the same codebase now supporting both.

## Features

- **File integrity monitoring** — SHA-256 baselining of critical files, with drift detection on demand
- **Real-time file-change alerts** — via `watchdog` (inotify on Linux, FSEvents on macOS)
- **SSH brute-force detection** — log file parsing on Linux, unified logging (`log show`) on macOS
- **Suspicious command scanning** — checks shell history (bash and zsh) against configurable patterns
- **HTML report generation** — a styled, shareable summary of everything detected
- **Optional email alerts** — SMTP-based notifications for critical events

## Tech stack

Python · Textual (TUI) · watchdog (cross-platform filesystem events) · smtplib

## Getting started

### macOS
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp config.example.json config.json   # then fill in your own values
python3 tui.py
```

### Linux
Same steps as above — `watchdog` uses inotify under the hood here, so no code changes are needed.

Press `q` to quit. Use **Initialize Baseline** the first time you run it on a new machine — baselines aren't portable across OSes, since the exact set of monitored files that exist (e.g. `/etc/shadow`) differs between Linux and macOS.

### macOS-specific notes
- **SSH log checking** shells out to `log show`, since macOS doesn't write sshd activity to a flat file. If it fails, grant your terminal Full Disk Access (System Settings → Privacy & Security → Full Disk Access) or run with `sudo`.
- **Shell history** checks `~/.zsh_history` first (macOS's default shell), falling back to `~/.bash_history`.

## What changed for macOS

| Area | Linux (original) | Cross-platform (current) |
|---|---|---|
| Real-time file watching | `inotify_simple` — Linux-only | `watchdog` — same code, backed by FSEvents on macOS / inotify on Linux |
| SSH log check | Reads `/var/log/auth.log` / `/var/log/secure` | Linux: unchanged. macOS: queries `log show` (unified logging) |
| Suspicious command scan | Only `~/.bash_history` | Checks `~/.zsh_history` first, with correct parsing of zsh's timestamped history format |

Also fixed a bug in `email_alerts.py` where `send_alert()` was reading the sender's email as a dict *key* instead of using the `sender_email` field — this silently broke every real-time email alert.

## Configuration

Copy `config.example.json` to `config.json` and fill in your own values: monitored files, SSH brute-force threshold, suspicious command patterns, and (optionally) SMTP details for email alerts. `config.json` is gitignored, so your real values never get committed.

## Project structure

```
hids-intrusion-detection/
├── tui.py                  # Entry point — Textual TUI
├── hids_core.py             # Baselining, integrity checks, SSH log analysis, command scanning
├── monitor_realtime.py       # Real-time file watching (watchdog)
├── email_alerts.py           # SMTP email alerts
├── report_generator.py       # HTML report generation
├── config.example.json       # Config template
└── requirements.txt
```

## Author

**Aryaman Verma**
[GitHub](https://github.com/Aryaman-vbs) · [LinkedIn](https://www.linkedin.com/in/aryaman-verma-7a9ab4306/)
