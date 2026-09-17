# Host Intrusion Detection System (HIDS)

A terminal-based (Textual TUI) host intrusion detection tool that:
- Baselines and monitors critical system files for tampering (SHA-256 hashing)
- Watches those files in real time for changes
- Scans SSH logs for brute-force login attempts
- Scans shell history for suspicious commands
- Generates an HTML report and can email alert summaries

Originally built and tested on a Linux VM. This version has been adjusted to also run on macOS (see **What changed for macOS** below) — Linux still works exactly as before.

## Setup (macOS)

```bash
# 1. Clone your repo, then from inside the project folder:
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 2. Create your local config from the template and fill in real values
cp config.example.json config.json
nano config.json   # or open in any editor

# 3. Run it
python3 tui.py
```

Press `q` to quit. Use **Initialize Baseline** the first time you run it on a new machine — don't carry over a `baseline.json` generated on a different OS, since the exact set of files that exist (e.g. `/etc/shadow`) differs between Linux and macOS.

### macOS permissions to know about
- **SSH log checking**: macOS doesn't write sshd activity to a flat log file — it goes through the unified logging system instead, so this now shells out to `log show`. If it fails, either grant your terminal **Full Disk Access** (System Settings → Privacy & Security → Full Disk Access) or run with `sudo`.
- **Shell history**: checks `~/.zsh_history` first (macOS's default shell since Catalina), falling back to `~/.bash_history`.
- **Monitored files**: `/etc/shadow` doesn't exist on macOS (user credentials live in Directory Services, not a flat file) — it'll just be skipped, not an error.

## What changed for macOS

| Area | Before (Linux-only) | Now |
|---|---|---|
| Real-time file watching | `inotify_simple` — wraps a Linux-only kernel API, doesn't run on macOS at all | `watchdog` — same code path uses FSEvents on macOS, inotify on Linux |
| SSH log check | Read `/var/log/auth.log` / `/var/log/secure` directly | Linux: unchanged. macOS: queries `log show` (unified logging), since sshd doesn't write those files there |
| Suspicious command scan | Only checked `~/.bash_history` | Checks `~/.zsh_history` (macOS default) first, falls back to bash, and correctly parses zsh's timestamped history line format |

I also fixed a pre-existing bug in `email_alerts.py`'s `send_alert()`: it was reading `self.email_config['sender_email']`'s *value* as a dict key (`self.email_config['linuxkaproject@gmail.com']`) instead of just using `'sender_email'`/`'recipient_email'` — that key doesn't exist in the dict, so every real-time email alert was silently throwing a `KeyError` and failing (caught and logged, but never actually sent). `send_summary_report()` didn't have this bug. It's fixed in both now.

## ⚠️ About your Gmail app password

Your uploaded `config.json` had a live Gmail app password sitting in plain text. That file is **not** included here — it's gitignored, and `config.example.json` (with placeholders) is what gets committed instead. But since that password already left your machine once (in the file you sent me), I'd treat it as burned: **revoke/regenerate it at <https://myaccount.google.com/apppasswords> before you do anything else**, then put the new one only in your local `config.json`.

## Pushing to GitHub

From inside the project folder on your Mac:

```bash
git init
git add .
git commit -m "Convert HIDS project for macOS"
git branch -M main
git remote add origin https://github.com/Aryaman-vbs/<your-repo-name>.git
git push -u origin main
```

If the repo doesn't exist on GitHub yet, create it first (via github.com or `gh repo create`) before the `git remote add` step. Double check `git status` before your first commit — you want to see `config.json`, `venv/`, `baseline.json`, and `__pycache__/` listed as ignored, not staged.
