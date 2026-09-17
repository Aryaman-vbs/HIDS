"""
HIDS Core Module
Handles file integrity monitoring, SSH log analysis, and suspicious command detection

Cross-platform notes:
- Linux: reads /var/log/auth.log or /var/log/secure directly, as before.
- macOS: sshd doesn't write to a flat log file anymore — its output goes
  through the unified logging system — so failed-login checking shells out
  to `log show` instead. See _check_ssh_logs_macos().
- Shell history: checks ~/.zsh_history first (the macOS default shell),
  falling back to ~/.bash_history, and understands zsh's timestamped
  history line format.
"""

import hashlib
import json
import os
import platform
import re
import subprocess
from datetime import datetime
from pathlib import Path
from email_alerts import EmailAlerter

class HIDSCore:
    def __init__(self, config_path="config.json"):
        self.config = self.load_config(config_path)
        self.baseline_file = "baseline.json"
        self.alerts = []
        self.email_alerter = EmailAlerter(self.config)
        
    def load_config(self, config_path):
        """Load configuration from JSON file"""
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            # Return default config if file doesn't exist
            return {
                "monitored_files": ["/etc/passwd", "/etc/group", "/etc/shadow"],
                "ssh_threshold": 3,
                "suspicious_commands": ["rm -rf", "nmap", "chmod 777", "curl http"],
                "email_alerts": False
            }
    
    def calculate_hash(self, filepath):
        """Calculate SHA-256 hash of a file"""
        try:
            sha256_hash = hashlib.sha256()
            with open(filepath, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            return None
    
    def create_baseline(self):
        """Create baseline of monitored files"""
        baseline = {}
        created_count = 0
        
        for filepath in self.config["monitored_files"]:
            if os.path.exists(filepath):
                file_hash = self.calculate_hash(filepath)
                if file_hash:
                    baseline[filepath] = {
                        "hash": file_hash,
                        "timestamp": datetime.now().isoformat()
                    }
                    created_count += 1
        
        with open(self.baseline_file, 'w') as f:
            json.dump(baseline, f, indent=4)
        
        return created_count, len(self.config["monitored_files"])
    
    def check_integrity(self):
        """Check file integrity against baseline"""
        if not os.path.exists(self.baseline_file):
            return False, "Baseline not found. Please initialize baseline first."
        
        with open(self.baseline_file, 'r') as f:
            baseline = json.load(f)
        
        changes_detected = []
        
        for filepath, baseline_data in baseline.items():
            if not os.path.exists(filepath):
                alert = f"⚠️ FILE DELETED: {filepath}"
                changes_detected.append(alert)
                self.add_alert("File Integrity", alert)
            else:
                current_hash = self.calculate_hash(filepath)
                if current_hash != baseline_data["hash"]:
                    alert = f"⚠️ FILE MODIFIED: {filepath}"
                    changes_detected.append(alert)
                    self.add_alert("File Integrity", alert)
        
        if not changes_detected:
            return True, "✓ All files match baseline. No changes detected."
        else:
            return True, changes_detected
    
    def check_ssh_logs(self):
        """Check for failed SSH login attempts (source depends on OS)"""
        failed_attempts = {}

        if platform.system() == "Darwin":
            success, error = self._check_ssh_logs_macos(failed_attempts)
        else:
            success, error = self._check_ssh_logs_linux(failed_attempts)

        if not success:
            return False, error

        if not failed_attempts:
            return True, "✓ No failed SSH login attempts detected."

        # Check threshold
        threshold = self.config.get("ssh_threshold", 3)
        alerts = []

        for identifier, count in failed_attempts.items():
            if count >= threshold:
                alert = f"🚨 BRUTE FORCE DETECTED: {count} failed attempts from {identifier}"
                alerts.append(alert)
                self.add_alert("SSH Security", alert)

        if not alerts:
            return True, f"✓ Failed login attempts detected but below threshold ({threshold})"

        return True, alerts

    def _check_ssh_logs_linux(self, failed_attempts):
        """Original behavior: read the flat auth log files directly."""
        log_paths = ["/var/log/auth.log", "/var/log/secure"]
        found_a_log = False

        for log_path in log_paths:
            if os.path.exists(log_path):
                found_a_log = True
                try:
                    with open(log_path, 'r', errors='ignore') as f:
                        for line in f:
                            self._extract_failed_attempt(line, failed_attempts)
                except PermissionError:
                    return False, "Permission denied. Run with sudo to access SSH logs."

        if not found_a_log:
            return True, None  # no log files present isn't an error, just nothing to report

        return True, None

    def _check_ssh_logs_macos(self, failed_attempts):
        """macOS routes sshd's output through the unified logging system
        instead of a flat file, so query it with the `log` command instead."""
        try:
            result = subprocess.run(
                ["log", "show", "--predicate", 'process == "sshd"',
                 "--style", "syslog", "--last", "1d"],
                capture_output=True, text=True, timeout=20
            )
        except FileNotFoundError:
            return False, "'log' command not found (this branch only works on macOS)."
        except subprocess.TimeoutExpired:
            return False, "Timed out querying the unified log. Try again."

        if result.returncode != 0:
            return False, (
                "Could not read the unified log. Your terminal may need Full Disk "
                "Access (System Settings > Privacy & Security > Full Disk Access), "
                "or try running with sudo. Details: " + result.stderr.strip()
            )

        for line in result.stdout.splitlines():
            self._extract_failed_attempt(line, failed_attempts)

        return True, None

    @staticmethod
    def _extract_failed_attempt(line, failed_attempts):
        """Shared parsing logic for both the Linux and macOS log sources."""
        if "Failed password" in line or "authentication failure" in line.lower():
            parts = line.split()
            identifier = "unknown"

            for part in parts:
                if part.startswith("from") and len(parts) > parts.index(part) + 1:
                    identifier = parts[parts.index(part) + 1]
                    break
                elif "rhost=" in part:
                    identifier = part.split("=")[1]
                    break

            failed_attempts[identifier] = failed_attempts.get(identifier, 0) + 1

    def check_suspicious_commands(self):
        """Check shell history for suspicious commands (zsh or bash)"""
        # macOS has defaulted to zsh since Catalina; check it first, then
        # fall back to bash history for Linux or older setups.
        candidate_histories = [
            os.path.expanduser("~/.zsh_history"),
            os.path.expanduser("~/.bash_history"),
        ]
        history_path = next((p for p in candidate_histories if os.path.exists(p)), None)

        if not history_path:
            return True, "No shell history file found."

        suspicious_found = []
        suspicious_patterns = self.config.get("suspicious_commands", [])

        try:
            with open(history_path, 'r', errors='ignore') as f:
                for line_num, raw_line in enumerate(f, 1):
                    line = self._clean_history_line(raw_line)
                    for pattern in suspicious_patterns:
                        if pattern in line:
                            alert = f"⚠️ Suspicious command found: '{line.strip()}' (Line {line_num})"
                            suspicious_found.append(alert)
                            self.add_alert("Command Monitor", alert)
                            break
        except Exception as e:
            return False, f"Error reading history: {str(e)}"

        if not suspicious_found:
            return True, f"✓ No suspicious commands detected in {os.path.basename(history_path)}."

        return True, suspicious_found

    @staticmethod
    def _clean_history_line(raw_line):
        """zsh's EXTENDED_HISTORY format prefixes each line with
        ': <timestamp>:<duration>;' before the actual command. Strip that
        so pattern matching behaves the same as it does for plain bash history."""
        match = re.match(r"^: \d+:\d+;(.*)$", raw_line)
        return match.group(1) if match else raw_line
    
    def add_alert(self, category, message):
        """Add an alert to the alerts list"""
        alert = {
            "timestamp": datetime.now().isoformat(),
            "category": category,
            "message": message
        }
        self.alerts.append(alert)
        
        # Send email alert for critical categories
        critical_categories = ["SSH Security", "File Integrity", "Real-time Monitor"]
        if category in critical_categories and self.config.get("email_alerts", False):
            try:
                success, result = self.email_alerter.send_alert(category, message)
                if not success:
                    print(f"[Email Alert Failed] {result}")
            except Exception as e:
                print(f"[Email Error] {str(e)}")
    
    def get_alerts(self):
        """Return all alerts"""
        return self.alerts
    
    def clear_alerts(self):
        """Clear all alerts"""
        self.alerts = []
