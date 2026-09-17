"""
Real-time File Monitoring Module
Uses the `watchdog` library, which wraps the native filesystem-event API on
whichever OS it's running on (inotify on Linux, FSEvents on macOS,
ReadDirectoryChangesW on Windows) — so this same code works on the Linux VM
and on macOS without any platform-specific branching.
"""

import os
from collections import defaultdict

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    FileSystemEventHandler = object  # placeholder so the class below still defines cleanly


class _MonitoredFileHandler(FileSystemEventHandler):
    """watchdog reports events at the directory level; this filters them
    down to just the specific files HIDS cares about."""

    def __init__(self, hids_core, watched_files):
        super().__init__()
        self.hids_core = hids_core
        self.watched_files = {os.path.abspath(f) for f in watched_files}

    def _matches(self, path):
        return os.path.abspath(path) in self.watched_files

    def on_modified(self, event):
        if not event.is_directory and self._matches(event.src_path):
            alert = f"🔴 REAL-TIME ALERT: File modified - {event.src_path}"
            self.hids_core.add_alert("Real-time Monitor", alert)

    def on_deleted(self, event):
        if not event.is_directory and self._matches(event.src_path):
            alert = f"🔴 REAL-TIME ALERT: File deleted - {event.src_path}"
            self.hids_core.add_alert("Real-time Monitor", alert)

    def on_created(self, event):
        if not event.is_directory and self._matches(event.src_path):
            alert = f"🔴 REAL-TIME ALERT: File created - {event.src_path}"
            self.hids_core.add_alert("Real-time Monitor", alert)

    def on_moved(self, event):
        # A watched file being renamed/moved away is effectively a deletion
        if not event.is_directory and self._matches(event.src_path):
            alert = f"🔴 REAL-TIME ALERT: File moved/renamed - {event.src_path}"
            self.hids_core.add_alert("Real-time Monitor", alert)


class RealtimeMonitor:
    def __init__(self, hids_core):
        self.hids_core = hids_core
        self.monitoring = False
        self.observer = None

    def start_monitoring(self):
        """Start real-time file monitoring"""
        if not WATCHDOG_AVAILABLE:
            return False, "watchdog not installed. Run: pip install watchdog"

        if self.monitoring:
            return False, "Monitoring is already running"

        monitored_files = [
            f for f in self.hids_core.config.get("monitored_files", [])
            if os.path.exists(f)
        ]

        if not monitored_files:
            return False, "None of the monitored files exist on this system."

        # Group files by parent directory so we only schedule one watch per directory
        dirs_to_files = defaultdict(list)
        for filepath in monitored_files:
            parent_dir = os.path.dirname(os.path.abspath(filepath))
            dirs_to_files[parent_dir].append(filepath)

        handler = _MonitoredFileHandler(self.hids_core, monitored_files)
        self.observer = Observer()

        try:
            for directory in dirs_to_files:
                self.observer.schedule(handler, directory, recursive=False)
            self.observer.start()
        except Exception as e:
            return False, f"Could not start monitoring: {str(e)}"

        self.monitoring = True
        return True, "Real-time monitoring started"

    def stop_monitoring(self):
        """Stop real-time file monitoring"""
        self.monitoring = False
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=2)
            except Exception:
                pass
            self.observer = None
        return True, "Real-time monitoring stopped"

    def is_monitoring(self):
        """Check if monitoring is active"""
        return self.monitoring
