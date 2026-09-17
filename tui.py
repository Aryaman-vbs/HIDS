"""
Text-based User Interface using Textual
Main entry point for the HIDS application
"""

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical, ScrollableContainer
from textual.widgets import Header, Footer, Button, Static, Label
from textual.binding import Binding
from hids_core import HIDSCore
from monitor_realtime import RealtimeMonitor
from report_generator import ReportGenerator
from datetime import datetime

class AlertDisplay(Static):
    """Widget to display alerts"""
    pass

class StatusDisplay(Static):
    """Widget to display system status"""
    pass

class HIDSApp(App):
    """HIDS Text User Interface Application"""
    
    CSS = """
    Screen {
        background: $surface;
    }
    
    Header {
        background: $primary;
        color: $text;
    }
    
    #status-container {
        height: 8;
        background: $panel;
        border: solid $primary;
        padding: 1;
        margin: 1;
    }
    
    #alerts-container {
        height: 1fr;
        background: $panel;
        border: solid $primary;
        padding: 1;
        margin: 1;
    }
    
    #buttons-container {
        height: auto;
        background: $panel;
        border: solid $primary;
        padding: 1;
        margin: 1;
    }
    
    Button {
        margin: 1;
        min-width: 30;
    }
    
    .alert-item {
        padding: 1;
        margin: 1;
        background: $error 20%;
        border-left: thick $error;
    }
    
    .success {
        color: $success;
    }
    
    .warning {
        color: $warning;
    }
    
    .error {
        color: $error;
    }
    """
    
    BINDINGS = [
        Binding("q", "quit", "Quit", show=True),
    ]
    
    def __init__(self):
        super().__init__()
        self.hids = HIDSCore()
        self.monitor = RealtimeMonitor(self.hids)
        self.report_gen = ReportGenerator(self.hids)
        self.monitoring_active = False
    
    def compose(self) -> ComposeResult:
        """Create child widgets"""
        yield Header(show_clock=True)
        
        with Container(id="status-container"):
            yield Static("🛡️ HIDS Status Monitor", id="status-title")
            yield StatusDisplay("System Ready", id="status")
        
        with ScrollableContainer(id="alerts-container"):
            yield Static("📋 Alert Log", id="alerts-title")
            yield AlertDisplay("No alerts yet. Start monitoring...", id="alerts")
        
        with Horizontal(id="buttons-container"):
            yield Button("Initialize Baseline", id="btn-baseline", variant="primary")
            yield Button("Check Integrity", id="btn-integrity", variant="default")
            yield Button("Check SSH Logs", id="btn-ssh", variant="default")
            yield Button("Check Commands", id="btn-commands", variant="default")
        
        with Horizontal(id="buttons-container2"):
            yield Button("Start Monitor", id="btn-monitor", variant="success")
            yield Button("Stop Monitor", id="btn-stop", variant="warning")
            yield Button("Generate Report", id="btn-report", variant="primary")
            yield Button("Email Summary", id="btn-email", variant="success")
            yield Button("Clear Alerts", id="btn-clear", variant="error")
        
        yield Footer()
    
    def on_mount(self) -> None:
        """Called when app starts"""
        email_status = "✉️ Enabled" if self.hids.config.get("email_alerts", False) else "✉️ Disabled"
        self.update_status(f"✅ HIDS Application Started | Email Alerts: {email_status}")
        self.update_alerts_display()
    
    def update_status(self, message: str):
        """Update status display"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        status_widget = self.query_one("#status", StatusDisplay)
        status_widget.update(f"[{timestamp}] {message}")
    
    def update_alerts_display(self):
        """Update alerts display"""
        alerts = self.hids.get_alerts()
        alerts_widget = self.query_one("#alerts", AlertDisplay)
        
        if not alerts:
            alerts_widget.update("No alerts detected. System appears secure. ✅")
            return
        
        alert_text = ""
        for i, alert in enumerate(reversed(alerts[-20:]), 1):  # Show last 20 alerts
            timestamp = alert['timestamp'].split('T')[1].split('.')[0]
            category = alert['category']
            message = alert['message']
            alert_text += f"\n[{timestamp}] [{category}] {message}\n"
        
        alerts_widget.update(alert_text.strip())
    
    async def on_button_pressed(self, event: Button.Pressed) -> None:
        """Handle button presses"""
        button_id = event.button.id
        
        if button_id == "btn-baseline":
            await self.handle_initialize_baseline()
        
        elif button_id == "btn-integrity":
            await self.handle_check_integrity()
        
        elif button_id == "btn-ssh":
            await self.handle_check_ssh()
        
        elif button_id == "btn-commands":
            await self.handle_check_commands()
        
        elif button_id == "btn-monitor":
            await self.handle_start_monitor()
        
        elif button_id == "btn-stop":
            await self.handle_stop_monitor()
        
        elif button_id == "btn-report":
            await self.handle_generate_report()
        
        elif button_id == "btn-email":
            await self.handle_send_email()
        
        elif button_id == "btn-clear":
            await self.handle_clear_alerts()
    
    async def handle_initialize_baseline(self):
        """Initialize baseline"""
        self.update_status("⏳ Creating baseline...")
        created, total = self.hids.create_baseline()
        self.update_status(f"✅ Baseline created: {created}/{total} files")
        self.update_alerts_display()
    
    async def handle_check_integrity(self):
        """Check file integrity"""
        self.update_status("⏳ Checking file integrity...")
        success, result = self.hids.check_integrity()
        
        if success:
            if isinstance(result, list):
                self.update_status(f"⚠️ {len(result)} changes detected!")
            else:
                self.update_status(result)
        else:
            self.update_status(f"❌ {result}")
        
        self.update_alerts_display()
    
    async def handle_check_ssh(self):
        """Check SSH logs"""
        self.update_status("⏳ Analyzing SSH logs...")
        success, result = self.hids.check_ssh_logs()
        
        if success:
            if isinstance(result, list):
                self.update_status(f"🚨 {len(result)} SSH threats detected!")
            else:
                self.update_status(result)
        else:
            self.update_status(f"❌ {result}")
        
        self.update_alerts_display()
    
    async def handle_check_commands(self):
        """Check suspicious commands"""
        self.update_status("⏳ Scanning bash history...")
        success, result = self.hids.check_suspicious_commands()
        
        if success:
            if isinstance(result, list):
                self.update_status(f"⚠️ {len(result)} suspicious commands found!")
            else:
                self.update_status(result)
        else:
            self.update_status(f"❌ {result}")
        
        self.update_alerts_display()
    
    async def handle_start_monitor(self):
        """Start real-time monitoring"""
        if self.monitoring_active:
            self.update_status("⚠️ Monitoring already active")
            return
        
        success, message = self.monitor.start_monitoring()
        if success:
            self.monitoring_active = True
            self.update_status("🟢 Real-time monitoring ACTIVE")
            # Set up periodic alert refresh
            self.set_interval(2, self.update_alerts_display)
        else:
            self.update_status(f"❌ {message}")
    
    async def handle_stop_monitor(self):
        """Stop real-time monitoring"""
        if not self.monitoring_active:
            self.update_status("⚠️ Monitoring not active")
            return
        
        success, message = self.monitor.stop_monitoring()
        self.monitoring_active = False
        self.update_status("🔴 Real-time monitoring STOPPED")
    
    async def handle_generate_report(self):
        """Generate HTML report"""
        self.update_status("⏳ Generating HTML report...")
        try:
            report_path = self.report_gen.generate_html_report()
            self.update_status(f"✅ Report saved: {report_path}")
        except Exception as e:
            self.update_status(f"❌ Report failed: {str(e)}")
    
    async def handle_send_email(self):
        """Send email summary"""
        if not self.hids.config.get("email_alerts", False):
            self.update_status("❌ Email alerts disabled in config.json")
            return
        
        alerts = self.hids.get_alerts()
        if not alerts:
            self.update_status("⚠️ No alerts to send")
            return
        
        self.update_status("⏳ Sending email summary...")
        try:
            success, message = self.hids.email_alerter.send_summary_report(alerts)
            if success:
                self.update_status(f"✅ {message}")
            else:
                self.update_status(f"❌ {message}")
        except Exception as e:
            self.update_status(f"❌ Email error: {str(e)}")
    
    async def handle_clear_alerts(self):
        """Clear all alerts"""
        self.hids.clear_alerts()
        self.update_status("🗑️ All alerts cleared")
        self.update_alerts_display()

def main():
    """Main entry point"""
    app = HIDSApp()
    app.run()

if __name__ == "__main__":
    main()
