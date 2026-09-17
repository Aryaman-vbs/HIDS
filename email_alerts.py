"""
Email Alert Module
Sends email notifications when critical alerts are detected
"""

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

class EmailAlerter:
    def __init__(self, config):
        self.config = config
        self.email_config = config.get("email_config", {})
        self.email_enabled = config.get("email_alerts", False)
        
    def send_alert(self, alert_category, alert_message):
        """Send an email alert"""
        if not self.email_enabled:
            return False, "Email alerts are disabled in config"
        
        # Validate email configuration
        required_fields = ["smtp_server", "smtp_port", "sender_email", "sender_password", "recipient_email"]
        for field in required_fields:
            if not self.email_config.get(field):
                return False, f"Missing email configuration: {field}"
        
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.email_config['sender_email']
            msg['To'] = self.email_config['recipient_email']
            msg['Subject'] = f"🚨 HIDS Alert: {alert_category}"
            
            # Email body
            body = f"""
HIDS Security Alert
===================

Category: {alert_category}
Timestamp: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

Alert Details:
{alert_message}

---
This is an automated alert from your Host Intrusion Detection System.
Please investigate immediately.

System: {self.config.get('system_name', 'Unknown')}
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Connect to SMTP server and send
            server = smtplib.SMTP(self.email_config['smtp_server'], self.email_config['smtp_port'])
            server.starttls()
            server.login(self.email_config['sender_email'], self.email_config['sender_password'])
            text = msg.as_string()
            server.sendmail(self.email_config['sender_email'], self.email_config['recipient_email'], text)
            server.quit()
            
            return True, "Email alert sent successfully"
            
        except smtplib.SMTPAuthenticationError:
            return False, "Email authentication failed. Check your email and password."
        except smtplib.SMTPException as e:
            return False, f"SMTP error: {str(e)}"
        except Exception as e:
            return False, f"Error sending email: {str(e)}"
    
    def send_summary_report(self, alerts):
        """Send a summary report of all alerts"""
        if not self.email_enabled or not alerts:
            return False, "No alerts to send or email disabled"
        
        try:
            # Create message
            msg = MIMEMultipart()
            msg['From'] = self.email_config['sender_email']
            msg['To'] = self.email_config['recipient_email']
            msg['Subject'] = f"📊 HIDS Daily Summary - {datetime.now().strftime('%Y-%m-%d')}"
            
            # Group alerts by category
            categories = {}
            for alert in alerts:
                cat = alert['category']
                if cat not in categories:
                    categories[cat] = []
                categories[cat].append(alert)
            
            # Email body
            body = f"""
HIDS Security Summary Report
=============================

Report Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Total Alerts: {len(alerts)}
Alert Categories: {len(categories)}

"""
            
            for category, cat_alerts in categories.items():
                body += f"\n{category} ({len(cat_alerts)} alerts)\n"
                body += "-" * 50 + "\n"
                for alert in cat_alerts[:5]:  # Show first 5 of each category
                    timestamp = alert['timestamp'].split('T')[1].split('.')[0]
                    body += f"  [{timestamp}] {alert['message']}\n"
                if len(cat_alerts) > 5:
                    body += f"  ... and {len(cat_alerts) - 5} more\n"
                body += "\n"
            
            body += """
---
This is an automated summary from your Host Intrusion Detection System.
For detailed information, please check the HTML report.
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Send email
            server = smtplib.SMTP(self.email_config['smtp_server'], self.email_config['smtp_port'])
            server.starttls()
            server.login(self.email_config['sender_email'], self.email_config['sender_password'])
            text = msg.as_string()
            server.sendmail(self.email_config['sender_email'], self.email_config['recipient_email'], text)
            server.quit()
            
            return True, "Summary report sent successfully"
            
        except Exception as e:
            return False, f"Error sending summary: {str(e)}"
