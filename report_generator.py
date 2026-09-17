"""
HTML Report Generator
Creates detailed HTML reports of all detected alerts
"""

from datetime import datetime
import os

class ReportGenerator:
    def __init__(self, hids_core):
        self.hids_core = hids_core
    
    def generate_html_report(self, filename="hids_report.html"):
        """Generate HTML report from alerts"""
        alerts = self.hids_core.get_alerts()
        
        html_content = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>HIDS Security Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            min-height: 100vh;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }}
        
        .header p {{
            font-size: 1.1em;
            opacity: 0.9;
        }}
        
        .stats {{
            display: flex;
            justify-content: space-around;
            padding: 30px;
            background: #f8f9fa;
            border-bottom: 3px solid #e9ecef;
        }}
        
        .stat-box {{
            text-align: center;
            padding: 20px;
            background: white;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            min-width: 150px;
        }}
        
        .stat-box h3 {{
            font-size: 2em;
            color: #667eea;
            margin-bottom: 10px;
        }}
        
        .stat-box p {{
            color: #6c757d;
            font-size: 0.9em;
        }}
        
        .content {{
            padding: 40px;
        }}
        
        .alert-section {{
            margin-bottom: 30px;
        }}
        
        .alert-section h2 {{
            color: #2a5298;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #e9ecef;
        }}
        
        .alert-item {{
            background: #fff;
            border-left: 4px solid #dc3545;
            padding: 20px;
            margin-bottom: 15px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
            transition: transform 0.2s;
        }}
        
        .alert-item:hover {{
            transform: translateX(5px);
        }}
        
        .alert-item.warning {{
            border-left-color: #ffc107;
        }}
        
        .alert-item.info {{
            border-left-color: #17a2b8;
        }}
        
        .alert-timestamp {{
            color: #6c757d;
            font-size: 0.85em;
            margin-bottom: 8px;
        }}
        
        .alert-category {{
            display: inline-block;
            background: #667eea;
            color: white;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            margin-bottom: 10px;
        }}
        
        .alert-message {{
            color: #333;
            line-height: 1.6;
        }}
        
        .no-alerts {{
            text-align: center;
            padding: 60px;
            color: #6c757d;
        }}
        
        .no-alerts h3 {{
            color: #28a745;
            font-size: 1.5em;
            margin-bottom: 10px;
        }}
        
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #6c757d;
            border-top: 2px solid #e9ecef;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ HIDS Security Report</h1>
            <p>Generated on {datetime.now().strftime("%B %d, %Y at %I:%M %p")}</p>
        </div>
        
        <div class="stats">
            <div class="stat-box">
                <h3>{len(alerts)}</h3>
                <p>Total Alerts</p>
            </div>
            <div class="stat-box">
                <h3>{len(set(a['category'] for a in alerts))}</h3>
                <p>Categories</p>
            </div>
            <div class="stat-box">
                <h3>{len(self.hids_core.config.get('monitored_files', []))}</h3>
                <p>Monitored Files</p>
            </div>
        </div>
        
        <div class="content">
"""
        
        if alerts:
            # Group alerts by category
            categories = {}
            for alert in alerts:
                category = alert['category']
                if category not in categories:
                    categories[category] = []
                categories[category].append(alert)
            
            for category, category_alerts in categories.items():
                html_content += f"""
            <div class="alert-section">
                <h2>{category} ({len(category_alerts)} alerts)</h2>
"""
                for alert in category_alerts:
                    html_content += f"""
                <div class="alert-item">
                    <div class="alert-timestamp">⏰ {alert['timestamp']}</div>
                    <div class="alert-category">{alert['category']}</div>
                    <div class="alert-message">{alert['message']}</div>
                </div>
"""
                html_content += """
            </div>
"""
        else:
            html_content += """
            <div class="no-alerts">
                <h3>✅ No Alerts Detected</h3>
                <p>Your system appears to be secure. No suspicious activity detected.</p>
            </div>
"""
        
        html_content += f"""
        </div>
        
        <div class="footer">
            <p>Host Intrusion Detection System (HIDS) v1.0</p>
            <p>Developed for Academic Project | {datetime.now().year}</p>
        </div>
    </div>
</body>
</html>
"""
        
        # Write to file
        with open(filename, 'w') as f:
            f.write(html_content)
        
        return os.path.abspath(filename)
