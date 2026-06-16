import smtplib, json, os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
class EmailAlerter:
    def __init__(self, smtp_host=None, smtp_port=587, username=None, password=None, to_addr=None):
        self.smtp_host = smtp_host or os.environ.get('WATCHDOG_SMTP_HOST')
        self.smtp_port = smtp_port
        self.username = username or os.environ.get('WATCHDOG_SMTP_USER')
        self.password = password or os.environ.get('WATCHDOG_SMTP_PASS')
        self.to_addr = to_addr or os.environ.get('WATCHDOG_ALERT_EMAIL','mikebains41@gmail.com')
    def send(self, alert):
        if not self.smtp_host or not self.username: return False
        try:
            severity = alert.get('severity','INFO')
            subject = f"[WATCHDOG {severity}] {alert.get('type')} — GPU {alert.get('gpu')}"
            body = f"""
WATCHDOG AIDR ALERT
===================
Time      : {alert.get('timestamp',datetime.now().isoformat())}
Type      : {alert.get('type')}
Severity  : {severity}
GPU       : {alert.get('gpu')}
Confidence: {alert.get('confidence','N/A')}
Message   : {alert.get('message')}

CVE 2048350 — Mike Bains GPU Security Research
            """.strip()
            msg = MIMEMultipart()
            msg['From'] = self.username
            msg['To'] = self.to_addr
            msg['Subject'] = subject
            msg.attach(MIMEText(body,'plain'))
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                server.starttls()
                server.login(self.username, self.password)
                server.send_message(msg)
            print(f"[EMAIL] Alert sent to {self.to_addr}")
            return True
        except Exception as e:
            print(f"[EMAIL ERROR] {e}")
            return False
