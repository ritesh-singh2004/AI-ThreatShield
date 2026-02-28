import smtplib
from email.mime.text import MIMEText

class AlertSystem:
    def send_email_alert(self, threat_details):
        msg = MIMEText(f"ALERT! Threat detected:\n{threat_details}")
        msg['Subject'] = '🚨 SECURITY ALERT - Intrusion Detected'
        msg['From'] = 'your_email@gmail.com'
        msg['To'] = 'admin@yourdomain.com'
        
        # SMTP configuration
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login('your_email@gmail.com', 'your_password')
            server.send_message(msg)