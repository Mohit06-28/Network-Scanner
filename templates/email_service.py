from flask_mail import Message
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

class EmailOTP:
    def __init__(self, mail):
        self.mail = mail
    
    def send_otp(self, email, otp):
        """Send OTP via email"""
        subject = "Network Scanner - Verification Code"
        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif;">
            <div style="max-width: 600px; margin: 0 auto; padding: 20px; background: #f8f9fa; border-radius: 10px;">
                <h2 style="color: #007bff;">Network Security Scanner</h2>
                <p>Your verification code is:</p>
                <div style="font-size: 32px; font-weight: bold; text-align: center; padding: 20px; background: white; border-radius: 5px; margin: 20px 0;">
                    {otp}
                </div>
                <p>This code will expire in 10 minutes.</p>
                <hr>
                <small style="color: #666;">If you didn't request this code, please ignore this email.</small>
            </div>
        </body>
        </html>
        """
        
        msg = Message(subject, recipients=[email], html=body)
        self.mail.send(msg)
    
    def send_report(self, email, report_data, report_format='pdf'):
        """Send scan report via email"""
        subject = f"Network Scan Report - {report_data.get('target', 'Unknown')}"
        
        body = f"""
        <html>
        <body style="font-family: Arial, sans-serif;">
            <div style="max-width: 800px; margin: 0 auto; padding: 20px;">
                <h2>Network Security Scan Report</h2>
                <p>Target: {report_data.get('target')}</p>
                <p>Scan Date: {report_data.get('timestamp')}</p>
                <p>Open Ports Found: {len(report_data.get('open_ports', []))}</p>
                <h3>Open Ports:</h3>
                <ul>
        """
        
        for port in report_data.get('open_ports', []):
            body += f"<li>Port {port['port']}/{port['protocol']} - {port.get('service', 'Unknown')}</li>"
        
        body += """
                </ul>
                <hr>
                <small>This is an automated report from Network Security Scanner.</small>
            </div>
        </body>
        </html>
        """
        
        msg = Message(subject, recipients=[email], html=body)
        self.mail.send(msg)