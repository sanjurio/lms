import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging

logger = logging.getLogger(__name__)


def send_password_reset_email(to_email, otp_code, username):
    """Send password reset OTP email via SMTP"""
    smtp_host = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
    smtp_port = int(os.environ.get('SMTP_PORT', 587))
    smtp_user = os.environ.get('SMTP_USER')
    smtp_password = os.environ.get('SMTP_PASSWORD')
    from_email = os.environ.get('SMTP_FROM_EMAIL', smtp_user)
    
    if not smtp_user or not smtp_password:
        logger.error("SMTP credentials not configured")
        return False
    
    subject = "Erlang LMS - Password Reset Code"
    
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px; }}
            .container {{ max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
            .header {{ background: linear-gradient(135deg, #6f42c1, #e83e8c); padding: 30px; text-align: center; }}
            .header h1 {{ color: #ffffff; margin: 0; font-size: 24px; }}
            .content {{ padding: 30px; }}
            .otp-box {{ background: #f8f9fa; border: 2px dashed #6f42c1; border-radius: 10px; padding: 20px; text-align: center; margin: 20px 0; }}
            .otp-code {{ font-size: 36px; font-weight: bold; color: #6f42c1; letter-spacing: 8px; }}
            .footer {{ background: #f8f9fa; padding: 20px; text-align: center; color: #666; font-size: 12px; }}
            p {{ color: #333; line-height: 1.6; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Password Reset Request</h1>
            </div>
            <div class="content">
                <p>Hello {username},</p>
                <p>We received a request to reset your password for your Erlang LMS account. Use the verification code below to reset your password:</p>
                <div class="otp-box">
                    <div class="otp-code">{otp_code}</div>
                </div>
                <p><strong>This code will expire in 10 minutes.</strong></p>
                <p>If you didn't request this password reset, please ignore this email or contact support if you have concerns.</p>
                <p>Best regards,<br>Erlang LMS Team</p>
            </div>
            <div class="footer">
                <p>This is an automated message. Please do not reply to this email.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    text_body = f"""
    Hello {username},
    
    We received a request to reset your password for your Erlang LMS account.
    
    Your verification code is: {otp_code}
    
    This code will expire in 10 minutes.
    
    If you didn't request this password reset, please ignore this email.
    
    Best regards,
    Erlang LMS Team
    """
    
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = from_email
        msg['To'] = to_email
        
        part1 = MIMEText(text_body, 'plain')
        part2 = MIMEText(html_body, 'html')
        msg.attach(part1)
        msg.attach(part2)
        
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.sendmail(from_email, to_email, msg.as_string())
        
        logger.info(f"Password reset email sent to {to_email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send password reset email: {e}")
        return False
