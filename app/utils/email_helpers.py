import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


def send_email_verification_otp(to_email, otp_code, username):
    """Send email verification OTP during registration"""
    smtp_host = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
    smtp_port = int(os.environ.get('SMTP_PORT', 587))
    smtp_user = os.environ.get('SMTP_USER')
    smtp_password = os.environ.get('SMTP_PASSWORD')
    from_email = os.environ.get('SMTP_FROM_EMAIL', smtp_user)
    
    if not smtp_user or not smtp_password:
        logger.error(f"SMTP credentials not configured - SMTP_USER exists: {bool(smtp_user)}, SMTP_PASSWORD exists: {bool(smtp_password)}")
        return False
    
    logger.info(f"Sending email verification OTP to {to_email}")
    
    subject = "Erlang LMS - Verify Your Email Address"
    
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
                <h1>Verify Your Email Address</h1>
            </div>
            <div class="content">
                <p>Hello {username},</p>
                <p>Thank you for registering with Erlang LMS. Please use the verification code below to confirm your email address:</p>
                <div class="otp-box">
                    <div class="otp-code">{otp_code}</div>
                </div>
                <p><strong>This code will expire in 10 minutes.</strong></p>
                <p>If you didn't create an account with Erlang LMS, please ignore this email.</p>
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
    
    Thank you for registering with Erlang LMS. Please use the verification code below to confirm your email address:
    
    Your verification code is: {otp_code}
    
    This code will expire in 10 minutes.
    
    If you didn't create an account with Erlang LMS, please ignore this email.
    
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
        
        logger.info(f"Email verification OTP sent to {to_email}")
        return True
    except Exception as e:
        import traceback
        logger.error(f"Failed to send email verification OTP: {type(e).__name__}: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return False


def send_mandatory_course_reminder_email(to_email, username, course_title, days_remaining, deadline):
    """Send 7-day reminder email for mandatory course completion"""
    smtp_host = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
    smtp_port = int(os.environ.get('SMTP_PORT', 587))
    smtp_user = os.environ.get('SMTP_USER')
    smtp_password = os.environ.get('SMTP_PASSWORD')
    from_email = os.environ.get('SMTP_FROM_EMAIL', smtp_user)
    
    if not smtp_user or not smtp_password:
        logger.warning("SMTP credentials not configured - skipping mandatory course reminder email")
        return False
    
    logger.info(f"Sending 7-day reminder to {to_email} for course: {course_title}")
    
    subject = f"URGENT: Only {days_remaining} days left to complete: {course_title}"
    
    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; margin: 0; padding: 20px; }}
            .container {{ max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }}
            .header {{ background: linear-gradient(135deg, #dc3545, #c82333); padding: 30px; text-align: center; }}
            .header h1 {{ color: #ffffff; margin: 0; font-size: 24px; }}
            .content {{ padding: 30px; }}
            .course-box {{ background: #fff3cd; border: 2px solid #ffc107; border-radius: 10px; padding: 20px; text-align: center; margin: 20px 0; }}
            .course-title {{ font-size: 24px; font-weight: bold; color: #856404; }}
            .deadline-box {{ background: #f8d7da; border: 2px solid #dc3545; border-radius: 10px; padding: 15px; text-align: center; margin: 20px 0; }}
            .deadline-text {{ font-size: 20px; font-weight: bold; color: #721c24; }}
            .footer {{ background: #f8f9fa; padding: 20px; text-align: center; color: #666; font-size: 12px; }}
            p {{ color: #333; line-height: 1.6; }}
            .btn {{ display: inline-block; background: linear-gradient(135deg, #dc3545, #c82333); color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; margin-top: 15px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Urgent: Course Deadline Approaching</h1>
            </div>
            <div class="content">
                <p>Hello {username},</p>
                <p>This is a reminder that you have a mandatory course that requires completion within the next {days_remaining} days.</p>
                <div class="course-box">
                    <div class="course-title">{course_title}</div>
                </div>
                <div class="deadline-box">
                    <div class="deadline-text">Deadline: {deadline.strftime('%B %d, %Y at %I:%M %p UTC')}</div>
                </div>
                <p>Please log in to your Erlang LMS account immediately to complete this mandatory course before the deadline.</p>
                <p style="text-align: center;">
                    <a href="#" class="btn">Complete Course Now</a>
                </p>
                <p>If you have already completed this course, you can ignore this message.</p>
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
    
    URGENT: Course Deadline Approaching
    
    This is a reminder that you have a mandatory course that requires completion within the next {days_remaining} days.
    
    Course: {course_title}
    Deadline: {deadline.strftime('%B %d, %Y at %I:%M %p UTC')}
    
    Please log in to your Erlang LMS account immediately to complete this mandatory course before the deadline.
    
    If you have already completed this course, you can ignore this message.
    
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
        
        logger.info(f"7-day reminder email sent to {to_email} for course: {course_title}")
        return True
    except Exception as e:
        import traceback
        logger.error(f"Failed to send reminder email: {type(e).__name__}: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return False


def send_password_reset_email(to_email, otp_code, username):
    """Send password reset OTP email via SMTP"""
    smtp_host = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
    smtp_port = int(os.environ.get('SMTP_PORT', 587))
    smtp_user = os.environ.get('SMTP_USER')
    smtp_password = os.environ.get('SMTP_PASSWORD')
    from_email = os.environ.get('SMTP_FROM_EMAIL', smtp_user)
    
    if not smtp_user or not smtp_password:
        logger.error(f"SMTP credentials not configured - SMTP_USER exists: {bool(smtp_user)}, SMTP_PASSWORD exists: {bool(smtp_password)}")
        return False
    
    logger.info(f"Attempting to send email via {smtp_host}:{smtp_port} from {smtp_user}")
    
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
        import traceback
        logger.error(f"Failed to send password reset email: {type(e).__name__}: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return False


def send_mandatory_course_email(to_email, username, course_title, deadline=None, assigned_by=None):
    """Send mandatory course assignment notification email"""
    smtp_host = os.environ.get('SMTP_HOST', 'smtp.gmail.com')
    smtp_port = int(os.environ.get('SMTP_PORT', 587))
    smtp_user = os.environ.get('SMTP_USER')
    smtp_password = os.environ.get('SMTP_PASSWORD')
    from_email = os.environ.get('SMTP_FROM_EMAIL', smtp_user)
    
    if not smtp_user or not smtp_password:
        logger.warning("SMTP credentials not configured - skipping mandatory course email notification")
        return False
    
    logger.info(f"Sending mandatory course notification to {to_email} for course: {course_title}")
    
    subject = f"Erlang LMS - New Mandatory Course Assigned: {course_title}"
    
    deadline_text = ""
    if deadline:
        deadline_text = f"""
        <div style="background: #fff3cd; border: 1px solid #ffc107; border-radius: 5px; padding: 15px; margin: 15px 0;">
            <strong style="color: #856404;">Deadline:</strong> 
            <span style="color: #856404;">{deadline.strftime('%B %d, %Y at %I:%M %p UTC')}</span>
        </div>
        """
        deadline_plain = f"Deadline: {deadline.strftime('%B %d, %Y at %I:%M %p UTC')}"
    else:
        deadline_plain = "No specific deadline"
    
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
            .course-box {{ background: #e8f4fd; border: 2px solid #0d6efd; border-radius: 10px; padding: 20px; text-align: center; margin: 20px 0; }}
            .course-title {{ font-size: 24px; font-weight: bold; color: #0d6efd; }}
            .footer {{ background: #f8f9fa; padding: 20px; text-align: center; color: #666; font-size: 12px; }}
            p {{ color: #333; line-height: 1.6; }}
            .btn {{ display: inline-block; background: linear-gradient(135deg, #6f42c1, #e83e8c); color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold; margin-top: 15px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>New Mandatory Course Assigned</h1>
            </div>
            <div class="content">
                <p>Hello {username},</p>
                <p>A new mandatory course has been assigned to you. Please complete this course as soon as possible.</p>
                <div class="course-box">
                    <div class="course-title">{course_title}</div>
                </div>
                {deadline_text}
                <p>Please log in to your Erlang LMS account to access and complete this course.</p>
                <p style="text-align: center;">
                    <a href="#" class="btn">Go to Course</a>
                </p>
                <p>If you have any questions, please contact your administrator.</p>
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
    
    A new mandatory course has been assigned to you:
    
    Course: {course_title}
    {deadline_plain}
    
    Please log in to your Erlang LMS account to access and complete this course.
    
    If you have any questions, please contact your administrator.
    
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
        
        logger.info(f"Mandatory course notification email sent to {to_email}")
        return True
    except Exception as e:
        import traceback
        logger.error(f"Failed to send mandatory course email: {type(e).__name__}: {e}")
        logger.error(f"Traceback: {traceback.format_exc()}")
        return False
