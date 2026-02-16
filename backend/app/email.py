import os
import logging
import resend
from typing import Optional
from html import escape

resend.api_key = os.getenv("RESEND_API_KEY")
logger = logging.getLogger(__name__)

APP_NAME = os.getenv("APP_NAME", "App")
FROM_EMAIL = os.getenv("FROM_EMAIL", "noreply@example.com")

if not resend.api_key:
    logger.warning("RESEND_API_KEY is not set - emails will not be sent")


def _redact_email(email: str) -> str:
    """Redact email for logging: u***@domain.com"""
    if "@" in email:
        local, domain = email.rsplit("@", 1)
        return f"{local[0]}***@{domain}" if local else f"***@{domain}"
    return "***"


def send_verification_email(to_email: str, code: str, username: str) -> Optional[dict]:
    """Send a verification email with the 6-digit code."""
    try:
        response = resend.Emails.send({
            "from": f"{APP_NAME} <{FROM_EMAIL}>",
            "to": [to_email],
            "subject": f"Verify your {APP_NAME} account",
            "html": f"""
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h1 style="color: #333;">Welcome to {escape(APP_NAME)}, {escape(username)}!</h1>
                    <p>Your verification code is:</p>
                    <div style="font-size: 32px; font-weight: bold; letter-spacing: 8px;
                                background: #f5f5f5; padding: 20px; text-align: center;
                                border-radius: 8px; margin: 20px 0;">
                        {code}
                    </div>
                    <p>This code expires in 15 minutes.</p>
                    <p>If you didn't create an account, you can ignore this email.</p>
                </div>
            """
        })
        return response
    except Exception as e:
        logger.error(f"Failed to send verification email to {_redact_email(to_email)}: {e}")
        return None


def send_password_reset_email(to_email: str, code: str, username: str) -> Optional[dict]:
    """Send a password reset email with the 6-digit code."""
    if not resend.api_key:
        logger.error("Cannot send email - RESEND_API_KEY is not set")
        return None
    try:
        response = resend.Emails.send({
            "from": f"{APP_NAME} <{FROM_EMAIL}>",
            "to": [to_email],
            "subject": f"Reset your {APP_NAME} password",
            "html": f"""
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h1 style="color: #333;">Password Reset Request</h1>
                    <p>Hi {escape(username)},</p>
                    <p>You requested to reset your password. Your reset code is:</p>
                    <div style="font-size: 32px; font-weight: bold; letter-spacing: 8px;
                                background: #f5f5f5; padding: 20px; text-align: center;
                                border-radius: 8px; margin: 20px 0;">
                        {code}
                    </div>
                    <p>This code expires in 15 minutes.</p>
                    <p>If you didn't request a password reset, you can ignore this email.</p>
                </div>
            """
        })
        return response
    except Exception as e:
        logger.error(f"Failed to send password reset email to {_redact_email(to_email)}: {e}")
        return None
