"""
auth/email_sender.py — Async Gmail SMTP email sender for recovery flows.

Setup (add to .env):
    SMTP_ENABLED=true
    SMTP_USER=your-gmail@gmail.com
    SMTP_PASSWORD=xxxx-xxxx-xxxx-xxxx   # Gmail App Password (16 chars)
    SMTP_FROM_NAME=Cyber Sentinel XDR
    FRONTEND_URL=http://localhost:3000

Gmail App Password: myaccount.google.com -> Security -> 2FA -> App passwords
"""
import asyncio
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

logger = logging.getLogger(__name__)


async def send_password_reset_email(
    to_email: str,
    reset_token: str,
    username: str,
) -> bool:
    """
    Send a password reset email with the recovery link.
    Returns True on success, False on failure (never raises).
    """
    from config import settings  # late import to avoid circular

    if not settings.smtp_enabled:
        logger.info(
            f"[EMAIL] SMTP disabled — reset link for {to_email}: "
            f"{settings.frontend_url}/reset-password?token={reset_token}"
        )
        return False

    if not settings.smtp_user or not settings.smtp_password:
        logger.warning("[EMAIL] SMTP_USER or SMTP_PASSWORD not set — skipping email send")
        return False

    reset_link = f"{settings.frontend_url}/reset-password?token={reset_token}"

    subject = "Cyber Sentinel XDR — Password Reset Request"

    # Plain-text fallback
    text_body = f"""
Cyber Sentinel XDR — Account Recovery
======================================

Hello {username},

A password reset was requested for your XDR account.

Reset Link: {reset_link}

This link expires in 10 minutes and can only be used once.

If you did not request this reset, your account may be under threat.
Contact your system administrator immediately.

— Cyber Sentinel XDR Security Team
"""

    # HTML body (professional dark theme)
    html_body = f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="margin:0;padding:0;background:#050b18;font-family:'Courier New',monospace;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#050b18;padding:40px 0;">
    <tr>
      <td align="center">
        <table width="540" cellpadding="0" cellspacing="0" style="background:rgba(0,20,40,0.95);border:1px solid rgba(0,212,255,0.25);border-radius:12px;overflow:hidden;">
          <!-- Header -->
          <tr>
            <td style="background:linear-gradient(135deg,#0a1628,#162032);padding:28px 36px;border-bottom:1px solid rgba(0,212,255,0.15);">
              <p style="margin:0;font-size:11px;letter-spacing:3px;color:#6b8fa3;text-transform:uppercase;">Cyber Sentinel XDR</p>
              <p style="margin:6px 0 0;font-size:20px;font-weight:700;color:#00d4ff;letter-spacing:1px;">Account Recovery</p>
            </td>
          </tr>
          <!-- Body -->
          <tr>
            <td style="padding:32px 36px;">
              <p style="color:#94a3b8;font-size:13px;line-height:1.7;margin:0 0 20px;">Hello <strong style="color:#e0f4ff;">{username}</strong>,</p>
              <p style="color:#94a3b8;font-size:13px;line-height:1.7;margin:0 0 24px;">
                A password reset was requested for your XDR account. Click the button below to proceed.
                This link is valid for <strong style="color:#ffaa00;">10 minutes</strong> and can only be used once.
              </p>
              <!-- CTA Button -->
              <table cellpadding="0" cellspacing="0" style="margin:0 0 28px;">
                <tr>
                  <td style="background:linear-gradient(135deg,#00d4ff,#0066ff);border-radius:8px;padding:0;">
                    <a href="{reset_link}" style="display:inline-block;padding:14px 32px;color:#050b18;font-weight:900;font-size:13px;letter-spacing:2px;text-decoration:none;text-transform:uppercase;">
                      Reset Password
                    </a>
                  </td>
                </tr>
              </table>
              <!-- Link fallback -->
              <p style="color:#475569;font-size:11px;line-height:1.6;margin:0 0 8px;">Or copy this link:</p>
              <p style="background:rgba(0,212,255,0.06);border:1px solid rgba(0,212,255,0.15);border-radius:6px;padding:10px 14px;color:#00d4ff;font-size:11px;word-break:break-all;margin:0 0 28px;">{reset_link}</p>
              <!-- Security warning -->
              <div style="background:rgba(255,170,0,0.06);border:1px solid rgba(255,170,0,0.2);border-radius:8px;padding:14px 16px;">
                <p style="color:#ffaa00;font-size:11px;margin:0;letter-spacing:0.5px;">
                  &#9888; If you did not request this reset, contact your administrator immediately.
                  Your credentials may be under threat.
                </p>
              </div>
            </td>
          </tr>
          <!-- Footer -->
          <tr>
            <td style="background:rgba(0,10,25,0.6);padding:16px 36px;border-top:1px solid rgba(0,212,255,0.08);">
              <p style="color:#334155;font-size:10px;margin:0;letter-spacing:1px;">
                CYBER SENTINEL XDR &nbsp;&middot;&nbsp; SECURITY OPERATIONS CENTER &nbsp;&middot;&nbsp; DO NOT REPLY
              </p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>"""

    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"{settings.smtp_from_name} <{settings.smtp_user}>"
        msg["To"] = to_email

        msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        # Run SMTP in a thread to avoid blocking the event loop
        def _send():
            with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as server:
                server.ehlo()
                server.starttls()
                server.ehlo()
                server.login(settings.smtp_user, settings.smtp_password)
                server.sendmail(settings.smtp_user, to_email, msg.as_string())

        await asyncio.get_event_loop().run_in_executor(None, _send)
        logger.info(f"[EMAIL] Password reset email sent to {to_email}")
        return True

    except smtplib.SMTPAuthenticationError:
        logger.error(
            "[EMAIL] Gmail SMTP authentication failed — check SMTP_USER and SMTP_PASSWORD "
            "(use App Password, not your Gmail password)"
        )
        return False
    except smtplib.SMTPException as exc:
        logger.error(f"[EMAIL] SMTP error sending to {to_email}: {exc}")
        return False
    except Exception as exc:
        logger.error(f"[EMAIL] Unexpected error sending email to {to_email}: {exc}")
        return False
