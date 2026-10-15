# -*- coding: utf-8 -*-
"""
Notification service for EmailShield-AI using Resend.
Provides secure delivery of threat analysis summaries and password reset OTPs.
Never forwards raw user email bodies to external parties.
"""

from typing import Tuple, Dict, Any, Optional
import resend

from app.config import Config
from app.models import AnalysisResult

if Config.is_resend_configured():
    resend.api_key = Config.RESEND_API_KEY

def send_password_reset_otp(recipient_email: str, otp: str) -> Tuple[bool, str]:
    """Sends a one-time verification code for password reset via Resend."""
    if not Config.is_resend_configured():
        return False, "Email notification service is not configured (RESEND_API_KEY missing)."

    try:
        html_content = f"""
        <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0b1120; color: #f8fafc; padding: 35px; border-radius: 12px; max-width: 500px; margin: 0 auto; border: 1px solid #1e293b;">
            <div style="border-bottom: 1px solid #1e293b; padding-bottom: 15px; margin-bottom: 20px;">
                <h2 style="color: #38bdf8; margin: 0; font-size: 20px;">EmailShield-AI Security</h2>
                <span style="color: #64748b; font-size: 12px;">Threat Intelligence Platform</span>
            </div>
            <p style="color: #94a3b8; font-size: 14px;">You requested a one-time verification code to reset your account password:</p>
            <div style="background-color: #0f172a; border: 1px dashed #38bdf8; border-radius: 8px; padding: 18px; text-align: center; margin: 20px 0;">
                <span style="font-size: 32px; font-weight: 800; letter-spacing: 6px; color: #38bdf8; font-family: monospace;">{otp}</span>
            </div>
            <p style="color: #94a3b8; font-size: 13px;">This security OTP will expire in <strong>10 minutes</strong>.</p>
            <p style="color: #64748b; font-size: 11px; margin-top: 25px; border-top: 1px solid #1e293b; padding-top: 12px;">
                If you did not initiate this request, you can safely disregard this email. Your password will remain unchanged.
            </p>
        </div>
        """

        params = {
            "from": Config.RESEND_FROM_EMAIL,
            "to": [recipient_email],
            "subject": "Verification Code - EmailShield-AI Password Reset",
            "html": html_content
        }

        response = resend.Emails.send(params)
        print(f"[Notifications] OTP email dispatched to {recipient_email}, ID: {response.get('id', 'sent')}")
        return True, "Verification code sent to your email."
    except Exception as e:
        print(f"[Notifications] Failed to send OTP email: {repr(e)}")
        return False, f"Email delivery failed: {str(e)}"

def send_analysis_summary(
    recipient_email: str,
    result: AnalysisResult,
    subject: Optional[str] = None,
    sender: Optional[str] = None
) -> Tuple[bool, str]:
    """
    Emails an executive threat report summary to a specified recipient.
    Only includes structured findings and advice, NEVER the raw email body.
    """
    if not Config.is_resend_configured():
        return False, "Resend API key is not configured in environment variables."

    # Determine badge color
    if result.classification == "Phishing":
        badge_color = "#ef4444"
        bg_badge = "#450a0a"
    elif result.classification == "Suspicious":
        badge_color = "#f59e0b"
        bg_badge = "#451a03"
    else:
        badge_color = "#10b981"
        bg_badge = "#022c22"

    indicators_html = "".join([f"<li style='margin-bottom: 6px; color: #cbd5e1;'>{ind}</li>" for ind in result.indicators])
    recommendations_html = "".join([f"<li style='margin-bottom: 6px; color: #cbd5e1;'>{rec}</li>" for rec in result.recommendations])

    html_content = f"""
    <div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0b1120; color: #f8fafc; padding: 30px; border-radius: 12px; max-width: 600px; margin: 0 auto; border: 1px solid #1e293b;">
        <div style="border-bottom: 1px solid #1e293b; padding-bottom: 15px; margin-bottom: 20px;">
            <h2 style="color: #38bdf8; margin: 0; font-size: 22px;">EmailShield-AI Threat Report</h2>
            <span style="color: #64748b; font-size: 12px;">Automated Email Security Analysis Summary</span>
        </div>

        <table style="width: 100%; border-collapse: collapse; margin-bottom: 20px;">
            <tr>
                <td style="padding: 8px 0; color: #94a3b8; font-size: 13px;">Subject:</td>
                <td style="padding: 8px 0; color: #f1f5f9; font-weight: 600; font-size: 14px;">{subject or 'Not provided'}</td>
            </tr>
            <tr>
                <td style="padding: 8px 0; color: #94a3b8; font-size: 13px;">Sender Claimed:</td>
                <td style="padding: 8px 0; color: #f1f5f9; font-size: 13px; font-family: monospace;">{sender or 'Not provided'}</td>
            </tr>
            <tr>
                <td style="padding: 8px 0; color: #94a3b8; font-size: 13px;">Classification:</td>
                <td style="padding: 8px 0;">
                    <span style="display: inline-block; padding: 4px 12px; border-radius: 6px; font-weight: 700; font-size: 13px; background-color: {bg_badge}; color: {badge_color}; border: 1px solid {badge_color};">
                        {result.classification.upper()}
                    </span>
                </td>
            </tr>
            <tr>
                <td style="padding: 8px 0; color: #94a3b8; font-size: 13px;">Risk Score:</td>
                <td style="padding: 8px 0; color: {badge_color}; font-size: 18px; font-weight: 800;">
                    {result.risk_score} / 100
                </td>
            </tr>
        </table>

        <div style="background-color: #111827; border: 1px solid #1e293b; border-radius: 8px; padding: 15px; margin-bottom: 20px;">
            <h4 style="color: #38bdf8; margin: 0 0 8px 0; font-size: 14px;">Executive Verdict</h4>
            <p style="color: #cbd5e1; font-size: 13px; margin: 0; line-height: 1.5;">{result.explanation}</p>
        </div>

        <div style="margin-bottom: 20px;">
            <h4 style="color: #f1f5f9; margin: 0 0 10px 0; font-size: 14px;">Key Threat Indicators</h4>
            <ul style="margin: 0; padding-left: 20px; font-size: 13px;">
                {indicators_html or "<li style='color: #64748b;'>No critical threat indicators flagged.</li>"}
            </ul>
        </div>

        <div style="margin-bottom: 25px;">
            <h4 style="color: #f1f5f9; margin: 0 0 10px 0; font-size: 14px;">Recommended Actions</h4>
            <ul style="margin: 0; padding-left: 20px; font-size: 13px;">
                {recommendations_html}
            </ul>
        </div>

        <div style="border-top: 1px solid #1e293b; padding-top: 15px; font-size: 11px; color: #64748b; line-height: 1.4;">
            <strong>Advisory Disclaimer:</strong> {result.disclaimer}
        </div>
    </div>
    """

    try:
        params = {
            "from": Config.RESEND_FROM_EMAIL,
            "to": [recipient_email],
            "subject": f"Security Analysis: [{result.classification}] - {subject or 'Email Evaluation'}",
            "html": html_content
        }
        res = resend.Emails.send(params)
        print(f"[Notifications] Analysis report sent to {recipient_email}, ID: {res.get('id', 'sent')}")
        return True, "Analysis summary sent successfully via Resend."
    except Exception as e:
        print(f"[Notifications] Resend delivery error: {repr(e)}")
        return False, f"Failed to deliver report: {str(e)}"

def check_resend_status() -> Dict[str, Any]:
    """Returns non-sensitive Resend configuration status."""
    is_ready = Config.is_resend_configured()
    return {
        "status": "ready" if is_ready else "not_configured",
        "sender": Config.RESEND_FROM_EMAIL if is_ready else "None",
        "key_present": bool(Config.RESEND_API_KEY)
    }
