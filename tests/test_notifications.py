# -*- coding: utf-8 -*-
"""
Tests for EmailShield-AI Notifications Layer.
Validates Resend email dispatching, OTP generation, and failure handling.
"""

import pytest
from unittest.mock import patch, MagicMock

from app.notifications import (
    send_password_reset_otp,
    send_analysis_summary,
    check_resend_status
)
from app.models import AnalysisResult
from app.config import Config

def test_resend_not_configured():
    """Test 11: Handling when Resend API key is omitted."""
    with patch.object(Config, "is_resend_configured", return_value=False):
        status = check_resend_status()
        assert status["status"] == "not_configured"

        success, msg = send_password_reset_otp("user@test.com", "123456")
        assert not success
        assert "not configured" in msg

def test_send_otp_success_mock():
    """Test 11: Resend OTP dispatching success."""
    with patch.object(Config, "is_resend_configured", return_value=True), \
         patch("resend.Emails.send", return_value={"id": "email_test_123"}) as mock_send:
        
        success, msg = send_password_reset_otp("analyst@company.com", "987654")
        assert success
        assert "Verification code sent" in msg
        mock_send.assert_called_once()
        sent_payload = mock_send.call_args[0][0]
        assert sent_payload["to"] == ["analyst@company.com"]
        assert "987654" in sent_payload["html"]

def test_send_analysis_summary_success_mock():
    """Test 11: Resend threat summary report delivery."""
    result = AnalysisResult(
        classification="Phishing",
        risk_score=92,
        explanation="Deceptive PayPal phishing template detected.",
        indicators=["Homograph link", "Credential harvesting"],
        recommendations=["Quarantine message", "Do not click link"],
        is_ai_generated=True,
        model_name="gemini-2.5-flash"
    )

    with patch.object(Config, "is_resend_configured", return_value=True), \
         patch("resend.Emails.send", return_value={"id": "email_rep_456"}) as mock_send:
        
        success, msg = send_analysis_summary(
            recipient_email="security@company.com",
            result=result,
            subject="Urgent Security Update",
            sender="service@paypal-spoof.com"
        )
        assert success
        assert "sent successfully" in msg
        mock_send.assert_called_once()
        html = mock_send.call_args[0][0]["html"]
        assert "PHISHING" in html
        assert "92 / 100" in html
        assert "Homograph link" in html

def test_resend_api_exception_handling():
    """Test 11: Resend API failure handling without crashing."""
    with patch.object(Config, "is_resend_configured", return_value=True), \
         patch("resend.Emails.send", side_effect=Exception("Rate limit exceeded")):
        
        success, msg = send_password_reset_otp("user@test.com", "123456")
        assert not success
        assert "Email delivery failed" in msg
