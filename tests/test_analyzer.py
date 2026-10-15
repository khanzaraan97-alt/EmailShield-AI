# -*- coding: utf-8 -*-
"""
Tests for EmailShield-AI Analyzer Engine.
Validates input sanitization, heuristic extraction, Gemini AI mocking,
and fallback execution.
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

from app.analyzer import (
    analyze_email,
    analyze_heuristics,
    extract_urls,
    analyze_links
)
from app.config import Config

@pytest.mark.asyncio
async def test_empty_email_input():
    """Test 5: Empty email input validation."""
    success, result, msg = await analyze_email("", subject="Test", sender="user@test.com")
    assert not success
    assert "Please paste an email body" in msg
    assert result.risk_score == 0

@pytest.mark.asyncio
async def test_oversized_email_input():
    """Test 3: Oversized email payload validation (> 50 KB)."""
    oversized_text = "A" * (Config.MAX_EMAIL_SIZE_BYTES + 1000)
    success, result, msg = await analyze_email(oversized_text)
    assert not success
    assert "exceeds maximum allowed size" in msg

def test_extract_urls():
    """Test URL extraction from email text."""
    text = "Visit https://paypal-security.top/login or http://192.168.1.1/admin. Do not click."
    urls = extract_urls(text)
    assert "https://paypal-security.top/login" in urls
    assert "http://192.168.1.1/admin" in urls

def test_heuristic_phishing_detection():
    """Test 7: Risk score validation and classification for obvious phishing."""
    phishing_sample = (
        "Dear Customer, your account will be suspended within 24 hours due to suspicious activity. "
        "Click here immediately to verify your credentials: https://paypal-login-update.top/auth"
    )
    data = analyze_heuristics(phishing_sample, subject="Urgent Notice", sender="service@gmail.com")
    assert data["risk_score"] >= 65
    assert data["classification"] == "Phishing"
    assert len(data["indicators"]) > 0

def test_heuristic_safe_detection():
    """Test safe classification for routine communication."""
    safe_sample = (
        "Hi John, hope you are doing well. Let's schedule the weekly project review for tomorrow afternoon. "
        "Best regards, Sarah."
    )
    data = analyze_heuristics(safe_sample, subject="Weekly Meeting", sender="sarah@company.com")
    assert data["risk_score"] <= 25
    assert data["classification"] == "Likely Safe"

@pytest.mark.asyncio
async def test_gemini_ai_success_mock():
    """Test 4: Email analysis success with mocked Gemini response."""
    mock_ai_json = (
        '{"classification": "Phishing", "risk_score": 90, '
        '"explanation": "Coercive social engineering and credential link detected.", '
        '"indicators": ["Urgency pressure", "Typosquatted domain"], '
        '"recommendations": ["Do not click links", "Quarantine message"]}'
    )
    mock_response = MagicMock()
    mock_response.text = mock_ai_json

    with patch("app.analyzer.genai_client") as mock_client:
        mock_client.aio.models.generate_content = AsyncMock(return_value=mock_response)
        with patch.object(Config, "is_gemini_configured", return_value=True):
            success, result, msg = await analyze_email(
                "Urgent: Verify your account at https://paypa1-update.xyz",
                subject="Account Alert",
                sender="alert@security-paypal.xyz"
            )
            assert success
            assert result.classification == "Phishing"
            assert result.risk_score == 90
            assert result.is_ai_generated is True
            assert "Do not click links" in result.recommendations

@pytest.mark.asyncio
async def test_gemini_ai_failure_fallback():
    """Test 6: Graceful fallback to heuristic engine when AI service fails."""
    with patch("app.analyzer.genai_client") as mock_client:
        mock_client.aio.models.generate_content = AsyncMock(side_effect=TimeoutError("AI API Timeout"))
        with patch.object(Config, "is_gemini_configured", return_value=True):
            success, result, msg = await analyze_email(
                "Urgent: Your account is locked. Click here to confirm identity: https://verify-bank.com",
                subject="Security Alert",
                sender="support@bank.com"
            )
            assert success
            # Should have fallen back to heuristic engine cleanly
            assert result.is_ai_generated is False
            assert "EmailShield-Heuristic-Engine" in result.model_name
            assert "temporarily unreachable" in result.explanation or "Heuristic" in result.explanation

def test_risk_score_bounds():
    """Test 7: Risk score is always strictly constrained within 0 and 100."""
    extreme_phishing = (
        "URGENT FINAL WARNING: Account suspended within 1 hour! "
        "Verify credentials immediately: http://192.168.0.1/login "
        "http://bit.ly/fake wire transfer bitcoin overdue invoice "
        "paypal microsoft apple netflix dear customer verify account "
    ) * 3
    data = analyze_heuristics(extreme_phishing, subject="CRITICAL NOTICE", sender="phish@gmail.com")
    assert 0 <= data["risk_score"] <= 100
