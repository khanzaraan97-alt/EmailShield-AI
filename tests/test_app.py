# -*- coding: utf-8 -*-
"""
Tests for EmailShield-AI Server Startup and Health Endpoint.
Validates FastAPI health route, application metadata, and configuration integrity.
"""

import pytest
from starlette.testclient import TestClient
from nicegui import app, core

import main
from app.config import Config

# Ensure NiceGUI run configuration is initialized for test client
if not core.app.config.has_run_config:
    core.app.config.add_run_config(
        reload=False,
        title="EmailShield-AI",
        viewport="width=device-width, initial-scale=1",
        favicon=None,
        dark=False,
        language="en-US",
        binding_refresh_interval=0.1,
        reconnect_timeout=3.0,
        message_history_length=1000,
        tailwind=True,
        unocss=None,
        prod_js=True,
        show_welcome_message=False,
        markdown=False,
    )

client = TestClient(app)

def test_health_check_endpoint():
    """Test 1 & 12: Health-check endpoint returns 200 OK and valid JSON telemetry."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["application"] == "EmailShield-AI"
    assert data["version"] == "1.0.0"
    assert "database" in data
    assert "ai_configured" in data
    assert "resend_configured" in data

def test_main_page_rendering():
    """Test 2: Main application and login page rendering."""
    # Test login page HTML
    response = client.get("/login")
    assert response.status_code == 200
    assert "EmailShield" in response.text
