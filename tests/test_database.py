# -*- coding: utf-8 -*-
"""
Tests for EmailShield-AI Database Layer.
Validates persistence, stats calculation, user data isolation,
and failure handling.
"""

import pytest
import sqlite3
from unittest.mock import patch

from app.database import (
    init_db,
    save_analysis,
    get_user_analyses,
    get_analysis_stats,
    clear_user_history,
    check_db_status
)
from app.auth import register_user, authenticate_user

@pytest.fixture(autouse=True)
def setup_test_db(tmp_path, monkeypatch):
    """Configures a temporary SQLite database for test isolation."""
    test_db = tmp_path / "test_emailshield.db"
    monkeypatch.setattr("app.config.Config.SQLITE_PATH", test_db)
    monkeypatch.setattr("app.config.Config.TIDB_HOST", "") # Force SQLite during tests
    init_db()
    yield test_db

def test_database_initialization():
    """Test 8: Database initialization and health check."""
    status = check_db_status()
    assert status["status"] == "connected"
    assert "SQLite" in status["engine"]

def test_user_registration_and_authentication():
    """Test registration and bcrypt verification."""
    success, msg, uid = register_user("testanalyst", "analyst@cyber.org", "SecurePassword123!")
    assert success
    assert uid is not None

    # Authenticate with correct credentials
    auth_ok, user, auth_msg = authenticate_user("analyst@cyber.org", "SecurePassword123!")
    assert auth_ok
    assert user.username == "testanalyst"

    # Authenticate with wrong password
    auth_fail, _, _ = authenticate_user("analyst@cyber.org", "WrongPassword!")
    assert not auth_fail

def test_save_and_retrieve_analysis():
    """Test 9: Saving and retrieving analysis records."""
    reg_ok, _, uid = register_user("user_a", "usera@test.com", "Password123!")
    assert reg_ok

    inserted_id = save_analysis(
        user_id=uid,
        subject="Invoice Overdue",
        sender="billing@scam.com",
        classification="Phishing",
        risk_score=85,
        explanation="Wire transfer scam detected.",
        indicators=["Urgent demand", "Wire transfer request"],
        preview="Please pay immediately."
    )
    assert inserted_id is not None

    records = get_user_analyses(uid)
    assert len(records) == 1
    assert records[0].classification == "Phishing"
    assert records[0].risk_score == 85
    assert "Urgent demand" in records[0].indicators

def test_user_data_isolation():
    """Test 10: Strict user data isolation between accounts."""
    _, _, uid_1 = register_user("user_alpha", "alpha@test.com", "Password123!")
    _, _, uid_2 = register_user("user_beta", "beta@test.com", "Password123!")

    # User 1 performs scan
    save_analysis(
        user_id=uid_1,
        subject="Alpha Secret Email",
        sender="sender@alpha.com",
        classification="Likely Safe",
        risk_score=10,
        explanation="Benign internal memo.",
        indicators=[]
    )

    # User 2 performs scan
    save_analysis(
        user_id=uid_2,
        subject="Beta Phishing Email",
        sender="hacker@beta.com",
        classification="Phishing",
        risk_score=95,
        explanation="Credential theft attempt.",
        indicators=["Password harvesting"]
    )

    # Verify User 1 cannot see User 2's records
    records_1 = get_user_analyses(uid_1)
    assert len(records_1) == 1
    assert records_1[0].subject == "Alpha Secret Email"
    assert records_1[0].classification == "Likely Safe"

    # Verify User 2 cannot see User 1's records
    records_2 = get_user_analyses(uid_2)
    assert len(records_2) == 1
    assert records_2[0].subject == "Beta Phishing Email"
    assert records_2[0].classification == "Phishing"

def test_clear_user_history():
    """Test clearing history for specific user."""
    _, _, uid = register_user("user_clear", "clear@test.com", "Password123!")
    save_analysis(uid, "Test", "test@test.com", "Suspicious", 45, "Explanation", [])
    
    assert len(get_user_analyses(uid)) == 1
    cleared = clear_user_history(uid)
    assert cleared
    assert len(get_user_analyses(uid)) == 0

def test_database_connection_failure_handling():
    """Test 8: Database connection failure returns clean status dictionary."""
    with patch("app.database.get_connection", side_effect=Exception("Database unreachable")):
        status = check_db_status()
        assert status["status"] == "disconnected"
        assert "Database unreachable" in status["error"]
