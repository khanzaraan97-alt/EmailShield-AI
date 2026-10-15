# -*- coding: utf-8 -*-
"""
Main Application Entry Point for EmailShield-AI.
Configures NiceGUI, FastAPI health endpoints, database initialization,
and server binding for Render and local execution.
"""

import os
from nicegui import app, ui, core
from fastapi.responses import JSONResponse

from app.config import Config

# Configure session encryption secret and defaults for NiceGUI
try:
    core.app.storage.secret = Config.SECRET_KEY
    if not hasattr(core.app.config, "markdown"):
        core.app.config.markdown = False
except Exception:
    pass
from app.database import init_db, check_db_status
from app.views.auth_view import register_auth_routes
from app.views.dashboard_view import register_dashboard_routes
from app.views.analyzer_view import register_analyzer_routes
from app.views.history_view import register_history_routes
from app.views.settings_view import register_settings_routes

# 1. Initialize persistent database schema
try:
    init_db()
except Exception as e:
    print(f"[Startup] Warning during DB initialization: {repr(e)}")

# 2. Register all application views
register_auth_routes()
register_dashboard_routes()
register_analyzer_routes()
register_history_routes()
register_settings_routes()

# 3. Add Health-Check REST API Endpoint for Render and monitoring
@app.get("/health")
def health_check():
    """Health check endpoint for container / platform monitoring."""
    db_info = check_db_status()
    is_healthy = (db_info.get("status") == "connected")
    
    payload = {
        "status": "healthy" if is_healthy else "degraded",
        "application": "EmailShield-AI",
        "version": "1.0.0",
        "database": db_info.get("engine", "none"),
        "ai_configured": Config.is_gemini_configured(),
        "resend_configured": Config.is_resend_configured()
    }
    status_code = 200 if is_healthy else 503
    return JSONResponse(content=payload, status_code=status_code)

if __name__ in {"__main__", "__mp_main__"}:
    print(f"==================================================")
    print(f"  EmailShield-AI Server Starting")
    print(f"  Host: {Config.HOST} | Port: {Config.PORT}")
    print(f"  AI Model: {Config.GEMINI_MODEL}")
    print(f"  TiDB Configured: {Config.is_tidb_configured()}")
    print(f"  Resend Configured: {Config.is_resend_configured()}")
    print(f"==================================================")
    
    ui.run(
        host=Config.HOST,
        port=Config.PORT,
        title="EmailShield-AI - Email Phishing Intelligence",
        storage_secret=Config.SECRET_KEY,
        reload=False,
        show=False
    )
