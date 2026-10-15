# -*- coding: utf-8 -*-
"""
Settings and Diagnostics view for EmailShield-AI.
Exposes database health, Resend status, Gemini model configuration,
and user profile settings without leaking secrets.
"""

from nicegui import app, ui

from app.config import Config
from app.database import check_db_status
from app.notifications import check_resend_status
from app.views.layout import setup_page_header, require_auth, logout_action

def register_settings_routes():

    @ui.page("/settings")
    def settings_page():
        user = require_auth()
        if not user:
            return

        setup_page_header(current_route="/settings")
        db_info = check_db_status()
        resend_info = check_resend_status()

        with ui.column().classes("w-full max-w-5xl mx-auto p-6 gap-6"):
            # Header
            with ui.row().classes("w-full items-center justify-between pb-3 border-b border-[#1b2842]"):
                with ui.column().classes("gap-1"):
                    with ui.row().classes("items-center gap-2"):
                        ui.icon("settings", size="26px").classes("text-cyan-400")
                        ui.label("System Settings & Telemetry").classes("text-2xl font-black text-white")
                    ui.label("Manage security preferences, database connectivity, and integrations.").classes("text-xs text-slate-400")

                ui.button("Sign Out", icon="logout", on_click=logout_action).props("outline dense no-caps").classes("text-xs text-rose-400 border-rose-500/30 hover:bg-rose-500/10 rounded-xl px-4 py-2")

            # Section 1: User Profile Details
            with ui.card().classes("cyber-card w-full p-6"):
                with ui.row().classes("items-center gap-2 mb-4"):
                    ui.icon("person", size="20px").classes("text-cyan-400")
                    ui.label("Active Analyst Profile").classes("text-base font-bold text-white")

                with ui.row().classes("w-full gap-4"):
                    with ui.column().classes("flex-1 p-3 rounded-xl bg-[#090f1d] border border-[#1b2842] gap-1"):
                        ui.label("Username").classes("text-[10px] text-slate-400 uppercase tracking-wider")
                        ui.label(user.get("username", "Unknown")).classes("text-sm font-semibold text-white")

                    with ui.column().classes("flex-1 p-3 rounded-xl bg-[#090f1d] border border-[#1b2842] gap-1"):
                        ui.label("Email Address").classes("text-[10px] text-slate-400 uppercase tracking-wider")
                        ui.label(user.get("email", "Unknown")).classes("text-sm font-semibold text-white font-mono")

                    with ui.column().classes("flex-1 p-3 rounded-xl bg-[#090f1d] border border-[#1b2842] gap-1"):
                        ui.label("User ID / Namespace").classes("text-[10px] text-slate-400 uppercase tracking-wider")
                        ui.label(f"UID #{user.get('id', 0)} (Isolated)").classes("text-sm font-semibold text-cyan-400 font-mono")

            # Section 2: Infrastructure & Integration Health
            with ui.card().classes("cyber-card w-full p-6"):
                with ui.row().classes("items-center gap-2 mb-4"):
                    ui.icon("dns", size="20px").classes("text-cyan-400")
                    ui.label("Infrastructure & Integration Health").classes("text-base font-bold text-white")

                with ui.column().classes("w-full gap-3"):
                    # TiDB Cloud / Database Status
                    with ui.row().classes("w-full p-4 rounded-xl bg-[#090f1d] border border-[#1b2842] items-center justify-between"):
                        with ui.column().classes("gap-1"):
                            with ui.row().classes("items-center gap-2"):
                                ui.label("Persistent Database Engine").classes("text-xs font-bold text-white")
                                if db_info["status"] == "connected":
                                    ui.badge("Connected", color="positive").props("dense outline").classes("text-[10px]")
                                else:
                                    ui.badge("Disconnected", color="negative").props("dense outline").classes("text-[10px]")
                            ui.label(f"Active Provider: {db_info['engine']} • Host: {db_info.get('host', 'local')}").classes("text-[11px] text-slate-400")

                        with ui.button("Test Connection", icon="refresh", on_click=lambda: ui.navigate.to("/settings")).props("flat dense no-caps").classes("text-xs text-cyan-400"):
                            pass

                    # Google Gemini AI Status
                    with ui.row().classes("w-full p-4 rounded-xl bg-[#090f1d] border border-[#1b2842] items-center justify-between"):
                        with ui.column().classes("gap-1"):
                            with ui.row().classes("items-center gap-2"):
                                ui.label("Google Gemini Generative AI").classes("text-xs font-bold text-white")
                                if Config.is_gemini_configured():
                                    ui.badge("API Key Active", color="positive").props("dense outline").classes("text-[10px]")
                                else:
                                    ui.badge("Heuristic Fallback Mode", color="warning").props("dense outline").classes("text-[10px]")
                            ui.label(f"Configured Model: {Config.GEMINI_MODEL} • Zero-shot reasoning").classes("text-[11px] text-slate-400")

                    # Resend Notifications Status
                    with ui.row().classes("w-full p-4 rounded-xl bg-[#090f1d] border border-[#1b2842] items-center justify-between"):
                        with ui.column().classes("gap-1"):
                            with ui.row().classes("items-center gap-2"):
                                ui.label("Resend Email Notification Dispatcher").classes("text-xs font-bold text-white")
                                if resend_info["status"] == "ready":
                                    ui.badge("Ready", color="positive").props("dense outline").classes("text-[10px]")
                                else:
                                    ui.badge("Disabled / Key Missing", color="slate").props("dense outline").classes("text-[10px]")
                            ui.label(f"Verified Sender: {resend_info['sender']}").classes("text-[11px] text-slate-400")

            # Section 3: Privacy & Data Retention Guidelines
            with ui.card().classes("cyber-card w-full p-6"):
                with ui.row().classes("items-center gap-2 mb-2"):
                    ui.icon("security", size="20px").classes("text-cyan-400")
                    ui.label("Data Privacy & Storage Policy").classes("text-base font-bold text-white")

                ui.label(
                    "To safeguard sensitive correspondence, EmailShield-AI avoids storing raw email bodies in the persistent database by default. "
                    "Only calculated telemetry (risk ratings, threat indicator lists, subject headers, and previews) is retained for audit logging. "
                    f"Configured Raw Body Storage: {'ENABLED' if Config.STORE_EMAIL_BODY else 'DISABLED (Default Privacy Mode)'}."
                ).classes("text-xs text-slate-300 leading-relaxed")

            # Section 4: Application Information
            with ui.row().classes("w-full justify-between items-center text-xs text-slate-500 pt-2"):
                ui.label("EmailShield-AI • Standalone Phishing Intelligence Edition • v1.0.0")
                ui.label("Build Target: Render Cloud / TiDB Cloud Serverless")
