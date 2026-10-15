# -*- coding: utf-8 -*-
"""
Dashboard view for EmailShield-AI.
Displays aggregate user telemetry, educational overview of email phishing,
and quick access to recent scans and analyzer.
"""

from nicegui import app, ui

from app.database import get_analysis_stats, get_user_analyses
from app.views.layout import setup_page_header, require_auth

def register_dashboard_routes():
    
    @ui.page("/")
    def dashboard_page():
        user = require_auth()
        if not user:
            return

        setup_page_header(current_route="/")
        user_id = user["id"]
        stats = get_analysis_stats(user_id)
        recent_scans = get_user_analyses(user_id, limit=5)

        with ui.column().classes("w-full max-w-7xl mx-auto p-6 gap-6"):
            # Hero / Welcome Banner
            with ui.card().classes("cyber-card w-full p-6 relative overflow-hidden bg-gradient-to-r from-[#0d1527] to-[#121f3a]"):
                with ui.row().classes("w-full items-center justify-between"):
                    with ui.column().classes("gap-1 max-w-2xl"):
                        with ui.row().classes("items-center gap-2"):
                            ui.label(f"Welcome back, {user.get('username', 'Analyst')}").classes("text-2xl font-black text-white")
                            ui.badge("Live Telemetry", color="cyan").props("outline dense").classes("text-[10px]")
                        ui.label(
                            "EmailShield-AI monitors incoming electronic correspondence using multi-layered heuristic signal parsing "
                            "and Google Gemini cognitive intelligence to detect social engineering, brand mimicry, and credential theft."
                        ).classes("text-xs text-slate-300 leading-relaxed mt-1")

                    with ui.button("Analyze Email", icon="send", on_click=lambda: ui.navigate.to("/analyze")).props("no-caps").classes("bg-cyan-600 hover:bg-cyan-500 text-white font-bold px-5 py-2.5 rounded-xl shadow-lg shadow-cyan-900/40"):
                        pass

            # Summary Metric Cards (Real DB Values)
            with ui.row().classes("w-full gap-4"):
                # Total Analyses
                with ui.card().classes("cyber-card flex-1 p-5"):
                    with ui.row().classes("w-full items-center justify-between"):
                        ui.label("TOTAL ANALYSES").classes("text-[11px] font-bold text-slate-400 tracking-wider")
                        ui.icon("analytics", size="20px").classes("text-cyan-400")
                    ui.label(str(stats["total"])).classes("text-3xl font-extrabold text-white mt-2")
                    ui.label("All-time email scans executed").classes("text-[11px] text-slate-400 mt-1")

                # Phishing Detected
                with ui.card().classes("cyber-card flex-1 p-5 border-rose-500/30"):
                    with ui.row().classes("w-full items-center justify-between"):
                        ui.label("PHISHING DETECTED").classes("text-[11px] font-bold text-rose-400 tracking-wider")
                        ui.icon("dangerous", size="20px").classes("text-rose-400")
                    ui.label(str(stats["phishing"])).classes("text-3xl font-extrabold text-rose-400 mt-2")
                    ui.label("High-risk credential & wire threats").classes("text-[11px] text-slate-400 mt-1")

                # Suspicious Flagged
                with ui.card().classes("cyber-card flex-1 p-5 border-amber-500/30"):
                    with ui.row().classes("w-full items-center justify-between"):
                        ui.label("SUSPICIOUS FLAGGED").classes("text-[11px] font-bold text-amber-400 tracking-wider")
                        ui.icon("warning", size="20px").classes("text-amber-400")
                    ui.label(str(stats["suspicious"])).classes("text-3xl font-extrabold text-amber-400 mt-2")
                    ui.label("Mild urgency or domain anomalies").classes("text-[11px] text-slate-400 mt-1")

                # Likely Safe
                with ui.card().classes("cyber-card flex-1 p-5 border-emerald-500/30"):
                    with ui.row().classes("w-full items-center justify-between"):
                        ui.label("LIKELY SAFE").classes("text-[11px] font-bold text-emerald-400 tracking-wider")
                        ui.icon("verified_user", size="20px").classes("text-emerald-400")
                    ui.label(str(stats["safe"])).classes("text-3xl font-extrabold text-emerald-400 mt-2")
                    ui.label("No anomalous indicators detected").classes("text-[11px] text-slate-400 mt-1")

            # Two Column Section: Educational Primer & Recent Scans
            with ui.row().classes("w-full gap-6 items-start"):
                # Left: Educational Threat Breakdown
                with ui.card().classes("cyber-card flex-1 p-6"):
                    with ui.row().classes("items-center gap-2 mb-3"):
                        ui.icon("psychology", size="22px").classes("text-cyan-400")
                        ui.label("How Phishing Detection Works").classes("text-base font-bold text-white")

                    with ui.column().classes("gap-3 text-xs text-slate-300 leading-relaxed"):
                        with ui.row().classes("gap-3 items-start"):
                            ui.icon("bolt", size="18px").classes("text-amber-400 mt-0.5")
                            with ui.column().classes("gap-0.5"):
                                ui.label("Urgency & Psychological Coercion").classes("font-semibold text-white")
                                ui.label("Attackers manufacture false deadlines ('Account locked in 2 hours') to trigger panic before verification.").classes("text-slate-400")

                        with ui.row().classes("gap-3 items-start"):
                            ui.icon("link_off", size="18px").classes("text-rose-400 mt-0.5")
                            with ui.column().classes("gap-0.5"):
                                ui.label("Deceptive Links & Typosquatting").classes("font-semibold text-white")
                                ui.label("Embedded hyperlinked text differs from actual destination URLs, directing victims to cloned credential portals.").classes("text-slate-400")

                        with ui.row().classes("gap-3 items-start"):
                            ui.icon("lock", size="18px").classes("text-cyan-400 mt-0.5")
                            with ui.column().classes("gap-0.5"):
                                ui.label("Generative AI Threat Reasoning").classes("font-semibold text-white")
                                ui.label("Google Gemini evaluates cross-context intent, semantic tone, and sender domain alignment to generate reliable scores.").classes("text-slate-400")

                # Right: Recent Analyses
                with ui.card().classes("cyber-card flex-1 p-6"):
                    with ui.row().classes("w-full items-center justify-between mb-4"):
                        with ui.row().classes("items-center gap-2"):
                            ui.icon("history", size="20px").classes("text-cyan-400")
                            ui.label("Recent Activity").classes("text-base font-bold text-white")
                        ui.link("View All", "/history").classes("text-xs text-cyan-400 hover:text-cyan-300 font-semibold")

                    if not recent_scans:
                        with ui.column().classes("w-full py-8 items-center justify-center text-center gap-2"):
                            ui.icon("inbox", size="36px").classes("text-slate-600")
                            ui.label("No analyses recorded yet.").classes("text-xs text-slate-400 font-medium")
                            ui.button("Scan First Email", icon="add", on_click=lambda: ui.navigate.to("/analyze")).props("flat dense no-caps").classes("text-xs text-cyan-400")
                    else:
                        with ui.column().classes("w-full gap-2"):
                            for scan in recent_scans:
                                with ui.row().classes("w-full p-3 rounded-xl bg-[#090f1d] border border-[#1b2842] items-center justify-between"):
                                    with ui.column().classes("gap-0.5 flex-1 pr-3"):
                                        ui.label(scan.subject or "Untitled Email").classes("text-xs font-semibold text-white truncate max-w-xs")
                                        ui.label(f"{scan.sender or 'Unknown sender'} • {scan.created_at[:16]}").classes("text-[10px] text-slate-400 font-mono")
                                    
                                    # Badge
                                    cls_name = scan.classification
                                    color = "rose" if "phish" in cls_name.lower() else ("amber" if "suspicious" in cls_name.lower() else "emerald")
                                    with ui.row().classes("items-center gap-2"):
                                        ui.badge(f"{scan.risk_score}/100", color=color).props("outline dense").classes("text-[10px] font-mono")
                                        ui.badge(cls_name, color=color).props("dense").classes("text-[10px] font-bold")
