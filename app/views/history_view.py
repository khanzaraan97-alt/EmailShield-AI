# -*- coding: utf-8 -*-
"""
History view for EmailShield-AI.
Displays isolated, user-specific analysis logs with detailed inspection modals
and clear-history confirmation.
"""

from nicegui import app, ui

from app.database import get_user_analyses, clear_user_history
from app.views.layout import setup_page_header, require_auth

def register_history_routes():

    @ui.page("/history")
    def history_page():
        user = require_auth()
        if not user:
            return

        setup_page_header(current_route="/history")
        user_id = user["id"]

        with ui.column().classes("w-full max-w-6xl mx-auto p-6 gap-6"):
            # Header
            with ui.row().classes("w-full items-center justify-between pb-3 border-b border-[#1b2842]"):
                with ui.column().classes("gap-1"):
                    with ui.row().classes("items-center gap-2"):
                        ui.icon("history", size="26px").classes("text-cyan-400")
                        ui.label("Scan Telemetry & History").classes("text-2xl font-black text-white")
                    ui.label("Review previous email phishing analyses and threat evaluations.").classes("text-xs text-slate-400")

                # Clear History button
                async def confirm_clear_history():
                    with ui.dialog() as dlg, ui.card().classes("cyber-card w-96 p-6"):
                        ui.label("Clear Analysis History?").classes("text-base font-bold text-white mb-2")
                        ui.label("Are you sure you want to delete all historical analysis records? This action cannot be undone.").classes("text-xs text-slate-400 mb-6 leading-relaxed")

                        async def execute_clear():
                            dlg.close()
                            success = clear_user_history(user_id)
                            if success:
                                ui.notify("Scan history cleared successfully.", type="positive", position="top")
                                ui.navigate.to("/history")
                            else:
                                ui.notify("Failed to clear history.", type="negative", position="top")

                        with ui.row().classes("w-full justify-end gap-2"):
                            ui.button("Cancel", on_click=dlg.close).props("flat dense no-caps").classes("text-xs text-slate-400")
                            ui.button("Delete All", icon="delete", on_click=execute_clear).props("no-caps dense").classes("bg-rose-600 hover:bg-rose-500 text-white text-xs px-4 py-1.5 rounded-lg")
                    dlg.open()

                ui.button("Clear History", icon="delete_sweep", on_click=confirm_clear_history).props("outline dense no-caps").classes("text-xs text-rose-400 border-rose-500/30 hover:bg-rose-500/10 rounded-xl px-4 py-2")

            records = get_user_analyses(user_id, limit=100)

            if not records:
                with ui.card().classes("cyber-card w-full p-12 items-center justify-center text-center gap-3"):
                    ui.icon("inventory_2", size="48px").classes("text-slate-600")
                    ui.label("No Analysis Records Found").classes("text-base font-bold text-white")
                    ui.label("You have not analyzed any emails yet. Results will be logged here automatically.").classes("text-xs text-slate-400 max-w-sm")
                    ui.button("Start Analysis", icon="add", on_click=lambda: ui.navigate.to("/analyze")).props("no-caps").classes("bg-cyan-600 text-white font-semibold text-xs px-5 py-2 rounded-xl mt-2")
                return

            # Table Container
            with ui.card().classes("cyber-card w-full p-6"):
                ui.label(f"Displaying {len(records)} Historical Analysis Logs").classes("text-xs font-semibold text-slate-400 mb-4")

                with ui.column().classes("w-full gap-3"):
                    for rec in records:
                        cls_lower = rec.classification.lower()
                        if "phish" in cls_lower:
                            badge_color = "rose"
                            border_cls = "border-rose-500/20"
                        elif "suspicious" in cls_lower:
                            badge_color = "amber"
                            border_cls = "border-amber-500/20"
                        else:
                            badge_color = "emerald"
                            border_cls = "border-emerald-500/20"

                        with ui.row().classes(f"w-full p-4 rounded-xl bg-[#090f1d] border {border_cls} items-center justify-between hover:border-cyan-500/30 transition-all"):
                            # Left info
                            with ui.column().classes("gap-1 flex-1 pr-4"):
                                with ui.row().classes("items-center gap-2"):
                                    ui.badge(rec.classification, color=badge_color).props("dense").classes("text-[10px] font-bold")
                                    ui.badge(f"Risk: {rec.risk_score}/100", color=badge_color).props("outline dense").classes("text-[10px] font-mono")
                                    ui.label(rec.created_at[:19]).classes("text-[11px] text-slate-400 font-mono")

                                ui.label(rec.subject or "Untitled Email").classes("text-sm font-bold text-white")
                                with ui.row().classes("items-center gap-2 text-xs text-slate-400"):
                                    ui.label(f"Sender: {rec.sender or 'Not provided'}")
                                    if rec.email_body_preview:
                                        ui.label(f"• Preview: {rec.email_body_preview[:80]}...").classes("text-slate-400 truncate")

                            # Right Details Button
                            def show_record_modal(r=rec):
                                with ui.dialog() as dlg, ui.card().classes("cyber-card w-full max-w-xl p-6"):
                                    with ui.row().classes("w-full items-center justify-between pb-3 border-b border-[#1b2842]"):
                                        ui.label("Analysis Details").classes("text-base font-bold text-white")
                                        ui.button(icon="close", on_click=dlg.close).props("flat dense round").classes("text-slate-400")

                                    with ui.column().classes("w-full gap-3 my-3 text-xs"):
                                        with ui.row().classes("w-full justify-between"):
                                            ui.label("Classification:").classes("text-slate-400")
                                            ui.badge(r.classification, color=badge_color).props("dense")
                                        with ui.row().classes("w-full justify-between"):
                                            ui.label("Risk Score:").classes("text-slate-400")
                                            ui.label(f"{r.risk_score} / 100").classes("font-mono font-bold text-white")
                                        with ui.row().classes("w-full justify-between"):
                                            ui.label("Timestamp:").classes("text-slate-400")
                                            ui.label(r.created_at).classes("font-mono text-slate-300")

                                        ui.separator().classes("bg-[#1b2842]")
                                        ui.label("EXECUTIVE EXPLANATION").classes("font-bold text-[10px] text-slate-400 tracking-wider")
                                        ui.label(r.explanation).classes("text-slate-200 leading-relaxed p-3 rounded-lg bg-[#080e1c] border border-[#1b2842]")

                                        ui.label("DETECTED INDICATORS").classes("font-bold text-[10px] text-slate-400 tracking-wider mt-2")
                                        if r.indicators:
                                            with ui.column().classes("gap-1"):
                                                for ind in r.indicators:
                                                    with ui.row().classes("items-center gap-2 text-slate-300"):
                                                        ui.icon("fiber_manual_record", size="8px").classes("text-cyan-400")
                                                        ui.label(ind)
                                        else:
                                            ui.label("No abnormal indicators recorded.").classes("text-slate-400 italic")

                                dlg.open()

                            ui.button("Inspect Details", icon="visibility", on_click=show_record_modal).props("outline dense no-caps").classes("text-xs text-cyan-400 border-cyan-500/30 rounded-lg px-3 py-1.5")
