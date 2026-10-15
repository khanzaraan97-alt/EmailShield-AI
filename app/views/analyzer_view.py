# -*- coding: utf-8 -*-
"""
Email Analyzer View for EmailShield-AI.
Interactive form to inspect raw email bodies, view multi-tier threat scores,
review detected indicators, and export summaries via Resend.
"""

import re
from nicegui import app, ui

from app.analyzer import analyze_email
from app.database import save_analysis
from app.notifications import send_analysis_summary, check_resend_status
from app.views.layout import setup_page_header, require_auth
from app.config import Config

def register_analyzer_routes():

    @ui.page("/analyze")
    def analyzer_page():
        user = require_auth()
        if not user:
            return

        setup_page_header(current_route="/analyze")
        user_id = user["id"]

        with ui.column().classes("w-full max-w-4xl mx-auto p-6 gap-6"):
            # Header
            with ui.row().classes("w-full items-center justify-between pb-3 border-b border-slate-700"):
                with ui.column().classes("gap-1"):
                    with ui.row().classes("items-center gap-2"):
                        ui.icon("verified_user", size="26px").classes("text-blue-400")
                        ui.label("Email Phishing Checker").classes("text-2xl font-bold text-white")
                    ui.label("Paste any suspicious email to immediately check for scams, phishing, and fake links.").classes("text-xs text-slate-400")

                with ui.row().classes("items-center gap-2"):
                    ui.badge("Real-time Scanner", color="blue").props("dense outline").classes("text-[10px]")

            # Input Card (Single Email Input Box)
            with ui.card().classes("cyber-card w-full p-6"):
                with ui.column().classes("w-full gap-2 mb-3"):
                    with ui.row().classes("w-full items-center justify-between"):
                        ui.label("Email Content").classes("text-sm font-semibold text-slate-200")
                        ui.label(f"Max size: {Config.MAX_EMAIL_SIZE_BYTES // 1024} KB").classes("text-[11px] text-slate-400")

                    email_input = ui.textarea(
                        placeholder="Paste your email here (message, headers, links, or complete text)...\n\nExample:\nFrom: service@security-alert-bank.xyz\nSubject: Urgent: Verify Account\nDear customer, your account has been locked. Verify immediately: https://bank-verify.xyz/login"
                    ).classes("w-full font-mono text-xs").props("outlined dark rows=9")

                # Sample Buttons & Primary Action
                with ui.row().classes("w-full items-center justify-between pt-1"):
                    with ui.row().classes("items-center gap-2"):
                        ui.label("Quick tests:").classes("text-xs text-slate-400")

                        async def load_phishing_sample():
                            email_input.value = (
                                "From: service-alert@paypal-security-auth.top\n"
                                "Subject: CRITICAL: Your PayPal Account Has Been Suspended Within 24 Hours\n\n"
                                "Dear Valued Customer,\n\n"
                                "We detected unauthorized login attempts from an unknown device in Moscow, Russia. "
                                "For your safety, your account access has been restricted immediately.\n\n"
                                "You must confirm your identity and update your credit card details within 24 hours "
                                "or your account will be permanently closed.\n\n"
                                "Please click here to restore your account:\n"
                                "https://paypal-verify-account.top/login-checkpoint?id=98421\n\n"
                                "Thank you,\nPayPal Security Team"
                            )
                            await run_analysis()

                        async def load_safe_sample():
                            email_input.value = (
                                "From: newsletter@python.org\n"
                                "Subject: Python Weekly Issue #624 - Tutorials and News\n\n"
                                "Hi Pythonistas,\n\n"
                                "Welcome to this week's issue of Python Weekly. In this issue, we cover the latest "
                                "features in Python 3.13, asynchronous design patterns, and open-source data science tools.\n\n"
                                "Read the full newsletter online:\n"
                                "https://python.org/community/newsletter/\n\n"
                                "Best regards,\nThe Python Software Foundation Team"
                            )
                            await run_analysis()

                        def clear_all():
                            email_input.value = ""
                            results_container.clear()

                        ui.button("Phishing Example", on_click=load_phishing_sample).props("flat dense no-caps").classes("text-xs font-semibold text-rose-300 bg-rose-950/40 hover:bg-rose-900/50 rounded-lg px-2.5 py-1 border border-rose-800/60")
                        ui.button("Safe Example", on_click=load_safe_sample).props("flat dense no-caps").classes("text-xs font-semibold text-emerald-300 bg-emerald-950/40 hover:bg-emerald-900/50 rounded-lg px-2.5 py-1 border border-emerald-800/60")
                        ui.button("Clear", on_click=clear_all).props("flat dense no-caps").classes("text-xs font-semibold text-slate-300 bg-slate-800 hover:bg-slate-700 rounded-lg px-2.5 py-1 border border-slate-700")

                    # Primary Check Button
                    analyze_btn = ui.button("Check This Email", icon="search", on_click=lambda: run_analysis()).props("no-caps").classes("bg-blue-600 hover:bg-blue-500 text-white font-bold px-6 py-2.5 rounded-xl shadow-xs")

            # Dynamic Results Container
            results_container = ui.column().classes("w-full gap-4 mt-2")

            def extract_headers_and_body(text: str):
                """Auto-extracts sender and subject if present in pasted text."""
                sender = ""
                subject = ""
                body_lines = []
                in_headers = True

                for line in text.splitlines():
                    from_m = re.match(r'^(?:From|Sender):\s*(.+)$', line, re.IGNORECASE)
                    subj_m = re.match(r'^(?:Subject):\s*(.+)$', line, re.IGNORECASE)
                    if in_headers and from_m:
                        sender = from_m.group(1).strip()
                    elif in_headers and subj_m:
                        subject = subj_m.group(1).strip()
                    elif in_headers and line.strip() == "":
                        in_headers = False
                    else:
                        body_lines.append(line)

                clean_body = "\n".join(body_lines).strip()
                if not clean_body:
                    clean_body = text.strip()
                return sender, subject, clean_body

            async def run_analysis():
                raw_text = (email_input.value or "").strip()

                if not raw_text:
                    ui.notify("Please paste an email to analyze.", type="warning", position="top")
                    return

                sender, subject, email_body = extract_headers_and_body(raw_text)

                # UI Loading State
                analyze_btn.disable()
                analyze_btn.set_text("Scanning...")
                results_container.clear()

                with results_container:
                    with ui.card().classes("cyber-card w-full p-6 items-center justify-center gap-3"):
                        ui.spinner(size="32px", color="blue")
                        ui.label("Scanning email for phishing threats and malicious links...").classes("text-xs text-slate-300 font-medium")

                # Execute analysis
                success, result, msg = await analyze_email(email_body, subject, sender)
                analyze_btn.enable()
                analyze_btn.set_text("Check This Email")
                results_container.clear()

                if not success:
                    ui.notify(msg, type="negative", position="top")
                    with results_container:
                        with ui.card().classes("cyber-card w-full p-4 border border-rose-500/50 bg-rose-950/30"):
                            ui.label("Scan Failed").classes("text-sm font-bold text-rose-300")
                            ui.label(msg).classes("text-xs text-slate-300 mt-1")
                    return

                # Persist to database under current user
                preview = email_body[:120].replace("\n", " ")
                save_analysis(
                    user_id=user_id,
                    subject=subject or "Direct Email Scan",
                    sender=sender or "Pasted Email",
                    classification=result.classification,
                    risk_score=result.risk_score,
                    explanation=result.explanation,
                    indicators=result.indicators,
                    preview=preview
                )

                # Render Results View
                with results_container:
                    render_results_card(result, subject or "Direct Email Scan", sender or "Pasted Email")

            def render_results_card(res, subj, sndr):
                # Theme styling based on classification
                cls_lower = res.classification.lower()
                if "phish" in cls_lower:
                    card_border = "border-rose-500/50"
                    bg_banner = "bg-rose-950/50 border border-rose-500/40"
                    text_badge = "text-rose-300"
                    badge_style = "bg-rose-900/60 text-rose-200 border-rose-500/60"
                    icon_name = "dangerous"
                    badge_color = "red"
                elif "suspicious" in cls_lower:
                    card_border = "border-amber-500/50"
                    bg_banner = "bg-amber-950/50 border border-amber-500/40"
                    text_badge = "text-amber-300"
                    badge_style = "bg-amber-900/60 text-amber-200 border-amber-500/60"
                    icon_name = "warning"
                    badge_color = "amber"
                else:
                    card_border = "border-emerald-500/50"
                    bg_banner = "bg-emerald-950/50 border border-emerald-500/40"
                    text_badge = "text-emerald-300"
                    badge_style = "bg-emerald-900/60 text-emerald-200 border-emerald-500/60"
                    icon_name = "check_circle"
                    badge_color = "green"

                with ui.card().classes(f"cyber-card w-full p-6 border {card_border}"):
                    # Top verdict row
                    with ui.row().classes(f"w-full items-center justify-between p-4 rounded-xl {bg_banner} mb-4"):
                        with ui.row().classes("items-center gap-3"):
                            ui.icon(icon_name, size="32px").classes(text_badge)
                            with ui.column().classes("gap-0.5"):
                                with ui.row().classes("items-center gap-2"):
                                    ui.label("RESULT:").classes("text-xs font-bold text-slate-300 uppercase tracking-wider")
                                    ui.label(res.classification.upper()).classes(f"text-sm font-extrabold px-2.5 py-0.5 rounded-md border {badge_style}")
                                ui.label(f"Engine: {res.model_name}").classes("text-xs text-slate-400")

                        # Risk Gauge Score
                        with ui.row().classes("items-center gap-3 bg-slate-900 px-4 py-2 rounded-xl border border-slate-700 shadow-2xs"):
                            with ui.column().classes("items-end gap-0"):
                                ui.label("RISK SCORE").classes("text-[10px] font-bold text-slate-400 tracking-wider")
                                ui.label(f"{res.risk_score} / 100").classes(f"text-xl font-extrabold font-mono {text_badge}")
                            ui.circular_progress(res.risk_score / 100.0, size="34px", color=badge_color, show_value=False)

                    # Executive Explanation
                    with ui.column().classes("w-full gap-1 mb-4"):
                        ui.label("THREAT SUMMARY").classes("text-[11px] font-bold text-slate-400 tracking-wider")
                        ui.label(res.explanation).classes("text-sm text-slate-200 leading-relaxed p-4 rounded-xl bg-slate-900/80 border border-slate-700")

                    # Detected Indicators Tags
                    with ui.column().classes("w-full gap-1.5 mb-4"):
                        ui.label("DETECTED THREAT SIGNALS").classes("text-[11px] font-bold text-slate-400 tracking-wider")

                        if not res.indicators:
                            ui.label("No abnormal indicators identified.").classes("text-xs text-slate-400 italic")
                        else:
                            with ui.row().classes("w-full gap-2 flex-wrap"):
                                for ind in res.indicators:
                                    with ui.row().classes("items-center gap-1.5 px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700"):
                                        ui.icon("circle", size="8px").classes(text_badge)
                                        ui.label(ind).classes("text-xs text-slate-200 font-medium")

                    # Recommended Defensive Actions
                    with ui.column().classes("w-full gap-1.5 mb-4"):
                        ui.label("RECOMMENDED PROTECTIVE ACTIONS").classes("text-[11px] font-bold text-slate-400 tracking-wider")

                        with ui.column().classes("w-full gap-1.5"):
                            for rec in res.recommendations:
                                with ui.row().classes("items-start gap-2 text-xs text-slate-200"):
                                    ui.icon("check", size="16px").classes("text-blue-400 mt-0.5")
                                    ui.label(rec).classes("leading-relaxed flex-1")

                    # Bottom Action Bar: Resend Report & Disclaimer
                    with ui.row().classes("w-full items-center justify-between pt-4 border-t border-slate-700"):
                        # Disclaimer
                        with ui.row().classes("items-center gap-2 flex-1 pr-4"):
                            ui.icon("info", size="16px").classes("text-slate-400")
                            ui.label(res.disclaimer).classes("text-[11px] text-slate-400 leading-tight")

                        # Resend Button
                        async def open_resend_dialog():
                            with ui.dialog() as dlg, ui.card().classes("cyber-card w-96 p-6"):
                                ui.label("Email Threat Report").classes("text-base font-bold text-white mb-1")
                                ui.label("Send an executive summary of this analysis to an authorized inbox.").classes("text-xs text-slate-400 mb-4")
                                
                                recipient = ui.input(label="Recipient Email", value=user.get("email", "")).classes("w-full mb-4").props("outlined dark dense")
                                
                                async def send_report():
                                    target = (recipient.value or "").strip()
                                    if not target or "@" not in target:
                                        ui.notify("Please enter a valid recipient email address.", type="warning", position="top")
                                        return
                                    
                                    dlg.close()
                                    ui.notify("Dispatching threat report...", type="info", position="top")
                                    ok, dispatch_msg = send_analysis_summary(target, res, subj, sndr)
                                    if ok:
                                        ui.notify(dispatch_msg, type="positive", position="top")
                                    else:
                                        ui.notify(dispatch_msg, type="negative", position="top")

                                with ui.row().classes("w-full justify-end gap-2"):
                                    ui.button("Cancel", on_click=dlg.close).props("flat dense no-caps").classes("text-xs text-slate-400")
                                    ui.button("Send Report", icon="send", on_click=send_report).props("no-caps dense").classes("bg-blue-600 text-white text-xs px-4 py-1.5 rounded-lg")
                            dlg.open()

                        ui.button("Email Report", icon="forward_to_inbox", on_click=open_resend_dialog).props("outline dense no-caps").classes("text-xs text-blue-400 border-blue-500/40 hover:bg-blue-500/10 rounded-xl px-4 py-2")
