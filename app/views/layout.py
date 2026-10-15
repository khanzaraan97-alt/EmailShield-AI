# -*- coding: utf-8 -*-
"""
Main cyber layout, navigation header, and visual styling for EmailShield-AI.
Dark navy and charcoal background with subtle cyan accents.
"""

from nicegui import app, ui
from typing import Optional

THEME_CSS = """
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">

<style>
    :root {
        --bg-main: #0f172a;
        --card-bg: #1e293b;
        --card-border: #334155;
        --primary-blue: #3b82f6;
        --text-main: #f8fafc;
        --text-muted: #94a3b8;
    }
    
    body {
        font-family: 'Plus Jakarta Sans', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
        background-color: #0f172a !important;
        color: #f8fafc !important;
        margin: 0;
        padding: 0;
    }

    .q-page-container {
        background-color: #0f172a !important;
    }
    
    /* Scrollbar */
    ::-webkit-scrollbar {
        width: 7px;
        height: 7px;
    }
    ::-webkit-scrollbar-track {
        background: #0f172a;
    }
    ::-webkit-scrollbar-thumb {
        background: #334155;
        border-radius: 4px;
    }
    ::-webkit-scrollbar-thumb:hover {
        background: #475569;
    }

    /* Minimal Dark Card Styles */
    .cyber-card, .modern-card {
        background-color: #1e293b !important;
        border: 1px solid #334155 !important;
        border-radius: 16px !important;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.2), 0 2px 4px -2px rgba(0, 0, 0, 0.2) !important;
        transition: border-color 0.15s ease, box-shadow 0.15s ease;
    }
    
    .cyber-card:hover, .modern-card:hover {
        border-color: #475569 !important;
    }

    /* Input overrides */
    .q-field--outlined .q-field__control {
        background-color: #0f172a !important;
        border-radius: 12px !important;
        border-color: #334155 !important;
        color: #f8fafc !important;
    }
    .q-field--outlined .q-field__control:hover {
        border-color: #475569 !important;
    }
    .q-field--outlined.q-field--focused .q-field__control {
        border-color: #3b82f6 !important;
        box-shadow: 0 0 0 2px rgba(59, 130, 246, 0.2) !important;
    }
    .q-field__native, .q-field__prefix, .q-field__suffix, .q-field__input {
        color: #f8fafc !important;
    }
    .q-field__native::placeholder, .q-field__input::placeholder {
        color: #64748b !important;
    }
    
    .font-mono {
        font-family: 'JetBrains Mono', monospace !important;
    }
</style>
"""

def setup_page_header(current_route: str = "/"):
    """Injects head styles and renders top navigation bar."""
    ui.add_head_html(THEME_CSS)
    
    try:
        user = app.storage.user.get("user")
    except Exception:
        user = None
    
    with ui.header().classes("w-full bg-[#1e293b] border-b border-slate-700 px-6 py-3 items-center justify-between z-50 shadow-sm"):
        # Left: Brand
        with ui.row().classes("items-center gap-3 cursor-pointer").on("click", lambda: ui.navigate.to("/")):
            with ui.row().classes("w-9 h-9 rounded-xl bg-blue-500/15 border border-blue-500/30 items-center justify-center"):
                ui.icon("shield", size="22px").classes("text-blue-400")
            with ui.column().classes("gap-0"):
                with ui.row().classes("items-center gap-2"):
                    ui.label("EmailShield").classes("font-extrabold text-base tracking-tight text-white")
                    ui.badge("Pro", color="blue").props("dense").classes("text-[10px] font-bold")
                ui.label("Email Security & Threat Detection").classes("text-[10px] text-slate-400 font-medium")

        # Center: Navigation Links
        with ui.row().classes("items-center gap-1 bg-slate-900/80 p-1 rounded-xl border border-slate-700"):
            nav_items = [
                ("dashboard", "Dashboard", "/"),
                ("mark_email_read", "Email Analyzer", "/analyze"),
                ("history", "Scan History", "/history"),
                ("settings", "Settings", "/settings")
            ]
            for icon, label, path in nav_items:
                is_active = (current_route == path)
                if is_active:
                    btn_cls = "text-xs font-semibold px-3 py-1.5 rounded-lg bg-blue-600 text-white shadow-xs"
                else:
                    btn_cls = "text-xs font-semibold px-3 py-1.5 rounded-lg text-slate-300 hover:text-white hover:bg-slate-800"
                    
                ui.button(label, icon=icon, on_click=lambda p=path: ui.navigate.to(p)).props("flat dense no-caps").classes(btn_cls)

        # Right: User & Status
        with ui.row().classes("items-center gap-3"):
            if user:
                with ui.row().classes("items-center gap-2 px-3 py-1 rounded-lg bg-slate-900 border border-slate-700"):
                    ui.icon("account_circle", size="18px").classes("text-slate-400")
                    ui.label(user.get("username", "User")).classes("text-xs font-semibold text-slate-200")
                    
                ui.button(icon="logout", on_click=logout_action).props("flat dense round").classes("text-slate-400 hover:text-rose-400").tooltip("Sign Out")
            else:
                ui.button("Sign In", icon="login", on_click=lambda: ui.navigate.to("/login")).props("outline dense no-caps").classes("text-xs text-blue-400 border-blue-500/50 hover:bg-blue-500/10")

def logout_action():
    try:
        app.storage.user.clear()
    except Exception:
        pass
    ui.notify("Signed out successfully.", type="positive", position="top")
    ui.navigate.to("/login")

def require_auth() -> Optional[dict]:
    """Ensures user session exists, redirects to login otherwise."""
    try:
        user = app.storage.user.get("user")
    except Exception:
        user = None
    if not user:
        ui.navigate.to("/login")
        return None
    return user
