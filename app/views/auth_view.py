# -*- coding: utf-8 -*-
"""
Authentication views for EmailShield-AI:
Login, Registration, and Password Reset with Resend OTP.
"""

import random
import time
from nicegui import app, ui

from app.auth import authenticate_user, register_user, update_password, validate_email_format
from app.notifications import send_password_reset_otp
from app.views.layout import THEME_CSS

# In-memory OTP storage: {email: {"otp": str, "timestamp": float}}
_otp_store = {}

def register_auth_routes():
    
    @ui.page("/login")
    def login_page():
        ui.add_head_html(THEME_CSS)
        
        # If already logged in, redirect to dashboard
        try:
            logged_user = app.storage.user.get("user")
        except Exception:
            logged_user = None
        if logged_user:
            ui.navigate.to("/")
            return

        with ui.column().classes("w-full min-h-screen items-center justify-center p-4 bg-[#070c18]"):
            # Brand Header
            with ui.row().classes("items-center gap-3 mb-6"):
                with ui.row().classes("w-12 h-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 items-center justify-center"):
                    ui.icon("shield", size="28px").classes("text-cyan-400")
                with ui.column().classes("gap-0"):
                    ui.label("EmailShield-AI").classes("font-black text-2xl tracking-tight text-white")
                    ui.label("Enterprise Phishing Intelligence").classes("text-xs text-slate-400")

            # Login Card
            with ui.card().classes("cyber-card w-full max-w-md p-8"):
                ui.label("Sign In").classes("text-2xl font-bold text-white mb-1")
                ui.label("Enter your credentials to access the security console.").classes("text-xs text-slate-400 mb-6")

                email_input = ui.input(label="Email Address", placeholder="analyst@domain.com").classes("w-full mb-3").props("outlined dark")
                email_input.props('prepend-icon="mail"')

                password_input = ui.input(label="Password", placeholder="••••••••", password=True, password_toggle_button=True).classes("w-full mb-2").props("outlined dark")
                password_input.props('prepend-icon="lock"')

                with ui.row().classes("w-full justify-end mb-6"):
                    ui.link("Forgot password?", "/forgot-password").classes("text-xs text-cyan-400 hover:text-cyan-300 font-medium")

                async def handle_login():
                    email = (email_input.value or "").strip()
                    password = password_input.value or ""
                    
                    if not email or not password:
                        ui.notify("Please fill in both email and password.", type="warning", position="top")
                        return

                    success, user, message = authenticate_user(email, password)
                    if success and user:
                        # Save session
                        app.storage.user["user"] = {
                            "id": user.id,
                            "username": user.username,
                            "email": user.email,
                            "created_at": user.created_at
                        }
                        ui.notify("Welcome back! Authentication successful.", type="positive", position="top")
                        ui.navigate.to("/")
                    else:
                        ui.notify(message, type="negative", position="top")

                submit_btn = ui.button("Authenticate", icon="login", on_click=handle_login).props("no-caps").classes("w-full py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white font-bold rounded-xl shadow-lg shadow-cyan-900/30")
                email_input.on("keydown.enter", handle_login)
                password_input.on("keydown.enter", handle_login)

                with ui.row().classes("w-full justify-center items-center mt-6 gap-2 text-xs text-slate-400"):
                    ui.label("Don't have an account?")
                    ui.link("Create Account", "/register").classes("text-cyan-400 hover:text-cyan-300 font-semibold")

    @ui.page("/register")
    def register_page():
        ui.add_head_html(THEME_CSS)
        
        with ui.column().classes("w-full min-h-screen items-center justify-center p-4 bg-[#070c18]"):
            with ui.row().classes("items-center gap-3 mb-6"):
                with ui.row().classes("w-12 h-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 items-center justify-center"):
                    ui.icon("shield", size="28px").classes("text-cyan-400")
                with ui.column().classes("gap-0"):
                    ui.label("EmailShield-AI").classes("font-black text-2xl tracking-tight text-white")
                    ui.label("Register Security Analyst Account").classes("text-xs text-slate-400")

            with ui.card().classes("cyber-card w-full max-w-md p-8"):
                ui.label("Create Account").classes("text-2xl font-bold text-white mb-1")
                ui.label("Set up isolated credentials for personal email analysis.").classes("text-xs text-slate-400 mb-6")

                username_input = ui.input(label="Username", placeholder="e.g. cyber_analyst").classes("w-full mb-3").props("outlined dark")
                username_input.props('prepend-icon="person"')

                email_input = ui.input(label="Work / Personal Email", placeholder="analyst@domain.com").classes("w-full mb-3").props("outlined dark")
                email_input.props('prepend-icon="mail"')

                password_input = ui.input(label="Password (min 8 chars, 1 uppercase, 1 digit)", placeholder="••••••••", password=True, password_toggle_button=True).classes("w-full mb-3").props("outlined dark")
                password_input.props('prepend-icon="lock"')

                confirm_input = ui.input(label="Confirm Password", placeholder="••••••••", password=True, password_toggle_button=True).classes("w-full mb-6").props("outlined dark")
                confirm_input.props('prepend-icon="lock_reset"')

                async def handle_register():
                    username = (username_input.value or "").strip()
                    email = (email_input.value or "").strip()
                    password = password_input.value or ""
                    confirm = confirm_input.value or ""
                    
                    if password != confirm:
                        ui.notify("Passwords do not match.", type="negative", position="top")
                        return

                    success, msg, uid = register_user(username, email, password)
                    if success:
                        ui.notify("Account created successfully! Please sign in.", type="positive", position="top")
                        ui.navigate.to("/login")
                    else:
                        ui.notify(msg, type="negative", position="top")

                ui.button("Register Account", icon="how_to_reg", on_click=handle_register).props("no-caps").classes("w-full py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white font-bold rounded-xl shadow-lg shadow-cyan-900/30")

                with ui.row().classes("w-full justify-center items-center mt-6 gap-2 text-xs text-slate-400"):
                    ui.label("Already have an account?")
                    ui.link("Sign In", "/login").classes("text-cyan-400 hover:text-cyan-300 font-semibold")

    @ui.page("/forgot-password")
    def forgot_password_page():
        ui.add_head_html(THEME_CSS)
        
        with ui.column().classes("w-full min-h-screen items-center justify-center p-4 bg-[#070c18]"):
            with ui.row().classes("items-center gap-3 mb-6"):
                with ui.row().classes("w-12 h-12 rounded-2xl bg-cyan-500/10 border border-cyan-500/30 items-center justify-center"):
                    ui.icon("lock_reset", size="28px").classes("text-cyan-400")
                ui.label("Password Recovery").classes("font-black text-2xl tracking-tight text-white")

            with ui.card().classes("cyber-card w-full max-w-md p-8"):
                ui.label("Reset Password").classes("text-2xl font-bold text-white mb-1")
                ui.label("Enter your verified email address to receive an OTP code.").classes("text-xs text-slate-400 mb-6")

                email_input = ui.input(label="Registered Email", placeholder="analyst@domain.com").classes("w-full mb-4").props("outlined dark")
                
                otp_section = ui.column().classes("w-full gap-3")
                otp_section.set_visibility(False)

                otp_input = ui.input(label="6-Digit OTP Code", placeholder="123456").classes("w-full").props("outlined dark")
                new_pwd_input = ui.input(label="New Password", placeholder="••••••••", password=True).classes("w-full").props("outlined dark")

                async def request_otp():
                    email = (email_input.value or "").strip().lower()
                    if not validate_email_format(email):
                        ui.notify("Please enter a valid email address.", type="warning", position="top")
                        return

                    otp = str(random.randint(100000, 999999))
                    _otp_store[email] = {"otp": otp, "time": time.time()}
                    
                    success, msg = send_password_reset_otp(email, otp)
                    if success:
                        ui.notify("Verification code dispatched to your email.", type="positive", position="top")
                        otp_section.set_visibility(True)
                        email_input.disable()
                        req_btn.set_visibility(False)
                    else:
                        ui.notify(msg, type="negative", position="top")

                async def submit_reset():
                    email = (email_input.value or "").strip().lower()
                    entered_otp = (otp_input.value or "").strip()
                    new_pwd = new_pwd_input.value or ""

                    record = _otp_store.get(email)
                    if not record:
                        ui.notify("Please request an OTP code first.", type="warning", position="top")
                        return
                    if time.time() - record["time"] > 600:
                        ui.notify("OTP has expired. Please request a new one.", type="negative", position="top")
                        return
                    if entered_otp != record["otp"]:
                        ui.notify("Invalid OTP code. Please check your email.", type="negative", position="top")
                        return

                    success, msg = update_password(email, new_pwd)
                    if success:
                        _otp_store.pop(email, None)
                        ui.notify("Password successfully reset! Please sign in.", type="positive", position="top")
                        ui.navigate.to("/login")
                    else:
                        ui.notify(msg, type="negative", position="top")

                req_btn = ui.button("Send Recovery Code", icon="send", on_click=request_otp).props("no-caps").classes("w-full py-2.5 bg-cyan-600 hover:bg-cyan-500 text-white font-bold rounded-xl")
                
                with otp_section:
                    ui.button("Verify & Update Password", icon="check_circle", on_click=submit_reset).props("no-caps").classes("w-full py-2.5 bg-emerald-600 hover:bg-emerald-500 text-white font-bold rounded-xl mt-2")

                with ui.row().classes("w-full justify-center items-center mt-6"):
                    ui.link("Back to Sign In", "/login").classes("text-xs text-slate-400 hover:text-slate-200")
