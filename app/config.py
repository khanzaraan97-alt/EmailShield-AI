# -*- coding: utf-8 -*-
"""
Configuration management for EmailShield-AI.
Loads environment variables and exposes typed settings.
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Base directory of the EmailShield-AI project
BASE_DIR = Path(__file__).resolve().parent.parent

# Load .env file from project root if it exists
ENV_PATH = BASE_DIR / ".env"
if ENV_PATH.exists():
    load_dotenv(dotenv_path=ENV_PATH)
else:
    load_dotenv()

class Config:
    # Server
    HOST: str = os.environ.get("HOST", "0.0.0.0")
    PORT: int = int(os.environ.get("PORT", "8080"))
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "emailshield-default-session-secret-key-32b")
    
    # Gemini AI
    GEMINI_API_KEY: str = os.environ.get("GEMINI_API_KEY", "").strip()
    GEMINI_MODEL: str = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash").strip()
    
    # TiDB Cloud MySQL
    TIDB_HOST: str = os.environ.get("TIDB_HOST", "").strip()
    TIDB_PORT: int = int(os.environ.get("TIDB_PORT", "4000"))
    TIDB_USER: str = os.environ.get("TIDB_USER", "").strip()
    TIDB_PASSWORD: str = os.environ.get("TIDB_PASSWORD", os.environ.get("DB_PASSWORD", "")).strip()
    TIDB_DATABASE: str = os.environ.get("TIDB_DATABASE", "test").strip()
    TIDB_SSL_MODE: str = os.environ.get("TIDB_SSL_MODE", "VERIFY_IDENTITY").strip()
    USE_SQLITE_FALLBACK: bool = os.environ.get("USE_SQLITE_FALLBACK", "true").lower() in ("true", "1", "yes")
    SQLITE_PATH: Path = BASE_DIR / "emailshield_local.db"
    
    # Resend Email Service
    RESEND_API_KEY: str = os.environ.get("RESEND_API_KEY", "").strip()
    RESEND_FROM_EMAIL: str = os.environ.get("RESEND_FROM_EMAIL", "onboarding@resend.dev").strip()
    
    # Privacy & Limits
    STORE_EMAIL_BODY: bool = os.environ.get("STORE_EMAIL_BODY", "false").lower() in ("true", "1", "yes")
    MAX_EMAIL_SIZE_BYTES: int = int(os.environ.get("MAX_EMAIL_SIZE_BYTES", "51200")) # 50 KB
    
    @classmethod
    def is_tidb_configured(cls) -> bool:
        """Returns True if minimum valid TiDB credentials are provided."""
        return bool(
            cls.TIDB_HOST
            and cls.TIDB_USER
            and cls.TIDB_PASSWORD
            and "your_" not in cls.TIDB_USER
            and "your_" not in cls.TIDB_PASSWORD
            and not cls.TIDB_USER.startswith("<")
        )

    @classmethod
    def is_gemini_configured(cls) -> bool:
        """Returns True if real Gemini API key is set."""
        return bool(
            cls.GEMINI_API_KEY
            and "your_gemini" not in cls.GEMINI_API_KEY
            and not cls.GEMINI_API_KEY.startswith("your_")
            and len(cls.GEMINI_API_KEY) > 20
        )

    @classmethod
    def is_resend_configured(cls) -> bool:
        """Returns True if real Resend API key is set."""
        return bool(
            cls.RESEND_API_KEY
            and "your_resend" not in cls.RESEND_API_KEY
            and not cls.RESEND_API_KEY.startswith("re_your_")
            and len(cls.RESEND_API_KEY) > 15
        )
