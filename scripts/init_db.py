# -*- coding: utf-8 -*-
"""
Database Migration & Setup Script for EmailShield-AI.
Executes schema initialization directly on configured TiDB Cloud MySQL or SQLite.
Run: python scripts/init_db.py
"""

import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.database import init_db, check_db_status
from app.config import Config

def main():
    print("=" * 60)
    print("  EmailShield-AI Database Schema Initialization")
    print("=" * 60)
    print(f"TiDB Host Configured: {Config.TIDB_HOST or 'None (using local fallback)'}")
    print(f"TiDB Database:        {Config.TIDB_DATABASE}")
    print(f"SQLite Fallback:      {Config.USE_SQLITE_FALLBACK}")
    print("-" * 60)
    
    try:
        init_db()
        status = check_db_status()
        print("\n[SUCCESS] Database initialized successfully!")
        print(f"Active Engine: {status.get('engine')}")
        print(f"Status:        {status.get('status')}")
    except Exception as e:
        print(f"\n[ERROR] Database initialization failed: {repr(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
