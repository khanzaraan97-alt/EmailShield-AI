# -*- coding: utf-8 -*-
"""
Database abstraction layer for EmailShield-AI.
Supports TiDB Cloud Serverless MySQL with connection pooling,
with resilient SQLite fallback for local development and offline testing.
"""

import json
import sqlite3
import threading
from typing import Optional, List, Dict, Any, Tuple
from datetime import datetime

import mysql.connector
from mysql.connector import pooling

from app.config import Config
from app.models import AnalysisRecord

_mysql_pool: Optional[pooling.MySQLConnectionPool] = None
_db_lock = threading.Lock()
_active_engine: str = "unknown"
_tidb_failed: bool = False

def _get_mysql_pool() -> Optional[pooling.MySQLConnectionPool]:
    global _mysql_pool, _tidb_failed
    if not Config.is_tidb_configured() or _tidb_failed:
        return None
        
    with _db_lock:
        if _mysql_pool is None and not _tidb_failed:
            try:
                # TiDB Cloud connection settings
                pool_config = {
                    "pool_name": "emailshield_tidb_pool",
                    "pool_size": 5,
                    "pool_reset_session": True,
                    "host": Config.TIDB_HOST,
                    "port": Config.TIDB_PORT,
                    "user": Config.TIDB_USER,
                    "password": Config.TIDB_PASSWORD,
                    "database": Config.TIDB_DATABASE,
                    "ssl_disabled": False,
                }
                _mysql_pool = pooling.MySQLConnectionPool(**pool_config)
            except Exception as e:
                print(f"[Database] TiDB Pool initialization failed (switching to SQLite): {repr(e)}")
                _tidb_failed = True
                return None
    return _mysql_pool

class DBConnection:
    """Wrapper that abstracts MySQL and SQLite connections."""
    def __init__(self, conn, engine: str):
        self.conn = conn
        self.engine = engine

    def cursor(self):
        return self.conn.cursor()

    def commit(self):
        self.conn.commit()

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass

def get_connection() -> DBConnection:
    """Acquires a database connection (TiDB Cloud MySQL if configured, else SQLite)."""
    global _active_engine, _tidb_failed
    
    # 1. Attempt TiDB Cloud MySQL
    if Config.is_tidb_configured() and not _tidb_failed:
        pool = _get_mysql_pool()
        if pool:
            try:
                raw_conn = pool.get_connection()
                _active_engine = "TiDB Cloud (MySQL)"
                return DBConnection(raw_conn, "mysql")
            except Exception as e:
                print(f"[Database] Could not get connection from TiDB pool: {repr(e)}")
                _tidb_failed = True
        
        # Direct fallback attempt if pool failed
        if not _tidb_failed:
            try:
                raw_conn = mysql.connector.connect(
                    host=Config.TIDB_HOST,
                    port=Config.TIDB_PORT,
                    user=Config.TIDB_USER,
                    password=Config.TIDB_PASSWORD,
                    database=Config.TIDB_DATABASE,
                    ssl_disabled=False
                )
                _active_engine = "TiDB Cloud (MySQL)"
                return DBConnection(raw_conn, "mysql")
            except Exception as e:
                print(f"[Database] Direct TiDB connection failed: {repr(e)}")
                _tidb_failed = True

    # 2. Resilient SQLite fallback
    if Config.USE_SQLITE_FALLBACK:
        _active_engine = "SQLite (Local Fallback)"
        conn = sqlite3.connect(str(Config.SQLITE_PATH), timeout=15)
        conn.row_factory = sqlite3.Row
        return DBConnection(conn, "sqlite")
        
    raise RuntimeError("No database available. Please configure TiDB Cloud credentials in .env")

def init_db():
    """Initializes schema for users and email_analyses tables."""
    conn = get_connection()
    cur = conn.cursor()
    
    if conn.engine == "mysql":
        # MySQL / TiDB schema
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(64) NOT NULL UNIQUE,
                email VARCHAR(120) NOT NULL UNIQUE,
                password VARCHAR(256) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS email_analyses (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                subject VARCHAR(255) NULL,
                sender VARCHAR(255) NULL,
                classification VARCHAR(32) NOT NULL,
                risk_score INT NOT NULL,
                explanation TEXT NOT NULL,
                indicators TEXT NOT NULL,
                email_body_preview VARCHAR(255) NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_user_history (user_id, created_at DESC)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
        """)
    else:
        # SQLite schema
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP NULL
            );
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS email_analyses (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                subject TEXT NULL,
                sender TEXT NULL,
                classification TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                explanation TEXT NOT NULL,
                indicators TEXT NOT NULL,
                email_body_preview TEXT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)
        
    conn.commit()
    cur.close()
    conn.close()
    print(f"[Database] Schema verified on {_active_engine}")

def save_analysis(
    user_id: int,
    subject: Optional[str],
    sender: Optional[str],
    classification: str,
    risk_score: int,
    explanation: str,
    indicators: List[str],
    preview: Optional[str] = None
) -> Optional[int]:
    """Persists an analysis record bound to the authenticated user."""
    conn = get_connection()
    cur = conn.cursor()
    indicators_json = json.dumps(indicators)
    inserted_id = None
    
    try:
        if conn.engine == "mysql":
            cur.execute("""
                INSERT INTO email_analyses 
                (user_id, subject, sender, classification, risk_score, explanation, indicators, email_body_preview)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (user_id, subject, sender, classification, risk_score, explanation, indicators_json, preview))
            inserted_id = cur.lastrowid
        else:
            cur.execute("""
                INSERT INTO email_analyses 
                (user_id, subject, sender, classification, risk_score, explanation, indicators, email_body_preview)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (user_id, subject, sender, classification, risk_score, explanation, indicators_json, preview))
            inserted_id = cur.lastrowid
            
        conn.commit()
    except Exception as e:
        print(f"[Database] Error saving analysis: {repr(e)}")
    finally:
        cur.close()
        conn.close()
        
    return inserted_id

def get_user_analyses(user_id: int, limit: int = 50) -> List[AnalysisRecord]:
    """Retrieves analysis records strictly for the requested user."""
    conn = get_connection()
    cur = conn.cursor()
    records = []
    
    try:
        query = """
            SELECT id, user_id, subject, sender, classification, risk_score, explanation, indicators, created_at, email_body_preview
            FROM email_analyses
            WHERE user_id = {ph}
            ORDER BY created_at DESC
            LIMIT {limit_ph}
        """
        if conn.engine == "mysql":
            cur.execute(query.format(ph="%s", limit_ph="%s"), (user_id, limit))
        else:
            cur.execute(query.format(ph="?", limit_ph="?"), (user_id, limit))
            
        rows = cur.fetchall()
        for r in rows:
            # Handle tuple or sqlite3.Row
            ind_raw = r[7] if isinstance(r, tuple) else r["indicators"]
            try:
                ind_list = json.loads(ind_raw) if ind_raw else []
            except Exception:
                ind_list = [ind_raw] if ind_raw else []
                
            rec = AnalysisRecord(
                id=r[0] if isinstance(r, tuple) else r["id"],
                user_id=r[1] if isinstance(r, tuple) else r["user_id"],
                subject=r[2] if isinstance(r, tuple) else r["subject"],
                sender=r[3] if isinstance(r, tuple) else r["sender"],
                classification=r[4] if isinstance(r, tuple) else r["classification"],
                risk_score=r[5] if isinstance(r, tuple) else r["risk_score"],
                explanation=r[6] if isinstance(r, tuple) else r["explanation"],
                indicators=ind_list,
                created_at=str(r[8] if isinstance(r, tuple) else r["created_at"]),
                email_body_preview=r[9] if isinstance(r, tuple) else r["email_body_preview"]
            )
            records.append(rec)
    except Exception as e:
        print(f"[Database] Error fetching user history: {repr(e)}")
    finally:
        cur.close()
        conn.close()
        
    return records

def get_analysis_stats(user_id: int) -> Dict[str, int]:
    """Returns aggregated analysis counts strictly for the specified user."""
    conn = get_connection()
    cur = conn.cursor()
    stats = {"total": 0, "phishing": 0, "suspicious": 0, "safe": 0}
    
    try:
        query = "SELECT classification, COUNT(*) FROM email_analyses WHERE user_id = {ph} GROUP BY classification"
        if conn.engine == "mysql":
            cur.execute(query.format(ph="%s"), (user_id,))
        else:
            cur.execute(query.format(ph="?"), (user_id,))
            
        rows = cur.fetchall()
        for r in rows:
            cls_name = (r[0] if isinstance(r, tuple) else r["classification"]).lower()
            count = r[1] if isinstance(r, tuple) else r[1]
            stats["total"] += count
            if "phish" in cls_name:
                stats["phishing"] += count
            elif "suspicious" in cls_name:
                stats["suspicious"] += count
            else:
                stats["safe"] += count
    except Exception as e:
        print(f"[Database] Error fetching stats: {repr(e)}")
    finally:
        cur.close()
        conn.close()
        
    return stats

def clear_user_history(user_id: int) -> bool:
    """Deletes all analysis history for the current user."""
    conn = get_connection()
    cur = conn.cursor()
    success = False
    try:
        query = "DELETE FROM email_analyses WHERE user_id = {ph}"
        if conn.engine == "mysql":
            cur.execute(query.format(ph="%s"), (user_id,))
        else:
            cur.execute(query.format(ph="?"), (user_id,))
        conn.commit()
        success = True
    except Exception as e:
        print(f"[Database] Error clearing history: {repr(e)}")
    finally:
        cur.close()
        conn.close()
    return success

def check_db_status() -> Dict[str, Any]:
    """Provides non-sensitive database diagnostic status."""
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.fetchone()
        cur.close()
        engine_type = "TiDB Cloud Serverless (MySQL)" if conn.engine == "mysql" else "Local SQLite (Development Fallback)"
        conn.close()
        return {
            "status": "connected",
            "engine": engine_type,
            "host": Config.TIDB_HOST if conn.engine == "mysql" else "local_disk",
            "database": Config.TIDB_DATABASE if conn.engine == "mysql" else "emailshield_local.db",
            "ssl_active": True if conn.engine == "mysql" else False
        }
    except Exception as e:
        return {
            "status": "disconnected",
            "engine": "None",
            "error": str(e)
        }
