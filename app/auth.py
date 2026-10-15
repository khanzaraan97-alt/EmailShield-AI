# -*- coding: utf-8 -*-
"""
Authentication and User Management for EmailShield-AI.
Secured with bcrypt password hashing and parameterized queries.
"""

import re
from typing import Optional, Tuple
import bcrypt

from app.database import get_connection
from app.models import User

def validate_email_format(email: str) -> bool:
    """Validates standard email syntax."""
    if not email or len(email) > 120:
        return False
    pattern = r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'
    return bool(re.match(pattern, email.strip()))

def validate_password_strength(password: str) -> Tuple[bool, str]:
    """Ensures password meets standard security strength requirements."""
    if not password or len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter (A-Z)."
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter (a-z)."
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one digit (0-9)."
    return True, ""

def hash_password(password: str) -> str:
    """Hashes a plaintext password with bcrypt and automatic salt."""
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plaintext password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False

def register_user(username: str, email: str, password: str) -> Tuple[bool, str, Optional[int]]:
    """Registers a new user account with hashed credentials."""
    username = (username or "").strip()
    email = (email or "").strip().lower()
    
    if not username or len(username) < 3:
        return False, "Username must be at least 3 characters long.", None
        
    if not validate_email_format(email):
        return False, "Please enter a valid email address.", None
        
    is_valid_pwd, pwd_err = validate_password_strength(password)
    if not is_valid_pwd:
        return False, pwd_err, None

    conn = get_connection()
    cur = conn.cursor()
    
    try:
        # Check if username or email already exists
        query_check = "SELECT id, email, username FROM users WHERE email = {ph} OR username = {ph}"
        if conn.engine == "mysql":
            cur.execute(query_check.format(ph="%s"), (email, username))
        else:
            cur.execute(query_check.format(ph="?"), (email, username))
            
        existing = cur.fetchone()
        if existing:
            return False, "An account with this email or username already exists.", None
            
        pwd_hash = hash_password(password)
        query_insert = "INSERT INTO users (username, email, password) VALUES ({ph}, {ph}, {ph})"
        if conn.engine == "mysql":
            cur.execute(query_insert.format(ph="%s"), (username, email, pwd_hash))
            uid = cur.lastrowid
        else:
            cur.execute(query_insert.format(ph="?"), (username, email, pwd_hash))
            uid = cur.lastrowid
            
        conn.commit()
        return True, "Account registered successfully.", uid
    except Exception as e:
        return False, f"Registration failed: {str(e)}", None
    finally:
        cur.close()
        conn.close()

def authenticate_user(email: str, password: str) -> Tuple[bool, Optional[User], str]:
    """Authenticates user credentials and returns User object on success."""
    email = (email or "").strip().lower()
    password = password or ""
    
    if not email or not password:
        return False, None, "Email and password are required."
        
    conn = get_connection()
    cur = conn.cursor()
    
    try:
        query = "SELECT id, username, email, password, created_at, last_login FROM users WHERE email = {ph}"
        if conn.engine == "mysql":
            cur.execute(query.format(ph="%s"), (email,))
        else:
            cur.execute(query.format(ph="?"), (email,))
            
        row = cur.fetchone()
        if not row:
            return False, None, "Invalid email or password."
            
        uid = row[0] if isinstance(row, tuple) else row["id"]
        uname = row[1] if isinstance(row, tuple) else row["username"]
        uemail = row[2] if isinstance(row, tuple) else row["email"]
        upwd = row[3] if isinstance(row, tuple) else row["password"]
        ucreate = str(row[4] if isinstance(row, tuple) else row["created_at"])
        ulast = str(row[5] if isinstance(row, tuple) else row["last_login"])
        
        if not verify_password(password, upwd):
            return False, None, "Invalid email or password."
            
        # Update last login timestamp
        try:
            update_q = "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = {ph}"
            if conn.engine == "mysql":
                cur.execute(update_q.format(ph="%s"), (uid,))
            else:
                cur.execute(update_q.format(ph="?"), (uid,))
            conn.commit()
        except Exception:
            pass
            
        user = User(
            id=uid,
            username=uname,
            email=uemail,
            password_hash=upwd,
            created_at=ucreate,
            last_login=ulast
        )
        return True, user, "Login successful."
    except Exception as e:
        return False, None, f"Authentication error: {str(e)}"
    finally:
        cur.close()
        conn.close()

def get_user_by_id(user_id: int) -> Optional[User]:
    """Fetches user record by ID."""
    conn = get_connection()
    cur = conn.cursor()
    try:
        query = "SELECT id, username, email, password, created_at, last_login FROM users WHERE id = {ph}"
        if conn.engine == "mysql":
            cur.execute(query.format(ph="%s"), (user_id,))
        else:
            cur.execute(query.format(ph="?"), (user_id,))
        row = cur.fetchone()
        if row:
            return User(
                id=row[0] if isinstance(row, tuple) else row["id"],
                username=row[1] if isinstance(row, tuple) else row["username"],
                email=row[2] if isinstance(row, tuple) else row["email"],
                password_hash=row[3] if isinstance(row, tuple) else row["password"],
                created_at=str(row[4] if isinstance(row, tuple) else row["created_at"]),
                last_login=str(row[5] if isinstance(row, tuple) else row["last_login"])
            )
        return None
    finally:
        cur.close()
        conn.close()

def update_password(email: str, new_password: str) -> Tuple[bool, str]:
    """Updates password for verified user."""
    is_valid, msg = validate_password_strength(new_password)
    if not is_valid:
        return False, msg
        
    conn = get_connection()
    cur = conn.cursor()
    try:
        pwd_hash = hash_password(new_password)
        query = "UPDATE users SET password = {ph} WHERE email = {ph}"
        if conn.engine == "mysql":
            cur.execute(query.format(ph="%s"), (pwd_hash, email.strip().lower()))
        else:
            cur.execute(query.format(ph="?"), (pwd_hash, email.strip().lower()))
        conn.commit()
        return True, "Password successfully updated."
    except Exception as e:
        return False, f"Failed to update password: {str(e)}"
    finally:
        cur.close()
        conn.close()
