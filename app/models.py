# -*- coding: utf-8 -*-
"""
Data models and schemas for EmailShield-AI.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone

@dataclass
class User:
    id: int
    username: str
    email: str
    password_hash: str
    created_at: Optional[str] = None
    last_login: Optional[str] = None

@dataclass
class AnalysisResult:
    classification: str       # 'Phishing', 'Suspicious', or 'Likely Safe'
    risk_score: int           # 0 to 100
    explanation: str          # Executive summary of threat findings
    indicators: List[str]     # Detected threat signals (urgency, spoofing, etc.)
    recommendations: List[str]# Actionable defensive advice
    is_ai_generated: bool     # True if Gemini, False if heuristic fallback
    model_name: str           # e.g., 'gemini-2.5-flash' or 'heuristic-engine'
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"))
    disclaimer: str = (
        "Automated AI analysis is an advisory cyber defense tool and can make mistakes. "
        "Never consider an email definitively safe based solely on automated scans."
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "classification": self.classification,
            "risk_score": self.risk_score,
            "explanation": self.explanation,
            "indicators": self.indicators,
            "recommendations": self.recommendations,
            "is_ai_generated": self.is_ai_generated,
            "model_name": self.model_name,
            "timestamp": self.timestamp,
            "disclaimer": self.disclaimer
        }

@dataclass
class AnalysisRecord:
    id: Optional[int]
    user_id: int
    subject: Optional[str]
    sender: Optional[str]
    classification: str
    risk_score: int
    explanation: str
    indicators: List[str]
    created_at: str
    email_body_preview: Optional[str] = None
