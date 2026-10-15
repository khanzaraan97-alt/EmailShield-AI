# -*- coding: utf-8 -*-
"""
Email Phishing Analyzer Engine for EmailShield-AI.
Combines deep heuristic feature extraction with Google Gemini Generative AI,
with resilient fallback mechanisms and strict input sanitization.
"""

import re
import json
import asyncio
from typing import Dict, Any, List, Tuple, Optional
from urllib.parse import urlparse

from app.config import Config
from app.models import AnalysisResult

# Initialize Google GenAI client if available
genai_client = None
if Config.is_gemini_configured():
    try:
        from google import genai
        genai_client = genai.Client(api_key=Config.GEMINI_API_KEY)
    except Exception as e:
        print(f"[Analyzer] Failed to initialize Gemini Client: {repr(e)}")

# ==============================================================================
# HEURISTIC INDICATOR DICTIONARIES
# ==============================================================================

URGENCY_PATTERNS = [
    r"\bimmediate(ly)?\b", r"\burgent(ly)?\b", r"\bwithin\s+\d+\s+(hours?|mins?|minutes?|days?)\b",
    r"\baccount\s+(will\s+be\s+)?(suspended|terminated|closed|locked)\b", r"\bfinal\s+warning\b",
    r"\baction\s+required\b", r"\bact\s+now\b", r"\bsecurity\s+alert\b",
    r"\bunauthorized\s+(access|activity|charge)\b", r"\bdeadline\b", r"\bcritical\s+notice\b"
]

CREDENTIAL_HARVESTING_PATTERNS = [
    r"\bverify\s+(your\s+)?(account|identity|email|details|credentials)\b",
    r"\bconfirm\s+(your\s+)?(identity|password|details|pin)\b",
    r"\bclick\s+(here|below|this\s+link)\s+to\s+(login|sign\s*in|verify|unlock|update)\b",
    r"\breset\s+(your\s+)?password\b", r"\bupdate\s+(your\s+)?(billing|payment|credit\s*card)\b",
    r"\bre-?authenticate\b", r"\bvalidate\s+your\s+session\b"
]

FINANCIAL_PATTERNS = [
    r"\bwire\s+transfer\b", r"\bgift\s*cards?\b", r"\bcrypto(currency)?\b", r"\bbitcoin\b",
    r"\boverdue\s+invoice\b", r"\brefund\s+claim\b", r"\bdirect\s+deposit\b",
    r"\bpayroll\s+update\b", r"\bbank\s+routing\b", r"\bpayment\s+processed\b"
]

KNOWN_BRANDS = {
    "paypal": ["paypal.com", "paypal.me"],
    "microsoft": ["microsoft.com", "live.com", "office.com", "outlook.com"],
    "apple": ["apple.com", "icloud.com"],
    "google": ["google.com", "gmail.com"],
    "netflix": ["netflix.com"],
    "amazon": ["amazon.com", "amazon.co.uk"],
    "chase": ["chase.com"],
    "bank of america": ["bankofamerica.com"],
    "wells fargo": ["wellsfargo.com"],
    "dhl": ["dhl.com"],
    "fedex": ["fedex.com"]
}

URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "cutt.ly"}

# ==============================================================================
# FEATURE EXTRACTION PIPELINE
# ==============================================================================

def extract_urls(text: str) -> List[str]:
    """Safely extracts all URLs from plain text or markdown email content."""
    url_pattern = r'https?://[^\s<>"\')]+'
    raw_urls = re.findall(url_pattern, text)
    # Clean trailing punctuation
    cleaned = []
    for u in raw_urls:
        u_clean = u.rstrip(".,;!?:")
        if u_clean:
            cleaned.append(u_clean)
    return list(dict.fromkeys(cleaned))

def analyze_links(urls: List[str]) -> Tuple[int, List[str]]:
    """Evaluates risk score contribution and indicators from links."""
    score = 0
    indicators = []
    
    for u in urls:
        try:
            parsed = urlparse(u)
            domain = parsed.netloc.lower()
            
            # Check for IP address as host
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$', domain):
                score += 35
                indicators.append(f"Suspicious raw IP address link detected ({domain})")
                
            # Check for URL shorteners hiding destination
            base_domain = domain.split(":")[0]
            if base_domain in URL_SHORTENERS:
                score += 20
                indicators.append(f"Obfuscated URL shortener detected ({base_domain})")
                
            # Suspicious TLDs often abused in phishing kits
            suspicious_tlds = (".top", ".xyz", ".club", ".work", ".buzz", ".cam", ".rest", ".tk", ".ml", ".ga")
            if any(base_domain.endswith(tld) for tld in suspicious_tlds):
                score += 25
                indicators.append(f"High-risk top-level domain detected ({base_domain})")
                
            # Multiple subdomains / brand spoofing tokens
            parts = base_domain.split(".")
            if len(parts) > 3:
                score += 15
                indicators.append(f"Excessive subdomain nesting detected ({base_domain})")
                
            for brand, legitimate in KNOWN_BRANDS.items():
                if brand in base_domain and not any(base_domain.endswith(legit) for legit in legitimate):
                    score += 35
                    indicators.append(f"Possible brand typosquatting or spoofing in URL ({domain} mimicking {brand.title()})")
        except Exception:
            pass
            
    return score, indicators

def analyze_heuristics(email_body: str, subject: Optional[str] = None, sender: Optional[str] = None) -> Dict[str, Any]:
    """
    Performs pure rule-based, deterministic heuristic feature extraction.
    Provides calculated baseline risk score and detected indicators.
    """
    combined_text = f"{subject or ''}\n{email_body}".strip()
    score = 0
    indicators: List[str] = []
    
    # 1. Urgency & Pressure analysis
    urgency_hits = []
    for pattern in URGENCY_PATTERNS:
        matches = re.findall(pattern, combined_text, flags=re.IGNORECASE)
        if matches:
            urgency_hits.append(pattern.replace(r"\b", "").replace(r"\s+", " "))
            
    if urgency_hits:
        weight = min(len(urgency_hits) * 15, 35)
        score += weight
        indicators.append(f"Psychological urgency and coercive pressure tactics detected ({len(urgency_hits)} occurrences)")

    # 2. Credential harvesting analysis
    cred_hits = []
    for pattern in CREDENTIAL_HARVESTING_PATTERNS:
        if re.search(pattern, combined_text, flags=re.IGNORECASE):
            cred_hits.append(pattern)
            
    if cred_hits:
        weight = min(len(cred_hits) * 20, 40)
        score += weight
        indicators.append("Credential or sensitive account verification requests identified")

    # 3. Financial fraud & wire demands
    fin_hits = [p for p in FINANCIAL_PATTERNS if re.search(p, combined_text, flags=re.IGNORECASE)]
    if fin_hits:
        score += 25
        indicators.append("Unusual financial, invoice, or wire transfer transaction demands")

    # 4. Link & URL inspection
    extracted_urls = extract_urls(combined_text)
    if extracted_urls:
        link_score, link_indicators = analyze_links(extracted_urls)
        score += link_score
        indicators.extend(link_indicators)
        if len(extracted_urls) > 5:
            score += 10
            indicators.append(f"Unusually high link density ({len(extracted_urls)} links embedded)")

    # 5. Sender domain inconsistency & spoofing checks
    if sender:
        sender_lower = sender.lower()
        # Free webmail used for corporate brand claims
        free_providers = ["@gmail.com", "@yahoo.com", "@hotmail.com", "@outlook.com", "@aol.com"]
        for brand in KNOWN_BRANDS:
            if brand in combined_text.lower():
                if any(sender_lower.endswith(fp) for fp in free_providers):
                    score += 35
                    indicators.append(f"Brand impersonation risk: Email discusses {brand.title()} but sender uses public webmail ({sender})")
                    break

    # 6. Generic greeting / Dear Customer
    if re.search(r"\b(dear\s+(customer|user|client|valued\s+member|account\s+holder))\b", combined_text, re.IGNORECASE):
        score += 15
        indicators.append("Generic or impersonal greeting common in automated phishing templates")

    # Clamp baseline risk score between 0 and 100
    final_score = min(max(score, 0), 100)
    
    # Classification determination
    if final_score >= 65:
        classification = "Phishing"
    elif final_score >= 25:
        classification = "Suspicious"
    else:
        classification = "Likely Safe"
        
    return {
        "risk_score": final_score,
        "classification": classification,
        "indicators": indicators,
        "url_count": len(extracted_urls)
    }

# ==============================================================================
# GEMINI GENERATIVE AI INTEGRATION
# ==============================================================================

async def analyze_with_gemini(
    email_body: str,
    subject: Optional[str],
    sender: Optional[str],
    heuristic_data: Dict[str, Any]
) -> Optional[AnalysisResult]:
    """
    Submits structured analysis prompt to Google Gemini 2.5 Flash.
    Returns structured AnalysisResult or None on failure.
    """
    if not Config.is_gemini_configured() or not genai_client:
        return None

    # Sanitize and truncate email body snippet for prompt
    safe_body = email_body[:10000] # Safe token limit
    
    prompt = f"""
You are a senior cybersecurity threat intelligence analyst specializing in anti-phishing, business email compromise (BEC), and social engineering detection.

Analyze the following incoming email for phishing threats.

=== EMAIL METADATA ===
Sender Address: {sender or 'Not provided'}
Subject Line: {subject or 'Not provided'}

=== EMAIL BODY CONTENT ===
{safe_body}

=== PRE-EXTRACTED HEURISTIC TELEMETRY ===
Calculated Heuristic Score: {heuristic_data['risk_score']}/100
Detected Heuristic Indicators:
{json.dumps(heuristic_data['indicators'], indent=2)}

=== YOUR INSTRUCTIONS ===
1. Evaluate whether this email is legitimate, suspicious, or malicious phishing.
2. Determine a calibrated Risk Score from 0 to 100:
   - 0 to 24: "Likely Safe" (Routine legitimate correspondence with normal communication patterns)
   - 25 to 64: "Suspicious" (Presents minor anomalies, unverified sender, or mild pressure)
   - 65 to 100: "Phishing" (Clear deception, credential harvesting, brand impersonation, urgent threats, or malicious links)
3. Detail specific indicators (e.g. sender mismatch, coercive urgency, link deception, unusual financial requests).
4. Provide 3-4 concrete, actionable defensive recommendations.

CRITICAL: Return ONLY valid JSON with no markdown backticks, matching this exact schema:
{{
  "classification": "Phishing" | "Suspicious" | "Likely Safe",
  "risk_score": integer between 0 and 100,
  "explanation": "concise executive verdict explaining the threat logic",
  "indicators": ["indicator 1", "indicator 2", ...],
  "recommendations": ["recommendation 1", "recommendation 2", ...]
}}
"""

    for attempt in range(2):
        try:
            # Asynchronous Gemini API call with timeout
            response = await asyncio.wait_for(
                genai_client.aio.models.generate_content(
                    model=Config.GEMINI_MODEL,
                    contents=prompt
                ),
                timeout=8.0
            )
            
            raw_text = response.text.strip()
            # Strip markdown code blocks if Gemini enclosed response in ```json ... ```
            clean_text = re.sub(r"^```(json)?", "", raw_text, flags=re.MULTILINE)
            clean_text = re.sub(r"```$", "", clean_text, flags=re.MULTILINE).strip()
            
            data = json.loads(clean_text)
            
            # Validate output fields
            classification = data.get("classification", heuristic_data["classification"])
            if classification not in ("Phishing", "Suspicious", "Likely Safe"):
                classification = heuristic_data["classification"]
                
            risk_score = int(data.get("risk_score", heuristic_data["risk_score"]))
            risk_score = min(max(risk_score, 0), 100)
            
            explanation = data.get("explanation", "").strip() or "Analysis completed by Gemini Threat Intelligence."
            indicators = data.get("indicators", []) or heuristic_data["indicators"]
            recommendations = data.get("recommendations", []) or [
                "Verify the sender's identity through an independent, trusted channel.",
                "Do not click any embedded links or open attachments.",
                "Report this email to your organization's IT security team."
            ]
            
            return AnalysisResult(
                classification=classification,
                risk_score=risk_score,
                explanation=explanation,
                indicators=indicators,
                recommendations=recommendations,
                is_ai_generated=True,
                model_name=Config.GEMINI_MODEL
            )
        except Exception as e:
            err_str = str(e).lower()
            print(f"[Analyzer] Gemini attempt {attempt + 1} failed: {repr(e)}")
            if "api_key" in err_str or "unregistered" in err_str or "invalid" in err_str or "permission" in err_str:
                break
            if attempt == 0:
                await asyncio.sleep(0.5)

    return None

# ==============================================================================
# MAIN PUBLIC ANALYZE FUNCTION
# ==============================================================================

async def analyze_email(
    email_body: str,
    subject: Optional[str] = None,
    sender: Optional[str] = None
) -> Tuple[bool, AnalysisResult, str]:
    """
    Main entry point for analyzing submitted email content.
    Validates input, runs heuristic engine, and queries Gemini AI with fallback.
    Returns: (success: bool, result: AnalysisResult, message: str)
    """
    # 1. Input validation
    if not email_body or not email_body.strip():
        empty_res = AnalysisResult(
            classification="Suspicious",
            risk_score=0,
            explanation="No content provided for analysis.",
            indicators=["Empty email body"],
            recommendations=["Paste the text of an email to evaluate."],
            is_ai_generated=False,
            model_name="none"
        )
        return False, empty_res, "Please paste an email body to analyze."

    if len(email_body.encode("utf-8")) > Config.MAX_EMAIL_SIZE_BYTES:
        err_res = AnalysisResult(
            classification="Suspicious",
            risk_score=50,
            explanation="Submitted email exceeds the allowed size limit (50 KB).",
            indicators=["Oversized email payload"],
            recommendations=["Shorten the submitted content or paste text snippets."],
            is_ai_generated=False,
            model_name="none"
        )
        return False, err_res, f"Email content exceeds maximum allowed size ({Config.MAX_EMAIL_SIZE_BYTES // 1024} KB)."

    # 2. Run deterministic heuristic evaluation
    heuristic_data = analyze_heuristics(email_body, subject, sender)

    # 3. Attempt Gemini AI classification
    ai_result = None
    if Config.is_gemini_configured():
        ai_result = await analyze_with_gemini(email_body, subject, sender, heuristic_data)

    # 4. If AI succeeded, return verified AI result
    if ai_result:
        return True, ai_result, "Analysis completed successfully using Google Gemini AI."

    # 5. Resilient fallback to heuristic engine if AI failed or unconfigured
    fallback_recs = [
        "Do not click on unverified links or open unexpected attachments.",
        "Confirm the legitimacy of the request by calling the sender using a known official number.",
        "Examine the actual sender header for domain spoofing."
    ]
    if heuristic_data["classification"] == "Phishing":
        fallback_recs.insert(0, "Immediately flag and quarantine this message. Do not respond or provide credentials.")
        
    explanation = (
        f"Evaluated via EmailShield Heuristic Threat Engine. "
        f"Calculated risk score is {heuristic_data['risk_score']}/100 based on {len(heuristic_data['indicators'])} detected threat signals."
    )
    if not Config.is_gemini_configured():
        explanation += " (Note: Gemini API key is not configured; running in standalone heuristic mode.)"
    else:
        explanation += " (Note: Gemini AI service was temporarily unreachable; results derived from local heuristic engine.)"

    fallback_result = AnalysisResult(
        classification=heuristic_data["classification"],
        risk_score=heuristic_data["risk_score"],
        explanation=explanation,
        indicators=heuristic_data["indicators"] or ["No anomalous heuristic indicators detected."],
        recommendations=fallback_recs,
        is_ai_generated=False,
        model_name="EmailShield-Heuristic-Engine"
    )

    return True, fallback_result, "Analysis completed using Heuristic Cyber Threat Engine."
