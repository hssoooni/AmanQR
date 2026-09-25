
"""
AmanQR - Decision Engine
Combines URL analysis + WHOIS into final verdict.
"""
from src.url_analyzer import analyze_url
from src.whois_checker import whois_check


def decide(url):
    """
    Final decision.
    Returns: dict with verdict, score, confidence, reasons, emoji, color
    """
    if not url:
        return {
            "verdict": "ERROR",
            "score": 0,
            "confidence": 0,
            "reasons": ["Could not decode QR code"],
            "emoji": "❓",
            "color": "gray",
            "url": "",
        }
    
    url_score, url_reasons = analyze_url(url)
    
    whois_score = 0
    whois_reason = None
    if url_score >= 10:
        try:
            whois_score, whois_reason = whois_check(url)
        except Exception:
            whois_score, whois_reason = 0, None
    
    final_score = url_score + (whois_score * 0.7)
    final_score = max(0, min(100, final_score))
    
    if final_score >= 60:
        verdict = "MALICIOUS"
        emoji = "🔴"
        color = "red"
        confidence = min(99, 50 + final_score * 0.5)
    elif final_score >= 30:
        verdict = "SUSPICIOUS"
        emoji = "🟡"
        color = "orange"
        confidence = min(95, 40 + final_score * 0.6)
    else:
        verdict = "BENIGN"
        emoji = "🟢"
        color = "green"
        confidence = min(99, 60 + (30 - final_score) * 1.3)
    
    all_reasons = url_reasons.copy()
    if whois_reason:
        all_reasons.append(whois_reason)
    
    return {
        "verdict": verdict,
        "score": final_score,
        "confidence": confidence,
        "reasons": all_reasons,
        "emoji": emoji,
        "color": color,
        "url": url,
    }
