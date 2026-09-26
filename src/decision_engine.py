"""
AmanQR - Decision Engine v2 (Hybrid: Rules + WHOIS + ML)
"""
import os
import re
import joblib
import numpy as np
from urllib.parse import urlparse

from src.url_analyzer import analyze_url, clean_url, extract_features_for_ml
from src.whois_checker import whois_check


# Load ML model
MODEL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(MODEL_DIR, 'models', 'lightgbm_model.pkl')
FEATURES_PATH = os.path.join(MODEL_DIR, 'models', 'feature_columns.pkl')

try:
    ML_MODEL = joblib.load(MODEL_PATH)
    ML_FEATURES = joblib.load(FEATURES_PATH)
    ML_AVAILABLE = True
except Exception as e:
    print(f"⚠️ ML model not loaded: {e}")
    ML_AVAILABLE = False


def predict_ml(url):
    """Get ML prediction probability"""
    if not ML_AVAILABLE:
        return 0.5, 0
    
    try:
        features = extract_features_for_ml(url)
        if features is None:
            return 0.5, 0
        
        # Align features with training order
        feature_vector = np.array([[features.get(f, 0) for f in ML_FEATURES]])
        proba = ML_MODEL.predict_proba(feature_vector)[0][1]
        return proba, 1
    except Exception as e:
        return 0.5, 0


def decide(url):
    """
    Hybrid decision: URL Rules + WHOIS + ML
    
    Final score = (url_score * 0.4) + (whois_score * 0.2) + (ml_proba * 100 * 0.4)
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
    
    url_clean = clean_url(url) or url
    
    # Layer 1: URL rules
    url_score, url_reasons = analyze_url(url_clean)
    
    # Layer 2: WHOIS (only if suspicious)
    whois_score = 0
    whois_reason = None
    if url_score >= 10:
        try:
            whois_score, whois_reason = whois_check(url_clean)
        except Exception:
            pass
    
    # Layer 3: ML prediction
    ml_proba, ml_used = predict_ml(url_clean)
    ml_score = ml_proba * 100  # Convert to 0-100
    
    # Combine (weighted)
    # ML is strongest → 50% weight
    # URL rules → 30%
    # WHOIS → 20%
    final_score = (url_score * 0.3) + (whois_score * 0.2) + (ml_score * 0.5)
    final_score = max(0, min(100, final_score))
    
    # Verdict
    if final_score >= 60:
        verdict = "LIKELY MALICIOUS"
        emoji = "🔴"
        color = "red"
        confidence = min(99, 50 + final_score * 0.5)
    elif final_score >= 30:
        verdict = "SUSPICIOUS"
        emoji = "🟡"
        color = "orange"
        confidence = min(95, 40 + final_score * 0.6)
    elif final_score <= 10:
        verdict = "LIKELY SAFE"
        emoji = "🟢"
        color = "green"
        confidence = min(99, 60 + (10 - final_score) * 2)
    else:
        verdict = "UNKNOWN"
        emoji = "⚪"
        color = "gray"
        confidence = 50
    
    # Reasons
    all_reasons = list(url_reasons)
    if whois_reason:
        all_reasons.append(whois_reason)
    if ml_used:
        if ml_proba >= 0.7:
            all_reasons.append(f"ML: high risk ({ml_proba*100:.0f}%)")
        elif ml_proba <= 0.3:
            all_reasons.append(f"ML: low risk ({ml_proba*100:.0f}%)")
        else:
            all_reasons.append(f"ML: uncertain ({ml_proba*100:.0f}%)")
    
    return {
        "verdict": verdict,
        "score": final_score,
        "confidence": confidence,
        "reasons": all_reasons,
        "emoji": emoji,
        "color": color,
        "url": url_clean,
        "ml_proba": ml_proba,
        "url_score": url_score,
        "whois_score": whois_score,
    }
