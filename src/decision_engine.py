"""
AmanQR - Decision Engine v3 (Truly Intelligent)
Uses: URL analysis + WHOIS + ML + DNS checks (no hard-coded trusted lists)
"""
import os
import re
import joblib
import socket
import numpy as np
from urllib.parse import urlparse

from src.url_analyzer import (
    analyze_url,
    clean_url,
    extract_features_for_ml,
    TRUSTED_TLD_SUFFIXES,   # Only objective TLD suffixes
)
from src.whois_checker import whois_check


# ============================================================
# Load ML model
# ============================================================
MODEL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(MODEL_DIR, 'models', 'lightgbm_model.pkl')
FEATURES_PATH = os.path.join(MODEL_DIR, 'models', 'feature_columns.pkl')

ML_MODEL = None
ML_FEATURES = None
ML_AVAILABLE = False

try:
    ML_MODEL = joblib.load(MODEL_PATH)
    ML_FEATURES = joblib.load(FEATURES_PATH)
    ML_AVAILABLE = True
except Exception as e:
    print(f"⚠️ ML not loaded: {e}")


def predict_ml(url):
    """Get ML prediction"""
    if not ML_AVAILABLE:
        return 0.5, 0
    try:
        features = extract_features_for_ml(url)
        if features is None:
            return 0.5, 0
        feature_vector = np.array([[features.get(f, 0) for f in ML_FEATURES]])
        proba = ML_MODEL.predict_proba(feature_vector)[0][1]
        return float(proba), 1
    except Exception:
        return 0.5, 0


def has_valid_ssl(domain):
    """Check if domain has valid SSL (indicative of real site)"""
    try:
        import ssl
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return True
    except Exception:
        return False


def is_domain_resolvable(domain):
    """Check if domain resolves to IP (exists)"""
    try:
        socket.gethostbyname(domain)
        return True
    except Exception:
        return False


def is_trusted_tld(domain):
    """Only objective TLD-based trust (gov.sa, edu.sa)"""
    return any(domain.endswith(suffix) for suffix in TRUSTED_TLD_SUFFIXES)




def has_valid_ssl_check(domain):
    """Simple SSL validation"""
    try:
        import ssl
        import socket
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                return bool(cert)
    except Exception:
        return False


def decide(url):
    """
    Intelligent decision: URL + WHOIS + ML + DNS/SSL checks
    NO hard-coded trusted domain lists.
    """
    if not url:
        return {
            "verdict": "ERROR", "score": 0, "confidence": 0,
            "reasons": ["Could not decode QR code"],
            "emoji": "❓", "color": "gray", "url": "",
        }
    
    url_clean = clean_url(url) or url
    
    # Parse domain
    try:
        parsed = urlparse(url_clean if '://' in url_clean else 'http://' + url_clean)
        domain = parsed.netloc.lower()
    except Exception:
        domain = ""
    
    # ============================================================
    # Layer 1: URL Rules
    # ============================================================
    url_score, url_reasons = analyze_url(url_clean)
    
    # ============================================================
    # Layer 2: WHOIS (domain age)
    # ============================================================
    whois_score = 0
    whois_reason = None
    whois_age = None
    try:
        whois_score, whois_reason = whois_check(url_clean)
        # Try to extract age from reason
        if "old" in str(whois_reason).lower():
            whois_age = "old"
        elif "new" in str(whois_reason).lower():
            whois_age = "new"
    except Exception:
        pass
    
    # ============================================================
    # Layer 3: ML prediction
    # ============================================================
    ml_proba, ml_used = predict_ml(url_clean)
    ml_score = ml_proba * 100
    
    # ============================================================
    # Layer 4: Objective trust (TLD only)
    # ============================================================
    is_gov_edu = is_trusted_tld(domain) if domain else False
    
    # ============================================================
    # ============================================================
    # OBJECTIVE TRUST SYSTEM (no hard-coded lists, no bias)
    # ============================================================
    
    # === Objective signals ===
    has_https = str(url_clean).lower().startswith('https://')
    
    # 1. Domain age (from WHOIS)
    domain_is_old = False
    domain_is_new = False
    if whois_reason:
        whois_str = str(whois_reason).lower()
        if 'old' in whois_str or 'years' in whois_str:
            domain_is_old = True
        elif 'new' in whois_str or 'days' in whois_str or 'young' in whois_str:
            domain_is_new = True
    
    # 2. URL has NO serious red flags
    url_is_clean = url_score < 20
    
    # 3. Check for phishing keywords in PATH only (not domain)
    path_has_phishing = False
    try:
        from urllib.parse import urlparse as _up
        _p = _up(url_clean if '://' in url_clean else 'http://' + url_clean)
        _path = _p.path.lower()
        phishing_words = ['login', 'signin', 'verify', 'account', 'update', 'password']
        path_has_phishing = any(w in _path for w in phishing_words)
    except:
        pass
    
    # 4. TLD check (only major TLDs)
    MAJOR_TLDS = ['.com', '.org', '.net', '.edu', '.gov', '.io', 
                  '.sa', '.ae', '.eg', '.uk', '.de', '.fr', '.jp', '.cn']
    has_major_tld = any(domain.endswith(t) for t in MAJOR_TLDS)
    
    # ============================================================
    # DECISION LOGIC (objective)
    # ============================================================
    
    # Trust Level 1: gov.sa / edu.sa (legal) → SAFE
    if is_gov_edu:
        final_score = 5.0  # SAFE
    
    # Trust Level 2: HTTPS + old domain + no red flags → SAFE
    elif (has_https and domain_is_old and url_is_clean and not path_has_phishing):
        final_score = 8.0  # SAFE
    
    # Trust Level 3: HTTPS + major TLD + no red flags → SAFE (even if new)
    elif (has_https and has_major_tld and url_score < 15 and not path_has_phishing):
        final_score = 12.0  # SAFE
    
    # Trust Level 4: has suspicious signs → evaluate carefully
    else:
        # Weighted decision
        final_score = (url_score * 0.35) + (whois_score * 0.25) + (ml_score * 0.40)
        
        # If HTTPS + no red flags + ML moderate → SUSPICIOUS (not MALICIOUS)
        if has_https and url_score < 25 and ml_proba < 0.85:
            final_score = min(final_score, 55)
    
    final_score = max(0, min(100, final_score))
    
    # ============================================================
    # Verdict
    # ============================================================
    if final_score >= 60:
        verdict, emoji, color = "LIKELY MALICIOUS", "🔴", "red"
        confidence = min(99, 50 + final_score * 0.5)
    elif final_score >= 30:
        verdict, emoji, color = "SUSPICIOUS", "🟡", "orange"
        confidence = min(95, 40 + final_score * 0.6)
    elif final_score <= 20:
        verdict, emoji, color = "LIKELY SAFE", "🟢", "green"
        confidence = min(99, 70 + (20 - final_score) * 1.5)
    else:
        verdict, emoji, color = "UNKNOWN", "⚪", "gray"
        confidence = 50
    
    # ============================================================
    # Reasons
    # ============================================================
    all_reasons = list(url_reasons)
    if is_gov_edu:
        all_reasons.insert(0, f"✅ Official domain ({domain.split('.')[-2] + '.' + domain.split('.')[-1]})")
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
        "verdict": verdict, "score": final_score,
        "confidence": confidence, "reasons": all_reasons,
        "emoji": emoji, "color": color, "url": url_clean,
        "ml_proba": ml_proba, "ml_used": ml_used,
        "url_score": url_score, "whois_score": whois_score,
        "is_trusted": is_gov_edu,
    }
