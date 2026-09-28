"""
AmanQR - Decision Engine v5 (Final)
Hybrid: URL Rules + WHOIS + ML + VirusTotal + URLhaus
"""
import os
import joblib
import numpy as np
from urllib.parse import urlparse

from src.url_analyzer import (
    analyze_url, clean_url, extract_features_for_ml,
    TRUSTED_TLD_SUFFIXES,
)
from src.whois_checker import whois_check
from src.api_checker import check_external_apis
from src.url_unshortener import analyze_with_unshortening, is_shortener


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
    print(f"✅ ML model loaded: {len(ML_FEATURES)} features")
except Exception as e:
    print(f"⚠️ ML model not loaded: {e}")


# ============================================================
# Clear attack indicators
# ============================================================
CRITICAL_PHISHING_WORDS = [
    'login', 'signin', 'sign-in', 'verify-account',
    'confirm-account', 'secure-login', 'account-update',
    'recover-password', 'reset-password', 'unlock-account',
]

PHISHING_BRANDS = [
    'paypal', 'apple', 'microsoft', 'google', 'amazon', 'netflix',
    'facebook', 'instagram', 'whatsapp', 'hotmail', 'outlook',
    'gmail', 'yahoo', 'bank', 'visa', 'mastercard',
]

SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
    '.work', '.click', '.country', '.stream', '.download',
    '.review', '.loan', '.date',
}

SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
    'is.gd', 'buff.ly', 'rebrand.ly', 'shorturl.at',
}


def predict_ml(url):
    if not ML_AVAILABLE:
        return 0.5, 0
    try:
        features = extract_features_for_ml(url)
        if features is None:
            return 0.5, 0
        fv = np.array([[features.get(f, 0) for f in ML_FEATURES]])
        proba = ML_MODEL.predict_proba(fv)[0][1]
        return float(proba), 1
    except Exception:
        return 0.5, 0


def has_clear_attack_indicators(url, domain, path):
    """Return (score, reasons) for CLEAR attack evidence"""
    import re
    score = 0
    reasons = []
    url_lower = url.lower()
    
    # 1. Phishing brand in path (not domain)
    domain_base = domain.split('.')[0].lower() if domain else ''
    for brand in PHISHING_BRANDS:
        if brand in path.lower() and brand not in domain_base:
            score += 40
            reasons.append(f"🚨 Brand '{brand}' in URL path (phishing)")
            break
    
    # 2. Phishing keyword + HTTP
    if not url_lower.startswith('https://'):
        for kw in CRITICAL_PHISHING_WORDS:
            if kw in url_lower:
                score += 35
                reasons.append(f"🚨 Phishing keyword '{kw}' without HTTPS")
                break
    
    # 3. Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 30
            reasons.append(f"⚠️ Suspicious TLD: {tld}")
            break
    
    # 4. URL shortener
    for sh in SHORTENERS:
        if sh in domain:
            score += 25
            reasons.append(f"⚠️ URL shortener: {sh}")
            break
    
    # 5. IP address
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
        score += 40
        reasons.append("🚨 IP address instead of domain")
    
    # 6. Typosquatting
    for brand in PHISHING_BRANDS:
        if len(brand) >= 4:
            domain_clean = domain_base.replace('0','o').replace('1','l').replace('3','e')
            if brand in domain_clean and brand != domain_base and brand not in domain_base:
                score += 35
                reasons.append(f"🚨 Typosquatting of '{brand}'")
                break
    
    return score, reasons


def decide(url):
    """Trust-first decision with multiple layers"""
    if not url:
        return {
            "verdict": "ERROR", "score": 0, "confidence": 0,
            "reasons": ["Could not decode QR code"],
            "emoji": "❓", "color": "gray", "url": "",
        }
    
    url_clean = clean_url(url) or url
    
    # NEW: Unshorten URL
    unshort_result = {"is_shortened": False, "final_url": url_clean, "redirect_chain": []}
    actual_url = url_clean
    try:
        if is_shortener(url_clean):
            unshort_result = analyze_with_unshortening(url_clean)
            if unshort_result['success'] and unshort_result['final_url'] != url_clean:
                actual_url = unshort_result['final_url']
    except Exception:
        pass
    
    # Parse (use actual URL)
    try:
        parsed = urlparse(actual_url if '://' in actual_url else 'http://' + actual_url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
    except Exception:
        domain, path = "", ""
    
    url_lower = url_clean.lower()
    has_https = url_lower.startswith('https://')
    
    # ============================================================
    # Layer 1: Attack indicators
    # ============================================================
    attack_score, attack_reasons = has_clear_attack_indicators(url_clean, domain, path)
    
    # ============================================================
    # Layer 2: URL rules
    # ============================================================
    url_score, url_reasons = analyze_url(actual_url)
    
    if unshort_result['is_shortened']:
        if unshort_result['success']:
            url_reasons.insert(0, f"🔗 المختصر: {url_clean[:40]} → {actual_url[:50]}")
        else:
            url_reasons.insert(0, f"⚠️ رابط مختصر: {url_clean[:40]} (لم يُفك)")
    
    # ============================================================
    # Layer 3: ML
    # ============================================================
    ml_proba, ml_used = predict_ml(actual_url)
    ml_score = ml_proba * 100
    
    # ============================================================
    # Layer 4: WHOIS
    # ============================================================
    whois_score = 0
    whois_reason = None
    domain_is_old = False
    if attack_score >= 20 or url_score >= 20:
        try:
            whois_score, whois_reason = whois_check(actual_url)
            if whois_reason and 'old' in str(whois_reason).lower():
                domain_is_old = True
        except Exception:
            pass
    
    # ============================================================
    # Layer 5: External APIs (VirusTotal + URLhaus)
    # ============================================================
    api_result = {"score": 0, "reasons": [], "vt_score": 0, "uh_score": 0}
    try:
        api_result = check_external_apis(actual_url)
    except Exception as e:
        pass
    
    api_score = api_result.get("score", 0)
    api_reasons = api_result.get("reasons", [])
    
    # ============================================================
    # Check gov/edu TLD
    # ============================================================
    is_gov_edu = any(domain.endswith(s) for s in TRUSTED_TLD_SUFFIXES) if domain else False
    
    # ============================================================
    # COMBINE (priority order)
    # ============================================================
    
    # Priority 1: External API says malicious
    if api_score >= 50:
        final_score = min(95, 60 + api_score * 0.3)
    
    # Priority 2: Clear attack indicators
    elif attack_score >= 60:
        final_score = min(95, 60 + attack_score * 0.4)
    
    # Priority 3: Some attack indicators
    elif attack_score >= 30:
        final_score = min(65, 35 + attack_score * 0.4)
    
    # Priority 4: gov/edu TLD = SAFE
    elif is_gov_edu:
        final_score = 5.0
    
    # Priority 5: HTTPS + old domain (2+ years) + no attack = SAFE
    # Override TLD + WHOIS hidden
    elif has_https and domain_is_old and attack_score == 0 and url_score < 30:
        final_score = 12.0
    
    # Priority 6: HTTPS + clean
    elif has_https and url_score < 15:
        final_score = 12.0
    
    # Priority 7: Mixed signals
    else:
        final_score = (url_score * 0.35) + (whois_score * 0.15) + (ml_score * 0.30) + (api_score * 0.20)
        
        if has_https and url_score < 25 and ml_proba < 0.85:
            final_score = min(final_score, 55)
    
    final_score = max(0, min(100, final_score))
    
    # ============================================================
    # VERDICT
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
    # REASONS
    # ============================================================
    all_reasons = list(api_reasons) + list(attack_reasons) + list(url_reasons)
    
    if is_gov_edu:
        all_reasons.insert(0, "✅ Official domain (gov.sa / edu.sa)")
    
    if whois_reason:
        all_reasons.append(whois_reason)
    
    if ml_used and attack_score == 0 and api_score == 0:
        if ml_proba < 0.3:
            all_reasons.append(f"✅ ML: low risk ({ml_proba*100:.0f}%)")
    
    if attack_score == 0 and api_score == 0 and url_score < 10:
        if not any('No suspicious' in r for r in all_reasons):
            all_reasons.insert(0, "✅ No attack indicators found")
        if has_https:
            all_reasons.insert(1, "✅ HTTPS secure connection")
    
    if not all_reasons:
        all_reasons = ["No suspicious indicators"]
    
    return {
        "verdict": verdict, "score": final_score,
        "confidence": confidence, "reasons": all_reasons,
        "emoji": emoji, "color": color, "url": url_clean,
        "ml_proba": ml_proba, "ml_used": ml_used,
        "url_score": url_score, "whois_score": whois_score,
        "attack_score": attack_score,
        "api_score": api_score,
        "api_vt": api_result.get("vt_score", 0),
        "api_uh": api_result.get("uh_score", 0),
        "is_trusted": is_gov_edu,
    }
