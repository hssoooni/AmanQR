
"""
AmanQR - URL Analyzer Module
Rule-based detection of malicious URLs in QR codes.
"""
import re
from urllib.parse import urlparse
from difflib import SequenceMatcher

BRANDS = [
    "google", "youtube", "facebook", "instagram", "twitter", "whatsapp",
    "amazon", "apple", "microsoft", "netflix", "paypal", "linkedin",
    "dropbox", "adobe", "steam", "spotify", "tiktok",
    "bank", "visa", "mastercard", "stripe",
    "dhl", "fedex", "ups", "chronopost", "colissimo", "dpd",
    "stc", "mobily", "zain", "sabb", "rajhi", "alahli", "riyadbank",
    "alinma", "saib", "snb", "aramco", "sabic", "maaden",
    "gov", "moi", "mofa", "moh", "absher", "tawakkalna", "najiz",
]

ACTION_KEYWORDS = [
    "login", "signin", "verify", "verification", "account", "update",
    "secure", "security", "confirm", "password", "banking", "wallet",
    "authenticate", "recovery", "unlock", "suspended", "validation",
    "service", "enligne", "online", "inlogg", "accedi", "acceder",
    "atualizacao", "actualizar", "track", "tracking", "delivery",
    "colis", "package", "suivi",
]

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".work", ".click",
    ".country", ".stream", ".download", ".review", ".loan", ".date",
    ".online", ".site", ".website", ".space", ".store", ".fun",
}

FREE_HOSTING = {
    "000webhostapp.com", "ukit.me", "weebly.com", "wixsite.com",
    "blogspot.com", "wordpress.com", "github.io", "netlify.app",
    "vercel.app", "herokuapp.com", "firebaseapp.com", "web.app",
    "glitch.me", "repl.co", "r2.dev",
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy", "cutt.ly",
}

TRUSTED_DOMAINS = {
    "google.com", "google.com.sa", "youtube.com", "facebook.com",
    "wikipedia.org", "twitter.com", "instagram.com", "amazon.com",
    "apple.com", "microsoft.com", "linkedin.com", "github.com",
    "stackoverflow.com", "reddit.com", "taobao.com", "alibaba.com",
    "weibo.com", "baidu.com", "gov.sa", "my.gov.sa", "aramco.com",
    "stc.com.sa", "mobily.com.sa", "zain.com.sa", "sabb.com",
    "alrajhibank.com.sa",
}


def clean_url(text):
    """Remove pandas artifacts from URL string"""
    if not isinstance(text, str):
        return None
    text = text.strip()
    
    # Remove pandas "Name: url, dtype: object" suffix
    text = re.split(r"\s*Name:", text)[0]
    
    # Remove leading numbers (pandas index)
    text = re.sub(r"^\d+\s+", "", text)
    
    # Find http/https and cut everything before it
    if "http" in text.lower():
        text = text[text.lower().index("http"):]
    
    # Remove any trailing "dtype:" artifacts
    text = re.split(r"\s+dtype:", text)[0]
    
    return text.strip()


def levenshtein_ratio(a, b):
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def looks_like_brand(domain):
    domain_clean = domain.replace("-", "").replace("_", "")
    domain_base = domain_clean.split(".")[0]
    for brand in BRANDS:
        if brand in domain_clean and brand != domain_base:
            return True, brand
        sim = levenshtein_ratio(brand, domain_base)
        if 0.75 <= sim < 1.0:
            return True, brand
    return False, None


def analyze_url(url):
    if not url:
        return 0, ["No URL"]
    url = clean_url(url)
    if not url:
        return 0, ["Invalid URL"]
    
    url_lower = url.lower()
    score = 0
    reasons = []
    
    try:
        parsed = urlparse(url_lower)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
    except:
        return 0, ["Parse error"]
    
    if not domain:
        return 0, ["No domain"]
    
    is_trusted = any(domain.endswith(td) for td in TRUSTED_DOMAINS)
    if is_trusted:
        score -= 20
        reasons.append(f"Trusted domain: {domain}")
    
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 25
            reasons.append(f"Suspicious TLD: {tld}")
            break
    
    for fh in FREE_HOSTING:
        if fh in domain:
            score += 30
            reasons.append(f"Free hosting: {fh}")
            break
    
    for sh in SHORTENERS:
        if sh in domain:
            score += 25
            reasons.append(f"Shortener: {sh}")
            break
    
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", domain):
        score += 40
        reasons.append("IP address instead of domain")
    
    is_brand, brand_matched = looks_like_brand(domain)
    if is_brand and not is_trusted:
        score += 35
        reasons.append(f"Impersonates brand: {brand_matched}")
    
    full_text = domain + path
    has_brand = any(b in full_text for b in BRANDS)
    has_action = any(kw in full_text for kw in ACTION_KEYWORDS)
    if has_brand and has_action and not is_trusted:
        score += 30
        reasons.append("Brand + action keywords")
    
    if re.search(r"/[a-z0-9]{15,}", path):
        score += 25
        reasons.append("Random path (possible hacked site)")
    
    if url_lower.startswith("http://"):
        score += 10
        reasons.append("Not HTTPS")
    
    if len(url) > 100:
        score += 10
        reasons.append(f"Very long URL ({len(url)} chars)")
    
    if "@" in url_lower:
        score += 30
        reasons.append("@ symbol obfuscation")
    
    if domain.count(".") > 2:
        score += 10
        reasons.append("Many subdomains")
    
    score = max(0, min(100, score))
    if not reasons:
        reasons = ["No suspicious indicators"]
    
    return score, reasons
