
"""
AmanQR - URL Analyzer Module (v4)
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

EMAIL_BRANDS = [
    "hotmail", "outlook", "gmail", "yahoo", "icloud", "live",
    "msn", "aol", "protonmail", "zoho",
]

BANKING_BRANDS = [
    "paypal", "visa", "mastercard", "amex", "bank",
    "wellsfargo", "chase", "citibank", "hsbc",
    "alrajhi", "alahli", "sabb", "riyad", "snb",
]

ACTION_KEYWORDS = [
    "login", "signin", "verify", "verification", "account", "update",
    "secure", "security", "confirm", "password", "banking", "wallet",
    "authenticate", "recovery", "unlock", "suspended", "validation",
    "service", "enligne", "online", "inlogg", "accedi", "acceder",
    "atualizacao", "actualizar", "track", "tracking", "delivery",
    "colis", "package", "suivi", "bookmark", "redirect", "goto",
]

# NEW: Suspicious file patterns (hacked sites)
SUSPICIOUS_FILE_PATTERNS = [
    "admin.php", "wp-admin", "wp-login", "phpmyadmin",
    "shell.php", "c99.php", "r57.php", "backdoor",
    ".env", ".git", "config.php", "wp-config",
    "upload.php", "filemanager", "webshell",
    "xmlrpc.php", "setup.php", "install.php",
]

# NEW: Suspicious path keywords
SUSPICIOUS_PATH_KEYWORDS = [
    "admin", "administrator", "phpmyadmin", "cpanel",
    "webmail", "roundcube", "phpmailer",
    "backup", "old", "test", "tmp", "temp",
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
    text = re.split(r'\s*Name:', text)[0]
    text = re.split(r'\s+dtype:', text)[0]
    text = re.sub(r'^\d+\s+', '', text)
    text = text.replace('\n', ' ').strip()
    if 'http' in text.lower():
        text = text[text.lower().index('http'):]
    text = re.split(r'\s+Name:', text)[0]
    return text.strip()


def levenshtein_ratio(a, b):
    return SequenceMatcher(None, a.lower(), b.lower()).ratio()


def looks_like_brand(domain):
    """Check if domain base looks like a known brand"""
    domain_clean = domain.replace('-', '').replace('_', '').replace('.', '')
    parts = domain.replace('-', '.').replace('_', '.').split('.')
    
    # Check each part against brands
    for part in parts:
        for brand in BRANDS + EMAIL_BRANDS + BANKING_BRANDS:
            # Exact match within part (but part is not the brand itself)
            if brand in part and part != brand:
                return True, brand
            # Similarity check
            sim = levenshtein_ratio(brand, part)
            if 0.80 <= sim < 1.0 and len(part) >= 4:
                return True, brand
    
    return False, None


def has_brand_in_path(domain, path):
    """Check if a known brand appears in path but NOT in actual domain"""
    if not path:
        return False, None
    all_brands = BRANDS + EMAIL_BRANDS + BANKING_BRANDS
    for brand in all_brands:
        if brand in path.lower():
            domain_base = domain.split('.')[0].lower()
            if brand not in domain_base:
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
    
    # 1. Trusted domain
    is_trusted = any(domain.endswith(td) for td in TRUSTED_DOMAINS)
    if is_trusted:
        score -= 20
        reasons.append(f"Trusted domain: {domain}")
    
    # 2. Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 25
            reasons.append(f"Suspicious TLD: {tld}")
            break
    
    # 3. Free hosting
    for fh in FREE_HOSTING:
        if fh in domain:
            score += 30
            reasons.append(f"Free hosting: {fh}")
            break
    
    # 4. Shortener
    for sh in SHORTENERS:
        if sh in domain:
            score += 25
            reasons.append(f"Shortener: {sh}")
            break
    
    # 5. IP address
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
        score += 40
        reasons.append("IP address instead of domain")
    
    # 6. Brand impersonation in domain
    is_brand, brand_matched = looks_like_brand(domain)
    if is_brand and not is_trusted:
        score += 35
        reasons.append(f"Impersonates brand: {brand_matched}")
    
    # 7. Brand in PATH (phishing)
    has_path_brand, path_brand = has_brand_in_path(domain, path)
    if has_path_brand and not is_trusted:
        score += 45
        reasons.append(f"Phishing: '{path_brand}' in path")
    
    # 8. Brand + action keywords
    full_text = domain + path
    has_brand = any(b in full_text for b in BRANDS)
    has_action = any(kw in full_text for kw in ACTION_KEYWORDS)
    if has_brand and has_action and not is_trusted:
        score += 30
        reasons.append("Brand + action keywords")
    
    # 9. Random path
    if re.search(r'/[a-z0-9]{15,}', path):
        score += 25
        reasons.append("Random path")
    
    # 10. HTTP
    if url_lower.startswith('http://'):
        score += 10
        reasons.append("Not HTTPS")
    
    # 11. Long URL
    if len(url) > 100:
        score += 10
        reasons.append(f"Very long URL ({len(url)})")
    
    # 12. @ symbol
    if '@' in url_lower:
        score += 30
        reasons.append("@ symbol")
    
    # 13. Many subdomains
    if domain.count('.') > 2:
        score += 10
        reasons.append("Many subdomains")
    
    # 14. NEW: Trusted domain + suspicious path
    if is_trusted and any(kw in path for kw in ACTION_KEYWORDS):
        score += 15
        reasons.append("Trusted domain with suspicious path")
    
    # 15. NEW: Numbers in domain base (typosquatting)
    domain_base = domain.split('.')[0]
    if re.search(r'[0-9]', domain_base) and len(domain_base) > 4:
        score += 15
        reasons.append("Digits in domain (typosquatting)")
    
    # 16. Suspicious subdomain
    if domain_base in ['test', 'demo', 'dev', 'tmp', 'temp']:
        score += 15
        reasons.append(f"Suspicious subdomain: {domain_base}")
    
    # 17. NEW: Suspicious file pattern (hacked sites)
    for pattern in SUSPICIOUS_FILE_PATTERNS:
        if pattern in url_lower:
            score += 30
            reasons.append(f"Suspicious file: {pattern}")
            break
    
    # 18. NEW: Suspicious path keyword (admin panels)
    for kw in SUSPICIOUS_PATH_KEYWORDS:
        if f"/{kw}" in path or path.endswith(kw) or kw in path.split('/'):
            score += 20
            reasons.append(f"Suspicious path: {kw}")
            break
    
    score = max(0, min(100, score))
    if not reasons:
        reasons = ["No suspicious indicators"]
    
    return score, reasons
