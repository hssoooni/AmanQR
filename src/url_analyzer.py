import numpy as np

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

# Extended trusted domains (Saudi Arabia + global education)
TRUSTED_DOMAINS_EXTENDED = {
    # Government
    'gov.sa', 'my.gov.sa', 'moe.gov.sa', 'moh.gov.sa',
    'hrsd.gov.sa', 'tawakkalna.gov.sa', 'absher.gov.sa',
    'najiz.sa', 'etec.gov.sa', 'sdaia.gov.sa',
    'hasen.gov.sa', 'tahqaq.gov.sa',  # Saudi cybersecurity
    
    # Education (Saudi)
    'edu.sa', 'ksu.edu.sa', 'kau.edu.sa', 'kfupm.edu.sa',
    'pnu.edu.sa', 'imamu.edu.sa', 'qu.edu.sa', 'ut.edu.sa',
    
    # Global education
    'coursera.org', 'udemy.com', 'edx.org', 'khanacademy.org',
    'w3schools.com', 'freecodecamp.org',
    
    # Saudi training platforms
    'futurex.sa', 'doroob.sa', 'misk.org.sa',
    
    # Saudi banks
    'alrajhibank.com.sa', 'alahli.com', 'sabb.com',
    'riyadbank.com', 'alinma.com', 'saib.com.sa', 'snb.com.sa',
    
    # Saudi companies
    'aramco.com', 'sabic.com', 'stc.com.sa', 'mobily.com.sa',
    'zain.com.sa', 'maaden.com.sa', 'neom.com',
}

# Trusted TLD suffixes (auto-trusted)
TRUSTED_TLD_SUFFIXES = [
    '.gov.sa', '.edu.sa', '.mil.sa', '.gov', '.edu',
    '.gov.uk', '.gov.ae', '.gov.eg', '.edu.ae', '.edu.eg',
]




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
    
    # 1. Trusted domain (extended)
    is_trusted = False
    
    # Check exact trusted domains
    if any(domain.endswith(td) for td in TRUSTED_DOMAINS):
        is_trusted = True
    # Check extended trusted
    elif any(domain.endswith(td) for td in TRUSTED_DOMAINS_EXTENDED):
        is_trusted = True
    # Check trusted TLD suffixes (.gov.sa, .edu.sa)
    elif any(domain.endswith(suffix) for suffix in TRUSTED_TLD_SUFFIXES):
        is_trusted = True
    
    if is_trusted:
        score -= 30
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


# ============================================================
# ML Feature Extraction (must match training)
# ============================================================
from urllib.parse import urlparse
from tldextract import extract as tld_extract

SUSPICIOUS_TLDS_ML = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.work', '.click',
    '.country', '.stream', '.download', '.review', '.loan', '.date',
    '.online', '.site', '.website', '.space', '.store', '.fun',
}

TRUSTED_DOMAINS_ML = {
    'google.com', 'google.com.sa', 'youtube.com', 'facebook.com',
    'wikipedia.org', 'twitter.com', 'instagram.com', 'amazon.com',
    'apple.com', 'microsoft.com', 'linkedin.com', 'github.com',
    'stackoverflow.com', 'reddit.com', 'taobao.com', 'alibaba.com',
    'weibo.com', 'baidu.com', 'gov.sa', 'my.gov.sa', 'aramco.com',
    'stc.com.sa', 'mobily.com.sa', 'zain.com.sa', 'sabb.com',
    'alrajhibank.com.sa',
}

PHISHING_KEYWORDS_ML = [
    'login', 'signin', 'verify', 'verification', 'account', 'update',
    'secure', 'security', 'confirm', 'password', 'banking', 'wallet',
    'authenticate', 'recovery', 'unlock', 'suspended', 'validation',
    'service', 'enligne', 'online', 'inlogg', 'accedi', 'acceder',
    'atualizacao', 'actualizar', 'track', 'tracking', 'delivery',
    'colis', 'package', 'suivi', 'bookmark', 'redirect', 'goto',
]

BRANDS_ML = [
    'google', 'youtube', 'facebook', 'instagram', 'twitter', 'whatsapp',
    'amazon', 'apple', 'microsoft', 'netflix', 'paypal', 'linkedin',
    'hotmail', 'outlook', 'gmail', 'yahoo', 'icloud',
    'dhl', 'fedex', 'ups', 'chronopost',
    'bank', 'visa', 'mastercard',
]


def extract_features_for_ml(url):
    """Extract 28 features for ML model"""
    if not url or not isinstance(url, str):
        return None
    
    url = url.strip()
    if not url:
        return None
    
    try:
        parsed = urlparse(url if '://' in url else 'http://' + url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
    except:
        return None
    
    if not domain:
        return None
    
    features = {}
    features['url_length'] = len(url)
    features['domain_length'] = len(domain)
    features['path_length'] = len(path)
    features['query_length'] = len(query)
    features['num_dots'] = domain.count('.')
    features['num_digits_url'] = sum(c.isdigit() for c in url)
    features['num_digits_domain'] = sum(c.isdigit() for c in domain)
    features['num_hyphens'] = url.count('-')
    features['num_slashes'] = url.count('/')
    features['num_underscores'] = url.count('_')
    features['is_https'] = 1 if url.lower().startswith('https://') else 0
    features['is_http'] = 1 if url.lower().startswith('http://') else 0
    
    try:
        tld_info = tld_extract(domain)
        tld = '.' + tld_info.suffix if tld_info.suffix else ''
    except:
        tld = ''
    
    features['suspicious_tld'] = 1 if tld in SUSPICIOUS_TLDS_ML else 0
    features['trusted_domain'] = 1 if any(domain.endswith(td) for td in TRUSTED_DOMAINS_ML) else 0
    features['num_subdomains'] = max(0, domain.count('.') - 1)
    features['is_ip'] = 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain) else 0
    
    shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'cutt.ly']
    features['is_shortener'] = 1 if any(s in domain for s in shorteners) else 0
    
    free_hosting = ['000webhostapp.com', 'ukit.me', 'weebly.com', 'wixsite.com',
                    'blogspot.com', 'wordpress.com', 'netlify.app', 'vercel.app']
    features['is_free_hosting'] = 1 if any(f in domain for f in free_hosting) else 0
    
    full_text = domain + path + query
    features['has_phishing_keyword'] = 1 if any(kw in full_text for kw in PHISHING_KEYWORDS_ML) else 0
    features['num_phishing_keywords'] = sum(1 for kw in PHISHING_KEYWORDS_ML if kw in full_text)
    features['has_brand'] = 1 if any(b in full_text for b in BRANDS_ML) else 0
    features['num_brands'] = sum(1 for b in BRANDS_ML if b in full_text)
    features['brand_in_path'] = 1 if any(b in path for b in BRANDS_ML) else 0
    
    if domain:
        from collections import Counter
        counts = Counter(domain)
        probs = [c / len(domain) for c in counts.values()]
        features['domain_entropy'] = -sum(p * np.log2(p) for p in probs if p > 0)
    else:
        features['domain_entropy'] = 0
    
    text_clean = re.sub(r'[^a-z]', '', domain)
    max_consonant_run = 0
    current_run = 0
    for c in text_clean:
        if c not in 'aeiou':
            current_run += 1
            max_consonant_run = max(max_consonant_run, current_run)
        else:
            current_run = 0
    features['max_consonant_run'] = max_consonant_run
    
    vowels = sum(1 for c in text_clean if c in 'aeiou')
    features['vowel_ratio'] = vowels / max(len(text_clean), 1)
    features['has_random_path'] = 1 if re.search(r'/[a-z0-9]{10,}', path) else 0
    features['digit_ratio_domain'] = sum(c.isdigit() for c in domain) / max(len(domain), 1)
    
    return features
