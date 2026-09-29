import numpy as np
from src.homograph_detector import detect_homograph

# Global for abuse score
LAST_ABUSE_SCORE = 0

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
    # Web shell / admin panels
    "admin.php", "wp-admin", "wp-login", "phpmyadmin",
    "shell.php", "c99.php", "r57.php", "backdoor",
    ".env", ".git", "config.php", "wp-config",
    "upload.php", "filemanager", "webshell",
    "xmlrpc.php", "setup.php", "install.php",
    # Dangerous script files (NEW)
    ".ps1",       # PowerShell
    ".bat",       # Batch
    ".cmd",       # Command
    ".vbs",       # VBScript
    ".js",        # JavaScript (when executed)
    ".hta",       # HTML Application
    ".wsf",       # Windows Script
    ".scr",       # Screensaver (often malware)
    ".pif",       # Program Information File
    ".msi",       # MS Installer
    ".dll",       # Dynamic Link Library
    ".jar",       # Java Archive
    # Executables
    ".exe", ".apk", ".dmg", ".app", ".deb", ".rpm",
]

# NEW: Suspicious path keywords
SUSPICIOUS_PATH_KEYWORDS = [
    "admin", "administrator", "phpmyadmin", "cpanel",
    "webmail", "roundcube", "phpmailer",
    "backup", "old", "test", "tmp", "temp",
]



SUSPICIOUS_TLDS = {
    # Free/high-risk TLDs
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
    '.work', '.click', '.country', '.stream', '.download',
    '.review', '.loan', '.date', '.gdn', '.men', '.racing',
    # Blog/personal platforms (often abused)
    '.blog', '.site', '.online', '.website', '.space',
    '.store', '.fun', '.live', '.icu', '.rest',
    '.cyou', '.monster', '.quest', '.bar', '.bond',
    '.link', '.email', '.photos',
}

FREE_HOSTING = {
    # Free website hosting
    '000webhostapp.com', 'ukit.me', 'weebly.com', 'wixsite.com',
    'blogspot.com', 'wordpress.com', 'github.io', 'netlify.app',
    'vercel.app', 'herokuapp.com', 'firebaseapp.com', 'web.app',
    'glitch.me', 'repl.co', 'r2.dev',
    # Blog platforms
    'blogger.com', 'tumblr.com', 'medium.com', 'substack.com',
    'ghost.io', 'hashnode.dev', 'dev.to',
    # Website builders
    'godaddysites.com', 'site123.me', 'jimdofree.com',
    'webflow.io', 'carrd.co', 'notion.site',
    # Paste/file sharing (often abused)
    'pastebin.com', 'ghostbin.com', 'hastebin.com',
    'paste.ee', 'controlc.com',
    # Cloud storage
    'drive.google.com', 'dropbox.com', 'mega.nz',
    'mediafire.com', '4shared.com', 'anonfiles.com',
    'gofile.io',
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



# ============================================================
# GitHub / Blogspot / Free hosting abuse patterns
# ============================================================
ABUSE_HOSTING = {
    'github.com': {
        'paths': ['/releases/', '/downloads/', '/download/', '/raw/', '/blob/'],
        'files': ['.exe', '.apk', '.msi', '.dmg', '.zip', '.rar', '.sh', '.bin', '.jar'],
    },
    'raw.githubusercontent.com': {
        'paths': ['/'],
        'files': ['.exe', '.apk', '.msi', '.dmg', '.sh', '.bin', '.jar'],
    },
    'gitlab.com': {
        'paths': ['/releases/', '/downloads/', '/raw/'],
        'files': ['.exe', '.apk', '.msi', '.sh', '.bin'],
    },
    'blogspot.com': {
        'paths': ['/p/', '/page/'],
        'files': [],
    },
}




# ============================================================
# Hosting Abuse Detection (GitHub, GitLab, Blogspot, etc.)
# ============================================================
def check_hosting_abuse(domain, path):
    """
    Check if trusted hosting service is being abused.
    Returns: (score, reasons)
    """
    score = 0
    reasons = []
    path_lower = path.lower()
    domain_lower = domain.lower()
    
    # Known hosting services and their abuse patterns
    ABUSE_PATTERNS = {
        'github.com': {
            'suspicious_paths': ['/releases/', '/downloads/', '/releases/download/', '/raw/'],
            'file_extensions': ['.exe', '.apk', '.msi', '.dmg', '.sh', '.bin', '.jar', '.scr', '.vbs'],
            'suspicious_keywords': ['malware', 'virus', 'trojan', 'crack', 'hack', 'cheat', 'keygen'],
        },
        'raw.githubusercontent.com': {
            'suspicious_paths': ['/'],
            'file_extensions': ['.exe', '.apk', '.msi', '.sh', '.bin', '.jar'],
            'suspicious_keywords': [],
        },
        'gitlab.com': {
            'suspicious_paths': ['/releases/', '/downloads/', '/raw/'],
            'file_extensions': ['.exe', '.apk', '.sh', '.bin'],
            'suspicious_keywords': [],
        },
        'bitbucket.org': {
            'suspicious_paths': ['/downloads/', '/raw/'],
            'file_extensions': ['.exe', '.apk', '.sh', '.bin'],
            'suspicious_keywords': [],
        },
        'blogspot.com': {
            'suspicious_paths': [],
            'file_extensions': [],
            'suspicious_keywords': ['free-download', 'crack', 'keygen', 'hack'],
        },
    }
    
    # Check each hosting service
    for host, patterns in ABUSE_PATTERNS.items():
        if host in domain_lower:
            # 1. Check suspicious paths
            for sus_path in patterns['suspicious_paths']:
                if sus_path in path_lower:
                    score += 35
                    reasons.append(f"🚨 Suspicious path on {host}: {sus_path}")
                    break
            
            # 2. Check for executable file extensions
            for ext in patterns['file_extensions']:
                if ext in path_lower:
                    score += 40
                    reasons.append(f"🚨 Executable file on {host}: {ext}")
                    break
            
            # 3. Check suspicious keywords in path
            for kw in patterns['suspicious_keywords']:
                if kw in path_lower:
                    score += 30
                    reasons.append(f"🚨 Suspicious keyword on {host}: {kw}")
                    break
            
            break
    
    return score, reasons




# ============================================================
# Known malicious domains (from URLhaus, threat feeds)
# Update regularly from: https://urlhaus.abuse.ch/
# ============================================================
KNOWN_MALICIOUS_DOMAINS = {
    # From URLhaus recent (examples)
    'trust-soft.cc',
    'rabbids.cc',
    'polysupport.team',
    'cdn.jsdelivr.net',
    'downf468.com',
    'moziloader.com',
    # Add more from URLhaus as discovered
}




# ============================================================
# FreeDNS services (often abused for malware C2)
# ============================================================
FREEDNS_DOMAINS = {
    '.work.gd', '.ddns.net', '.no-ip.org', '.hopto.org',
    '.zapto.org', '.sytes.net', '.webhop.me', '.myftp.org',
    '.servebeer.com', '.serveftp.com', '.dynu.com', '.dynns.com',
    '.myvnc.com', '.ignorelist.com', '.chickenkiller.com',
    '.jumpingcrab.com', '.crabdance.com', '.strangled.net',
    '.mooo.com', '.3utilities.com', '.bounceme.net',
    '.ddnsguru.com', '.dnset.com', '.dyn-o-saur.com',
}

# IoT malware architectures (binaries for IoT devices)
IOT_ARCHITECTURES = [
    'mipsel', 'mips', 'arm7', 'arm', 'x86', 'i386', 'i586',
    'sparc', 'ppc', 'powerpc', 'sh4', 'm68k', 'arc',
    'aarch64', 'armv7', 'armv6', 'x86_64',
]




# ============================================================
# Trusted services (whitelist — skip all suspicious checks)
# ============================================================
TRUSTED_SERVICES = {
    # Google services
    'docs.google.com', 'drive.google.com', 'sheets.google.com',
    'slides.google.com', 'forms.gle', 'calendar.google.com',
    'sites.google.com', 'meet.google.com', 'photos.google.com',
    'mail.google.com', 'accounts.google.com',
    # Microsoft services
    'forms.office.com', 'onedrive.live.com', 'sharepoint.com',
    'outlook.office.com', 'docs.microsoft.com', 'teams.microsoft.com',
    # Productivity
    'notion.so', 'airtable.com', 'typeform.com', 'surveymonkey.com',
    'trello.com', 'asana.com', 'monday.com', 'clickup.com',
    # Cloud storage
    'dropbox.com', 'box.com', 'mega.nz',
    # Learning platforms
    'coursera.org', 'udemy.com', 'edx.org', 'khanacademy.org',
    'udacity.com', 'pluralsight.com', 'skillshare.com',
    # Government (Saudi)
    'gov.sa', 'my.gov.sa', 'moe.gov.sa', 'moh.gov.sa',
    'hrsd.gov.sa', 'tawakkalna.gov.sa', 'absher.gov.sa',
}

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
    
    # ============================================================
    # FREEDNS + GIBBERISH + IoT DETECTION (CRITICAL)
    # ============================================================
    # 1. Free DNS services
    FREEDNS_LIST = ['.work.gd', '.ddns.net', '.no-ip.org', '.hopto.org',
                    '.zapto.org', '.dynu.com', '.chickenkiller.com',
                    '.mooo.com', '.3utilities.com', '.sytes.net',
                    '.myftp.org', '.servebeer.com', '.dynns.com']
    for fdns in FREEDNS_LIST:
        if fdns in domain or domain.endswith(fdns):
            score += 40
            reasons.append(f"🚨 Free DNS service: {fdns}")
            break
    
    # 2. Gibberish subdomain
    domain_base = domain.split('.')[0] if domain else ''
    if len(domain_base) >= 10:
        vowels = sum(1 for c in domain_base if c in 'aeiou')
        vowel_ratio = vowels / max(len(domain_base), 1)
        
        if vowel_ratio < 0.25:
            score += 35
            reasons.append(f"🚨 Random gibberish domain: {domain_base[:20]}")
    
    # 3. IoT malware architecture paths
    IOT_ARCHS = ['mipsel', 'mips', 'arm7', 'arm', 'x86', 'i386', 
                 'sparc', 'ppc', 'sh4', 'm68k', 'aarch64', 'armv7']
    for arch in IOT_ARCHS:
        if path.endswith(f'/{arch}') or path == f'/{arch}' or f'/{arch}/' in path:
            score += 50
            reasons.append(f"🚨 IoT malware binary: /{arch}")
            break
    

        # ---- HOMOGRAPH ATTACK CHECK (HIGHEST PRIORITY) ----
    is_homograph, homograph_reasons, decoded_name = detect_homograph(url)
    if is_homograph:
        score += 95  # Critical threat
        reasons.extend(homograph_reasons)
        if decoded_name and decoded_name != domain:
            reasons.append(f"→ Real lookalike: {decoded_name}")
        return score, reasons, 0  # Immediate MALICIOUS
    
    # ---- WHITELIST: Trusted services (highest priority) ----
    for service in TRUSTED_SERVICES:
        if service in domain or domain.endswith(service):
            reasons.append(f"✅ Trusted service: {service}")
            return 0, reasons, 0  # SAFE, no abuse
    

# ---- 0. KNOWN MALICIOUS DOMAINS ----
    for mal_domain in KNOWN_MALICIOUS_DOMAINS:
        if mal_domain in domain:
            score += 80
            reasons.append(f"🚨 Known malicious domain: {mal_domain}")
            break

    
    # 1. Trusted TLD ONLY (objective rule — .gov.sa, .edu.sa)
    is_trusted = False
    
    # Only TLD-based trust (legal, objective)
    if any(domain.endswith(suffix) for suffix in TRUSTED_TLD_SUFFIXES):
        is_trusted = True
        score -= 40
        reasons.append(f"✅ Official domain ({domain.split('.')[-2]}.{domain.split('.')[-1]})")
    
    # 2. Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 5
            reasons.append(f"ℹ️ TLD: {tld}")
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
    
    # 14. (removed: trusted domain + suspicious path rule)
    
    # 15. NEW: Numbers in domain base (typosquatting)
    domain_base = domain.split('.')[0]
    if re.search(r'[0-9]', domain_base) and len(domain_base) > 4:
        score += 15
        reasons.append("Digits in domain (typosquatting)")
    
    # 16. Suspicious subdomain
    if domain_base in ['test', 'demo', 'dev', 'tmp', 'temp']:
        score += 15
        reasons.append(f"Suspicious subdomain: {domain_base}")
    
    # 16.5 DANGEROUS EXTENSIONS CHECK
    dangerous_exts = ['.ps1', '.bat', '.cmd', '.vbs', '.hta', '.wsf',
                      '.exe', '.apk', '.msi', '.dll', '.jar', '.scr', 
                      '.pif', '.dmg', '.app', '.deb', '.rpm', '.bin',
                      '.sh', '.run', '.com']
    for ext in dangerous_exts:
        if path.endswith(ext) or f'{ext}?' in url_lower or f'{ext}#' in url_lower:
            score += 50
            reasons.append(f"🚨 Dangerous file: {ext}")
            break
    
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
    
        # ---- HOSTING ABUSE CHECK (NEW) ----
    abuse_score, abuse_reasons = check_hosting_abuse(domain, path)
    if abuse_score > 0:
        score += abuse_score
        reasons.extend(abuse_reasons)
        # Store abuse score globally for decision_engine
        global LAST_ABUSE_SCORE
        LAST_ABUSE_SCORE = abuse_score
    else:
        LAST_ABUSE_SCORE = 0
    
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
