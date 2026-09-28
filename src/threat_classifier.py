"""
AmanQR - Threat Classifier v2
Identifies attack type, severity, and provides explanation.
"""
import re
from urllib.parse import urlparse


def classify_threat(url, analysis_result):
    """Classify threat type with better sensitivity."""
    if not url:
        return None
    
    url_lower = url.lower()
    
    try:
        parsed = urlparse(url_lower if '://' in url_lower else 'http://' + url_lower)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
    except:
        domain, path, query = "", "", ""
    
    url_score = analysis_result.get('url_score', 0)
    
    threat = {
        'attack_type': 'UNKNOWN',
        'attack_type_ar': 'غير معروف',
        'severity': 'MEDIUM',
        'severity_ar': 'متوسط',
        'indicators': [],
        'explanation': '',
        'explanation_ar': '',
        'icon': '❓',
        'color': 'gray',
    }
    
    # ============================================================
    # 1. MALWARE DISTRIBUTION
    # ============================================================
    malware_indicators = []
    malware_extensions = ['.exe', '.dll', '.apk', '.msi', '.bat', 
                          '.sh', '.bin', '.scr', '.vbs', '.jar']
    
    if any(path.endswith(ext) for ext in malware_extensions):
        malware_indicators.append(f"Direct file download ({path.split('.')[-1]})")
    
    if '/bin/' in path or path.endswith('/bin.sh'):
        malware_indicators.append("Binary file path detected")
    
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
        malware_indicators.append("Direct IP (no domain)")
    
    if ':' in domain and not domain.endswith(':443') and not domain.endswith(':80'):
        try:
            port = int(domain.split(':')[1])
            if port not in [80, 443, 8080]:
                malware_indicators.append(f"Unusual port {port}")
        except:
            pass
    
    if len(malware_indicators) >= 2:
        threat['attack_type'] = 'MALWARE'
        threat['attack_type_ar'] = 'برمجية خبيثة'
        threat['severity'] = 'CRITICAL'
        threat['severity_ar'] = 'حرج'
        threat['icon'] = '🦠'
        threat['color'] = 'red'
        threat['indicators'] = malware_indicators
        threat['explanation'] = 'URL distributes malware or connects to C2 server'
        threat['explanation_ar'] = 'الرابط يوزّع برمجيات خبيثة أو يتصل بسيرفر تحكم'
        return threat
    
    # ============================================================
    # 2. PHISHING
    # ============================================================
    phishing_indicators = []
    brands = ['paypal', 'apple', 'microsoft', 'google', 'amazon', 
              'netflix', 'facebook', 'instagram', 'whatsapp', 
              'hotmail', 'outlook', 'gmail', 'yahoo', 'bank',
              'stc', 'mobily', 'zain', 'rajhi', 'alahli']
    
    phishing_keywords = ['login', 'signin', 'sign-in', 'verify', 
                        'verification', 'account', 'update', 'secure',
                        'security', 'confirm', 'password', 'wallet',
                        'authenticate', 'recovery', 'unlock', 'suspended']
    
    domain_base = domain.split('.')[0] if domain else ''
    for brand in brands:
        if brand in path.lower() and brand not in domain_base:
            phishing_indicators.append(f"Brand '{brand}' in URL path")
            break
        domain_clean = domain_base.replace('0','o').replace('1','l').replace('3','e')
        if brand in domain_clean and brand != domain_base and brand not in domain_base:
            phishing_indicators.append(f"Typosquatting of '{brand}'")
            break
    
    found_keywords = [kw for kw in phishing_keywords if kw in url_lower]
    if found_keywords:
        phishing_indicators.append(f"Phishing keywords: {', '.join(found_keywords[:3])}")
    
    if len(phishing_indicators) >= 1:
        threat['attack_type'] = 'PHISHING'
        threat['attack_type_ar'] = 'تصيّد'
        threat['severity'] = 'HIGH'
        threat['severity_ar'] = 'عالي'
        threat['icon'] = '🎣'
        threat['color'] = 'red'
        threat['indicators'] = phishing_indicators
        threat['explanation'] = 'URL attempts to steal credentials via fake page'
        threat['explanation_ar'] = 'الرابط يحاول سرقة بيانات الدخول عبر صفحة مزيّفة'
        return threat
    
    # ============================================================
    # 3. HACKED SITE ABUSE (MORE SENSITIVE)
    # ============================================================
    hacked_indicators = []
    
    # Random long path (typical of hacked sites)
    if re.search(r'/[a-z0-9]{15,}', path):
        hacked_indicators.append("Random-looking path")
    
    # Random short path (like /x487kjf...)
    if re.search(r'/[a-z0-9]{8,}', path) and not any(kw in path for kw in 
        ['about', 'contact', 'product', 'service', 'blog', 'news', 'home']):
        if '/x' in path or re.search(r'/[a-z]\d{3,}', path):
            hacked_indicators.append("Suspicious path pattern")
    
    # Suspicious file paths
    suspicious_paths = ['/admin.php', '/wp-admin', '/phpmyadmin', 
                        '/.env', '/.git', '/backup', '/shell.php',
                        '/c99.php', '/r57.php', '/upload.php']
    for sp in suspicious_paths:
        if sp in path:
            hacked_indicators.append(f"Exposed file: {sp}")
            break
    
    # Deep subdirectory
    if path.count('/') >= 4:
        hacked_indicators.append("Deep subdirectory")
    
    # If 1 indicator + score >= 30 → hacked
    if len(hacked_indicators) >= 1 and url_score >= 25:
        threat['attack_type'] = 'HACKED_SITE'
        threat['attack_type_ar'] = 'موقع مخترق'
        threat['severity'] = 'HIGH'
        threat['severity_ar'] = 'عالي'
        threat['icon'] = '🔓'
        threat['color'] = 'orange'
        threat['indicators'] = hacked_indicators
        threat['explanation'] = 'URL hosted on compromised legitimate website'
        threat['explanation_ar'] = 'الرابط مستضاف على موقع شرعي مخترق'
        return threat
    
    # ============================================================
    # 4. SCAM / FRAUD
    # ============================================================
    scam_indicators = []
    
    if any(tld in domain for tld in ['.tk', '.ml', '.ga', '.cf', '.gq']):
        scam_indicators.append(f"Free TLD ({domain.split('.')[-1]})")
    
    if any(kw in url_lower for kw in ['free', 'winner', 'prize', 'lottery', 'gift']):
        scam_indicators.append("Scam keywords")
    
    # Free hosting abuse
    free_hosting = [
        'blogspot.com', 'blogger.com', 'wordpress.com', 'weebly.com',
        'wixsite.com', '000webhostapp.com', 'ukit.me',
        'github.io', 'netlify.app', 'vercel.app',
        'pastebin.com', 'medium.com', 'tumblr.com',
        'ghost.io', 'hashnode.dev', 'dev.to',
    ]
    if any(fh in domain for fh in free_hosting):
        scam_indicators.append(f"Hosted on {domain.split('.')[1] if len(domain.split('.')) > 1 else 'free service'}")
    
    # Random path (common in abuse)
    if re.search(r'/[a-z0-9]{7,}', path) and not any(kw in path for kw in 
        ['about', 'contact', 'product', 'service', 'blog', 'news', 'home', 'post']):
        scam_indicators.append("Random path")
    
    if len(scam_indicators) >= 1 and url_score >= 30:
        threat['attack_type'] = 'SCAM'
        threat['attack_type_ar'] = 'احتيال'
        threat['severity'] = 'HIGH'
        threat['severity_ar'] = 'عالي'
        threat['icon'] = '💰'
        threat['color'] = 'orange'
        threat['indicators'] = scam_indicators
        threat['explanation'] = 'URL is likely a scam or fraud attempt'
        threat['explanation_ar'] = 'الرابط على الأرجح محاولة احتيال'
        return threat
    
    # ============================================================
    # 5. SUSPICIOUS INFRASTRUCTURE
    # ============================================================
    infra_indicators = []
    
    if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', domain):
        infra_indicators.append("Direct IP address")
    
    if ':' in domain:
        try:
            port = int(domain.split(':')[1])
            if port not in [80, 443, 8080]:
                infra_indicators.append(f"Unusual port {port}")
        except:
            pass
    
    if not url_lower.startswith('https://'):
        infra_indicators.append("No HTTPS")
    
    if domain.count('.') > 2:
        infra_indicators.append("Multiple subdomains")
    
    if len(infra_indicators) >= 2:
        threat['attack_type'] = 'SUSPICIOUS_INFRA'
        threat['attack_type_ar'] = 'بنية مشبوهة'
        threat['severity'] = 'MEDIUM'
        threat['severity_ar'] = 'متوسط'
        threat['icon'] = '⚠️'
        threat['color'] = 'yellow'
        threat['indicators'] = infra_indicators
        threat['explanation'] = 'URL uses suspicious infrastructure'
        threat['explanation_ar'] = 'الرابط يستخدم بنية تحتية مشبوهة'
        return threat
    
    # ============================================================
    # 6. NO THREAT
    # ============================================================
    threat['attack_type'] = 'NO_THREAT'
    threat['attack_type_ar'] = 'لا يوجد تهديد'
    threat['severity'] = 'SAFE'
    threat['severity_ar'] = 'آمن'
    threat['icon'] = '✅'
    threat['color'] = 'green'
    threat['explanation'] = 'No attack patterns detected'
    threat['explanation_ar'] = 'لم يتم اكتشاف أنماط هجوم'
    
    return threat
