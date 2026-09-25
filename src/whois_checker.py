
"""
AmanQR - WHOIS Checker Module
Checks domain age and WHOIS visibility.
"""
import whois
from datetime import datetime, timezone
from urllib.parse import urlparse
import re


TRUSTED_WHOIS = {
    "google.com", "taobao.com", "wikipedia.org", "youtube.com",
    "facebook.com", "amazon.com", "apple.com", "microsoft.com",
    "twitter.com", "instagram.com", "linkedin.com", "github.com",
    "google.com.sa", "gov.sa", "stc.com.sa", "aramco.com",
}


def extract_base_domain(url):
    if not url:
        return None
    url = url.strip()
    if "http" in url.lower():
        url = url[url.lower().index("http"):]
    url = re.split(r"\s+Name:", url)[0]
    url = re.sub(r"^\d+\s+", "", url)
    
    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        domain = parsed.netloc.lower()
        parts = domain.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
    except:
        pass
    return None


def whois_check(url):
    """
    Returns: (score_adjustment, reason)
    """
    domain = extract_base_domain(url)
    if not domain:
        return 0, "No domain"
    
    if any(domain.endswith(td) for td in TRUSTED_WHOIS):
        return -15, f"Known trusted: {domain}"
    
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        
        if creation is None:
            return 15, "WHOIS information hidden"
        
        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)
        
        age_days = (datetime.now(timezone.utc) - creation).days
        age_years = age_days / 365.25
        
        if age_days < 30:
            return 40, f"Domain very new ({age_days} days)"
        elif age_days < 90:
            return 25, f"Domain new ({age_days} days)"
        elif age_days < 365:
            return 10, f"Domain young ({age_days} days)"
        else:
            return -5, f"Domain old ({age_years:.1f} years)"
    except Exception as e:
        err = str(e).lower()
        if "no match" in err or "not found" in err:
            return 20, "Domain not found in WHOIS"
        return 5, "WHOIS lookup failed"
