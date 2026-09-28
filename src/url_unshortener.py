"""
AmanQR - URL Unshortener v2
Handles: HTTP redirects + HTML meta refresh + JS redirects
"""
import re
import requests
from urllib.parse import urlparse


SHORTENERS = {
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
    'buff.ly', 'rebrand.ly', 'shorturl.at', 'tiny.cc', 'rb.gy',
    'cutt.ly', 'qrco.de', 'short.link', 'bl.ink', 'soo.gd',
    'shorte.st', 'adf.ly', 'bc.vc', 'j.mp', 'v.gd',
    'cli.gs', 'tr.im', 'u.nu', 'x.co', 'po.st',
}


def is_shortener(url):
    """Check if URL is from a shortener service"""
    try:
        parsed = urlparse(url if '://' in url else 'http://' + url)
        domain = parsed.netloc.lower().replace('www.', '')
        return any(domain == s or domain.endswith('.' + s) for s in SHORTENERS)
    except Exception:
        return False


def extract_redirects_from_html(html, base_url):
    """Extract redirect targets from HTML (meta refresh, JS)"""
    redirects = []
    
    # Meta refresh
    meta_match = re.search(
        r'<meta[^>]*http-equiv=["\']refresh["\'][^>]*content=["\']\d+;\s*url=([^"\'>]+)',
        html, re.IGNORECASE
    )
    if meta_match:
        redirects.append(meta_match.group(1).strip())
    
    # JavaScript window.location
    js_patterns = [
        r'window\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']',
        r'location\.replace\(["\']([^"\']+)["\']\)',
        r'location\.href\s*=\s*["\']([^"\']+)["\']',
    ]
    
    for pattern in js_patterns:
        matches = re.findall(pattern, html, re.IGNORECASE)
        redirects.extend(matches)
    
    return redirects


def expand_url(short_url, max_hops=5, timeout=10):
    """
    Expand a shortened URL using multiple techniques.
    Returns: (final_url, redirect_chain, success)
    """
    if not short_url:
        return short_url, [], False
    
    if not short_url.startswith(('http://', 'https://')):
        short_url = 'http://' + short_url
    
    redirect_chain = [short_url]
    current_url = short_url
    
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                      'AppleWebKit/537.36 (KHTML, like Gecko) '
                      'Chrome/120.0.0.0 Safari/537.36'
    }
    
    for hop in range(max_hops):
        try:
            # Use GET (not HEAD) to get HTML content
            response = requests.get(
                current_url,
                allow_redirects=False,
                timeout=timeout,
                headers=headers,
            )
            
            # 1. HTTP redirects (301, 302, etc.)
            if response.status_code in (301, 302, 303, 307, 308):
                next_url = response.headers.get('Location')
                if next_url:
                    if next_url.startswith('/'):
                        parsed = urlparse(current_url)
                        next_url = f"{parsed.scheme}://{parsed.netloc}{next_url}"
                    
                    redirect_chain.append(next_url)
                    current_url = next_url
                    
                    if not is_shortener(current_url):
                        break
                    continue
            
            # 2. HTML-based redirects
            html = response.text
            html_redirects = extract_redirects_from_html(html, current_url)
            
            if html_redirects:
                next_url = html_redirects[0]
                # Handle relative URLs
                if next_url.startswith('/'):
                    parsed = urlparse(current_url)
                    next_url = f"{parsed.scheme}://{parsed.netloc}{next_url}"
                elif not next_url.startswith(('http://', 'https://')):
                    # Relative path
                    parsed = urlparse(current_url)
                    next_url = f"{parsed.scheme}://{parsed.netloc}/{next_url.lstrip('/')}"
                
                if next_url != current_url:
                    redirect_chain.append(next_url)
                    current_url = next_url
                    
                    if not is_shortener(current_url):
                        break
                    continue
            
            # No more redirects
            break
            
        except requests.exceptions.Timeout:
            return current_url, redirect_chain, False
        except Exception:
            return current_url, redirect_chain, False
    
    success = (current_url != short_url)
    return current_url, redirect_chain, success


def analyze_with_unshortening(url):
    """Analyze URL with automatic unshortening."""
    result = {
        'original_url': url,
        'final_url': url,
        'redirect_chain': [url],
        'is_shortened': False,
        'success': False,
    }
    
    if not url:
        return result
    
    if not is_shortener(url):
        return result
    
    result['is_shortened'] = True
    final_url, chain, success = expand_url(url)
    result['final_url'] = final_url
    result['redirect_chain'] = chain
    result['success'] = success
    
    return result
