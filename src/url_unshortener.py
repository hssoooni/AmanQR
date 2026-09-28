"""
AmanQR - URL Unshortener
Expands shortened URLs to reveal their true destination.
"""
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


def expand_url(short_url, max_hops=5, timeout=5):
    """
    Expand a shortened URL by following redirects.
    Returns: (final_url, redirect_chain, success)
    """
    if not short_url:
        return short_url, [], False
    
    if not short_url.startswith(('http://', 'https://')):
        short_url = 'http://' + short_url
    
    redirect_chain = [short_url]
    current_url = short_url
    
    for hop in range(max_hops):
        try:
            response = requests.head(
                current_url,
                allow_redirects=False,
                timeout=timeout,
                headers={'User-Agent': 'Mozilla/5.0 (compatible; AmanQR/1.0)'}
            )
            
            if response.status_code in (301, 302, 303, 307, 308):
                next_url = response.headers.get('Location')
                if not next_url:
                    break
                
                if next_url.startswith('/'):
                    parsed = urlparse(current_url)
                    next_url = f"{parsed.scheme}://{parsed.netloc}{next_url}"
                
                redirect_chain.append(next_url)
                current_url = next_url
                
                if not is_shortener(current_url):
                    break
            else:
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
