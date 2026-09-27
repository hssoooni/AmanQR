"""
AmanQR - External API Checker (VirusTotal + URLhaus)
"""
import os
import base64
import requests
from typing import Dict, Optional


def load_env():
    """Load environment variables"""
    env_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        '.env'
    )
    env = {}
    if os.path.exists(env_path):
        with open(env_path, 'r') as f:
            for line in f:
                line = line.strip()
                if '=' in line and not line.startswith('#'):
                    key, val = line.split('=', 1)
                    env[key.strip()] = val.strip()
    return env


ENV = load_env()
VIRUSTOTAL_KEY = ENV.get('VIRUSTOTAL_API_KEY', '')
URLHAUS_KEY = ENV.get('URLHAUS_AUTH_KEY', '')


# ============================================================
# VirusTotal
# ============================================================
def check_virustotal(url: str, api_key: str = None) -> Dict:
    """
    Check URL with VirusTotal.
    Returns: dict with status, malicious, suspicious, harmless, total, score (0-100)
    """
    if not api_key:
        api_key = VIRUSTOTAL_KEY
    
    if not api_key:
        return {"status": "no_key", "score": 0}
    
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        
        response = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": api_key},
            timeout=10,
        )
        
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless = stats.get("harmless", 0)
            total = sum(stats.values()) if stats else 0
            
            # Compute score (0-100)
            if total > 0:
                score = ((malicious * 2 + suspicious) / max(total, 1)) * 100
                score = min(100, score * 3)  # Amplify
            else:
                score = 0
            
            return {
                "status": "ok",
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "total": total,
                "score": round(score, 1),
            }
        
        elif response.status_code == 404:
            return {"status": "not_found", "score": 0}
        elif response.status_code == 401:
            return {"status": "invalid_key", "score": 0}
        elif response.status_code == 429:
            return {"status": "rate_limit", "score": 0}
        else:
            return {"status": f"http_{response.status_code}", "score": 0}
    
    except Exception as e:
        return {"status": "exception", "error": str(e)[:50], "score": 0}


# ============================================================
# URLhaus
# ============================================================
def check_urlhaus(url: str, auth_key: str = None) -> Dict:
    """
    Check URL with URLhaus (abuse.ch).
    Returns: dict with status, threat, tags, score (0-100)
    """
    if not auth_key:
        auth_key = URLHAUS_KEY
    
    headers = {}
    if auth_key:
        headers["Auth-Key"] = auth_key
    
    try:
        response = requests.post(
            "https://urlhaus-api.abuse.ch/v1/url/",
            data={"url": url},
            headers=headers,
            timeout=10,
        )
        
        if response.status_code == 200:
            data = response.json()
            status = data.get("query_status", "unknown")
            
            if status == "ok":
                # URL found in database
                threat = data.get("threat", "unknown")
                tags = data.get("tags", [])
                
                # High risk if malware
                if threat == "malware_download":
                    score = 95
                elif threat == "malware":
                    score = 90
                else:
                    score = 75
                
                return {
                    "status": "found",
                    "threat": threat,
                    "tags": tags,
                    "score": score,
                }
            elif status == "no_results":
                return {"status": "clean", "score": 0}
            else:
                return {"status": status, "score": 0}
        
        return {"status": f"http_{response.status_code}", "score": 0}
    
    except Exception as e:
        return {"status": "exception", "error": str(e)[:50], "score": 0}


# ============================================================
# Combined Check
# ============================================================
def check_external_apis(url: str) -> Dict:
    """
    Check URL with both VirusTotal and URLhaus.
    Returns: dict with combined score, sources, reasons
    """
    results = {
        "virustotal": check_virustotal(url),
        "urlhaus": check_urlhaus(url),
    }
    
    # Combined score (highest wins)
    vt_score = results["virustotal"].get("score", 0)
    uh_score = results["urlhaus"].get("score", 0)
    
    combined_score = max(vt_score, uh_score)
    
    # Reasons
    reasons = []
    
    vt = results["virustotal"]
    if vt.get("status") == "ok":
        if vt.get("malicious", 0) > 0:
            reasons.append(f"🚨 VirusTotal: {vt['malicious']} engines flagged as malicious")
        elif vt.get("suspicious", 0) > 0:
            reasons.append(f"⚠️ VirusTotal: {vt['suspicious']} engines flagged as suspicious")
        elif vt.get("harmless", 0) >= 60:
            reasons.append(f"✅ VirusTotal: {vt['harmless']} engines say harmless")
    
    uh = results["urlhaus"]
    if uh.get("status") == "found":
        reasons.append(f"🚨 URLhaus: found in database (threat: {uh.get('threat', 'unknown')})")
    elif uh.get("status") == "clean":
        reasons.append("✅ URLhaus: not in malicious database")
    
    return {
        "score": combined_score,
        "sources": results,
        "reasons": reasons,
        "vt_score": vt_score,
        "uh_score": uh_score,
    }
