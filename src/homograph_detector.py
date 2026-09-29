"""
AmanQR - Homograph Attack Detector
Detects Cyrillic/Greek/Arabic characters that look like Latin.
"""
import unicodedata
from urllib.parse import urlparse


# Latin characters and their Unicode confusables (homograph attack letters)
# Format: {latin_char: [list of unicode confusables]}
HOMOGRAPH_MAP = {
    'a': ['\u0430', '\u03b1', '\u1d00'],  # Cyrillic, Greek, etc
    'c': ['\u0441', '\u03f2'],
    'e': ['\u0435', '\u04bd', '\u212e'],
    'i': ['\u0456', '\u0457', '\u04cf', '\u03b9'],
    'j': ['\u0458'],
    'o': ['\u043e', '\u03bf', '\u04e7', '\u0d20'],
    'p': ['\u0440', '\u03c1', '\u03f7'],
    's': ['\u0455', '\u03c2'],
    'x': ['\u0445', '\u03c7'],
    'y': ['\u0443', '\u04af'],
    'k': ['\u043a', '\u03ba'],
    'm': ['\u043c', '\u043c'],
    'n': ['\u03bd'],
    'u': ['\u057d'],
    'v': ['\u0475', '\u03bd'],
    'b': ['\u0431'],
    'd': ['\u0501'],
    'f': ['\u03dc'],
    'g': ['\u0261'],
    'h': ['\u04bb'],
    'l': ['\u04c0', '\u01c0', '\u0399'],
    'q': ['\u0566'],
    'r': ['\u0433'],
    't': ['\u03c4'],
    'w': ['\u0461'],
    'z': ['\u0290'],
}

# Latin alphabet ranges
LATIN_RANGES = [
    (0x0041, 0x005A),  # A-Z
    (0x0061, 0x007A),  # a-z
    (0x0030, 0x0039),  # 0-9
]

# Common Latin punctuation & special chars
LATIN_SPECIALS = set('.-_~')


def is_latin_char(char):
    """Check if char is standard Latin/ASCII"""
    code = ord(char)
    for start, end in LATIN_RANGES:
        if start <= code <= end:
            return True
    if char in LATIN_SPECIALS:
        return True
    return False


def get_char_script(char):
    """Get Unicode script of a character"""
    try:
        name = unicodedata.name(char)
        if 'CYRILLIC' in name:
            return 'Cyrillic'
        elif 'GREEK' in name:
            return 'Greek'
        elif 'ARABIC' in name:
            return 'Arabic'
        elif 'HEBREW' in name:
            return 'Hebrew'
        elif 'LATIN' in name:
            return 'Latin'
        elif 'ARMENIAN' in name:
            return 'Armenian'
        elif 'GEORGIAN' in name:
            return 'Georgian'
        elif 'THAI' in name:
            return 'Thai'
        elif 'HANGUL' in name:
            return 'Hangul'
        elif 'CJK' in name or 'CHINESE' in name or 'JAPANESE' in name:
            return 'CJK'
        else:
            return 'Other'
    except ValueError:
        return 'Unknown'


def find_homograph_chars(domain):
    """Find characters that look like Latin but aren't"""
    suspicious = []
    
    for char in domain:
        if is_latin_char(char):
            continue
        
        script = get_char_script(char)
        
        # Check if it looks like a Latin character
        for latin_char, confusables in HOMOGRAPH_MAP.items():
            if char in confusables:
                suspicious.append({
                    'fake_char': char,
                    'latin_lookalike': latin_char,
                    'script': script,
                    'codepoint': f'U+{ord(char):04X}',
                })
                break
    
    return suspicious


def detect_homograph(url):
    """
    Detect homograph attacks in a URL.
    Returns: (is_attack, reasons, decoded_name)
    """
    if not url:
        return False, [], None
    
    try:
        parsed = urlparse(url.lower() if '://' in url else 'http://' + url)
        domain = parsed.netloc.lower()
    except Exception:
        return False, [], None
    
    if not domain:
        return False, [], None
    
    # Remove port
    domain = domain.split(':')[0]
    
    suspicious = find_homograph_chars(domain)
    
    # Also check for mixed scripts
    scripts_found = set()
    for char in domain:
        if not is_latin_char(char):
            scripts_found.add(get_char_script(char))
    
    # Attack detected if:
    # 1. Multiple fake Latin chars, OR
    # 2. Mixed scripts (Latin + Cyrillic/Greek/etc.)
    is_attack = False
    reasons = []
    
    if len(suspicious) >= 2:
        is_attack = True
        reasons.append(f"🚨 HOMOGRAPH ATTACK: {len(suspicious)} fake characters detected")
        
        # Group by script
        scripts = set(s['script'] for s in suspicious)
        for script in scripts:
            fake_in_script = [s for s in suspicious if s['script'] == script]
            reasons.append(f"• Fake {script} chars: " + 
                          ', '.join(f"{s['fake_char']}(U+{ord(s['fake_char']):04X})→{s['latin_lookalike']}" 
                                   for s in fake_in_script[:5]))
    
    elif len(scripts_found) >= 1 and len(suspicious) >= 1:
        # Mixed script attack
        if any(c.isascii() and c.isalpha() for c in domain):
            is_attack = True
            reasons.append(f"🚨 HOMOGRAPH (mixed script): {'/'.join(scripts_found)} + Latin")
    
    # Generate ASCII name for reference
    decoded = domain
    for s in suspicious:
        decoded = decoded.replace(s['fake_char'], s['latin_lookalike'])
    
    return is_attack, reasons, decoded
