# ============================================================
# lookalike.py – Look-Alike / Typosquatting Domain Detection
# Detects domains impersonating well-known brands.
# Handles leet-speak substitutions: g00gle, paypa1, amaz0n …
# ============================================================

from thefuzz import fuzz

# Brand name → real trusted domain
TRUSTED_BRANDS = {
    'google':         'google.com',
    'paypal':         'paypal.com',
    'amazon':         'amazon.com',
    'apple':          'apple.com',
    'microsoft':      'microsoft.com',
    'facebook':       'facebook.com',
    'twitter':        'twitter.com',
    'instagram':      'instagram.com',
    'netflix':        'netflix.com',
    'ebay':           'ebay.com',
    'linkedin':       'linkedin.com',
    'dropbox':        'dropbox.com',
    'github':         'github.com',
    'chase':          'chase.com',
    'wellsfargo':     'wellsfargo.com',
    'bankofamerica':  'bankofamerica.com',
    'citibank':       'citibank.com',
    'yahoo':          'yahoo.com',
    'outlook':        'outlook.com',
    'whatsapp':       'whatsapp.com',
}

# Number / symbol → letter substitutions used in typosquatting
_LEET = str.maketrans({
    '0': 'o', '1': 'l', '2': 'z', '3': 'e',
    '4': 'a', '5': 's', '6': 'g', '7': 't',
    '8': 'b', '9': 'g', '@': 'a', '$': 's',
    '!': 'i', '|': 'l',
})

# Suspicious keywords that appear in phishing domains
_SUSPICIOUS_KEYWORDS = {
    'login', 'signin', 'secure', 'security', 'verify',
    'account', 'update', 'confirm', 'banking', 'support',
    'password', 'credential', 'auth', 'wallet', 'payment',
}


def _normalize(s: str) -> str:
    """Translate leet-speak characters to their letter equivalents."""
    return s.translate(_LEET)


def check_lookalike(domain: str) -> dict:
    """
    Compare a domain against known trusted brands.
    Returns match info if typosquatting is suspected.
    """
    if not domain:
        return {'detected': False}

    domain = domain.lower().strip()

    # Remove www prefix
    if domain.startswith('www.'):
        domain = domain[4:]

    # Check if it IS the real domain (exact match)
    for brand, trusted_domain in TRUSTED_BRANDS.items():
        if domain == trusted_domain or domain.endswith('.' + trusted_domain):
            return {'detected': False}

    # Split into parts: SLD and full domain for scoring
    parts       = domain.split('.')
    domain_name = parts[0]  # e.g. "g00gle-login-security" → "g00gle-login-security"

    # Normalize leet-speak substitutions
    norm_name = _normalize(domain_name)

    # Also grab just the brand-like part (before first hyphen)
    brand_part = norm_name.split('-')[0]  # "google" from "google-login-security"

    best_score = 0
    best_match = None

    for brand, trusted_domain in TRUSTED_BRANDS.items():
        # Score against full normalized name
        s1 = fuzz.ratio(norm_name, brand)
        # Score against brand part only (handles "g00gle-login-security")
        s2 = fuzz.ratio(brand_part, brand)
        # Partial ratio for substrings
        s3 = fuzz.partial_ratio(brand, norm_name)

        combined = max(s1, s2, s3)

        if combined > best_score:
            best_score = combined
            best_match = trusted_domain

    # Keyword boost: if domain contains suspicious words alongside brand similarity
    all_parts = set(domain_name.replace('-', '.').split('.'))
    keyword_hit = bool(all_parts & _SUSPICIOUS_KEYWORDS)

    # Lower threshold when suspicious keywords are present
    threshold = 68 if keyword_hit else 78

    if best_score >= threshold and best_match:
        return {
            'detected':         True,
            'similar_to':       best_match,
            'similarity_score': best_score,
            'keyword_boost':    keyword_hit,
        }

    return {'detected': False}

