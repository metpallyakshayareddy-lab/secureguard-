# ============================================================
# features.py – URL & Email Feature Extraction
# Used by both train.py (training) and app.py (prediction)
# ============================================================

import re
import math
from urllib.parse import urlparse


# ── Suspicious TLDs commonly used in phishing ──
SUSPICIOUS_TLDS = {
    '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top',
    '.click', '.win', '.loan', '.date', '.bid', '.stream',
    '.racing', '.download', '.accountant', '.trade', '.webcam',
    '.zip', '.review', '.country', '.kim', '.science', '.work',
    '.party', '.guru', '.biz', '.info'
}

# ── Brand names in phishing URLs (only suspicious when NOT on the real domain) ──
BRAND_KEYWORDS = [
    'paypal', 'amazon', 'apple', 'google', 'microsoft', 'netflix',
    'instagram', 'facebook', 'twitter', 'linkedin', 'dropbox',
    'ebay', 'chase', 'bankofamerica', 'wellsfargo', 'citibank',
]

# ── Generic phishing path/keyword indicators ──
PHISHING_KEYWORDS = [
    'login', 'verify', 'secure', 'account', 'update', 'confirm',
    'banking', 'password', 'credential', 'signin', 'billing',
    'suspended', 'unusual', 'reset', 'webscr', 'ebayisapi',
    'phishing', 'malware', 'ransomware',
]

# ── Known safe root domains (whitelist) ──
TRUSTED_DOMAINS = {
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com',
    'twitter.com', 'instagram.com', 'linkedin.com', 'microsoft.com',
    'apple.com', 'netflix.com', 'github.com', 'wikipedia.org',
    'stackoverflow.com', 'reddit.com', 'paypal.com', 'ebay.com',
    'chase.com', 'dropbox.com', 'outlook.com', 'live.com',
}


def _get_root_domain(hostname: str) -> str:
    """Extract root domain (SLD + TLD) from a hostname, e.g. sub.paypal.com → paypal.com"""
    parts = hostname.split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return hostname


def url_entropy(url: str) -> float:
    """Calculate Shannon entropy of URL characters."""
    if not url:
        return 0.0
    freq = {}
    for ch in url:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(url)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def extract_url_features(url: str) -> list:
    """
    Extract numerical features from a URL for the ML model.
    Returns a list of 16 numerical values.
    """
    url = url.strip()

    # --- Parse URL ---
    try:
        parsed   = urlparse(url if '://' in url else 'http://' + url)
        hostname = parsed.hostname or ''
        path     = parsed.path or ''
        query    = parsed.query or ''
        scheme   = parsed.scheme or ''
    except Exception:
        hostname, path, query, scheme = '', '', '', ''

    # 1. Total URL length
    url_length = len(url)

    # 2. Hostname length
    hostname_length = len(hostname)

    # 3. Path length
    path_length = len(path)

    # 4. Number of dots in URL
    num_dots = url.count('.')

    # 5. Number of hyphens in hostname
    num_hyphens = hostname.count('-')

    # 6. Number of '@' symbols (always suspicious in URL)
    num_at = url.count('@')

    # 7. Number of slashes
    num_slashes = url.count('/')

    # 8. Number of subdomains (parts of hostname minus domain + TLD)
    parts = hostname.split('.')
    num_subdomains = max(0, len(parts) - 2)

    # 9. Has IP address (1 = yes, 0 = no)
    ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
    has_ip = 1 if ip_pattern.search(hostname) else 0

    # 10. Uses HTTPS (1 = yes)
    has_https = 1 if scheme == 'https' else 0

    # 11. Suspicious TLD (1 = yes)
    tld = ('.' + parts[-1]) if parts else ''
    has_suspicious_tld = 1 if tld.lower() in SUSPICIOUS_TLDS else 0

    # 12. Phishing keyword count (generic path indicators)
    url_lower = url.lower()
    root_domain = _get_root_domain(hostname)
    keyword_count = sum(1 for kw in PHISHING_KEYWORDS if kw in url_lower)

    # 12b. Brand keyword count — only counted if NOT on the real domain
    # e.g. paypal.phishing.tk gets penalized, but paypal.com does not
    if root_domain not in TRUSTED_DOMAINS:
        keyword_count += sum(1 for bkw in BRAND_KEYWORDS if bkw in url_lower)

    # 13. Number of query parameters
    num_params = len(query.split('&')) if query else 0

    # 14. URL entropy (higher = more random/suspicious)
    entropy = url_entropy(url)

    # 15. Has port number (1 = yes, suspicious on http/https)
    has_port = 1 if parsed.port else 0

    # 16. Is the root domain a trusted/known domain?
    is_trusted_domain = 1 if root_domain in TRUSTED_DOMAINS else 0

    return [
        url_length,          # 1
        hostname_length,     # 2
        path_length,         # 3
        num_dots,            # 4
        num_hyphens,         # 5
        num_at,              # 6
        num_slashes,         # 7
        num_subdomains,      # 8
        has_ip,              # 9
        has_https,           # 10
        has_suspicious_tld,  # 11
        keyword_count,       # 12
        num_params,          # 13
        entropy,             # 14
        has_port,            # 15
        is_trusted_domain,   # 16
    ]


def extract_email_features(text: str) -> list:
    """
    Extract numerical features from email text for the ML model.
    Returns a list of 12 numerical values.
    """
    t = text.lower()
    words = text.split()

    # 1. Text length
    text_length = len(text)

    # 2. Number of URLs in text
    url_count = len(re.findall(r'https?://\S+', text, re.IGNORECASE))

    # 3. Urgent keyword count
    urgent_words = [
        'urgent', 'immediately', 'act now', 'expire', 'last chance',
        'final notice', 'action required', 'respond immediately',
        'account suspended', 'account locked', 'verify immediately',
        'final warning', 'expires tonight', 'within 24 hours',
    ]
    urgent_count = sum(1 for w in urgent_words if w in t)

    # 4. Sensitive info keyword count
    sensitive_words = [
        'password', 'credit card', 'ssn', 'social security',
        'bank account', 'cvv', 'pin number', 'date of birth',
        'confirm your', 'verify your', 'validate your',
        'bank details', 'billing information', 'payment info',
    ]
    sensitive_count = sum(1 for w in sensitive_words if w in t)

    # 5. Scam phrase count
    scam_phrases = [
        'you have won', 'lucky winner', 'claim your prize',
        'wire transfer', 'unclaimed funds', 'lottery winner',
        'you are selected', 'nigerian', 'inheritance',
        'million dollars', 'cash prize', 'you\'ve been selected',
        'claim your reward', 'unclaimed inheritance',
    ]
    scam_count = sum(1 for p in scam_phrases if p in t)

    # 6. Generic greeting (1 = yes)
    generic_greetings = [
        'dear customer', 'dear user', 'dear account holder',
        'dear member', 'valued customer', 'dear sir/madam',
        'dear valued customer',
    ]
    has_generic_greeting = 1 if any(g in t for g in generic_greetings) else 0

    # 7. Ratio of CAPS words
    caps_words = [w for w in words if len(w) > 3 and w.isupper()]
    caps_ratio = len(caps_words) / len(words) if words else 0

    # 8. Number of exclamation marks
    exclamation_count = text.count('!')

    # 9. Number of question marks
    question_count = text.count('?')

    # 10. Average word length (short = simple writing = potential phishing)
    avg_word_len = (sum(len(w) for w in words) / len(words)) if words else 0

    # 11. Number of currency symbols ($, £, €)
    currency_count = len(re.findall(r'[\$£€]', text))

    # 12. Suspicious action phrase count
    action_phrases = [
        'click here', 'click below', 'click the link',
        'open attachment', 'download now', 'log in now',
        'click to verify', 'click to confirm', 'verify now',
    ]
    action_count = sum(1 for p in action_phrases if p in t)

    return [
        text_length,            # 1
        url_count,              # 2
        urgent_count,           # 3
        sensitive_count,        # 4
        scam_count,             # 5
        has_generic_greeting,   # 6
        caps_ratio,             # 7
        exclamation_count,      # 8
        question_count,         # 9
        avg_word_len,           # 10
        currency_count,         # 11
        action_count,           # 12
    ]
