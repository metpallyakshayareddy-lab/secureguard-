# ============================================================
# form_detector.py – Sensitive Login Form Detection
# Fetches a URL and checks for password/OTP/credit card fields
# ============================================================

import requests
from bs4 import BeautifulSoup

HEADERS = {
    'User-Agent': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
        'AppleWebKit/537.36 (KHTML, like Gecko) '
        'Chrome/120.0.0.0 Safari/537.36'
    )
}


def detect_login_form(url: str, timeout: int = 5) -> dict:
    """
    Fetch the page at `url` and detect sensitive input fields.
    Returns a dict with has_login_form (bool) and fields_detected (list).
    """
    try:
        response = requests.get(
            url, timeout=timeout,
            headers=HEADERS,
            allow_redirects=True,
            verify=False   # Some phishing sites have bad certs
        )
        soup = BeautifulSoup(response.text, 'html.parser')
        found = []

        # ── Password field (strongest signal) ──
        if soup.find('input', {'type': 'password'}):
            found.append('password')

        # ── OTP / PIN / SSN fields ──
        otp_keywords = ['otp', 'ssn', 'social', 'pin', 'passcode', 'verification']
        for inp in soup.find_all('input'):
            attrs = ' '.join([
                inp.get('name',        ''),
                inp.get('id',          ''),
                inp.get('placeholder', ''),
                inp.get('aria-label',  ''),
            ]).lower()
            if any(k in attrs for k in otp_keywords) and 'otp' not in found:
                found.append('otp / pin')

        # ── Credit card fields ──
        cc_keywords = ['credit', 'card', 'cvv', 'cvc', 'expiry', 'expiration', 'cardnumber']
        for inp in soup.find_all('input'):
            attrs = ' '.join([
                inp.get('name',        ''),
                inp.get('id',          ''),
                inp.get('placeholder', ''),
            ]).lower()
            if any(k in attrs for k in cc_keywords) and 'credit card' not in found:
                found.append('credit card')

        # ── Email field alone (less severe) ──
        if soup.find('input', {'type': 'email'}) and 'password' not in found:
            found.append('email only')

        return {
            'has_login_form':  len(found) > 0,
            'fields_detected': found,
            'error':           None,
        }

    except requests.exceptions.Timeout:
        return {'has_login_form': False, 'fields_detected': [], 'error': 'timeout'}
    except Exception as e:
        return {'has_login_form': False, 'fields_detected': [], 'error': str(e)}
