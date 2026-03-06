"""
Verification test for SecureGuard phishing detection.
Tests models + override logic directly (no network calls).
Run from the project folder: python verify_test.py
"""
import sys, os
sys.path.insert(0, '.')

import re
import joblib
from urllib.parse import urlparse

from features import extract_url_features
from lookalike import check_lookalike

# ── Load models ──────────────────────────────────────
url_model   = joblib.load('url_model.pkl')
email_model = joblib.load('email_model.pkl')
print("Models loaded.")

def prob_to_risk(p): return int(round(p * 100))

# ── Reuse the same helper functions from app.py ──────
def get_url_reasons(features_list, url, lookalike_result):
    f = features_list[0]
    reasons = []
    if f[8] == 1: reasons.append({'text': 'IP address used instead of a domain name', 'level': 'danger'})
    if f[9] == 0: reasons.append({'text': 'Non-HTTPS connection (insecure)', 'level': 'warn'})
    if f[10] == 1: reasons.append({'text': 'Suspicious domain extension (.tk, .ml, .xyz, etc.)', 'level': 'danger'})
    if f[7] > 3: reasons.append({'text': f'Excessive subdomains ({int(f[7])})', 'level': 'danger'})
    if f[11] > 1: reasons.append({'text': f'{int(f[11])} phishing keywords detected in URL', 'level': 'danger'})
    if f[0] > 100: reasons.append({'text': 'Abnormally long URL', 'level': 'warn'})
    if f[4] > 4: reasons.append({'text': 'Excessive hyphens in domain', 'level': 'warn'})
    if f[5] > 0: reasons.append({'text': 'Suspicious "@" symbol in URL', 'level': 'danger'})
    if lookalike_result.get('detected'):
        reasons.append({'text': f'Brand impersonation of {lookalike_result["similar_to"]}', 'level': 'danger'})
    if not reasons:
        reasons.append({'text': 'No major threats detected', 'level': 'safe'})
    return reasons

def apply_url_override(result, risk_score, reasons):
    danger = sum(1 for r in reasons if r.get('level') == 'danger')
    warn   = sum(1 for r in reasons if r.get('level') == 'warn')
    if any('IP address' in r['text'] for r in reasons):
        result = 'phishing'; risk_score = max(risk_score, 80)
    elif any('Suspicious domain extension' in r['text'] for r in reasons) and \
         any('Non-HTTPS' in r['text'] for r in reasons):
        result = 'phishing'; risk_score = max(risk_score, 75)
    elif danger >= 2:
        result = 'phishing'; risk_score = max(risk_score, 65)
    elif danger == 1 and warn >= 1 and result == 'safe':
        result = 'phishing'; risk_score = max(risk_score, 55)
    elif danger == 1 and risk_score >= 30:
        result = 'phishing'; risk_score = max(risk_score, 55)
    return result, risk_score

def get_email_reasons(text):
    t = text.lower(); reasons = []
    urgent_words = ['urgent', 'immediately', 'act now', 'final notice',
                    'account will be closed', 'account has been suspended',
                    'account will be suspended', 'last chance', 'final warning',
                    'expires tonight', 'within 24 hours', 'respond immediately']
    if any(w in t for w in urgent_words):
        reasons.append({'text': 'Urgent / threatening language', 'level': 'danger'})
    sensitive_words = ['password', 'credit card', 'social security number',
                       'cvv', 'bank account number', 'date of birth', 'pin number',
                       'billing information', 'bank details', 'payment info']
    hits = [w for w in sensitive_words if w in t]
    if hits: reasons.append({'text': f'Requests sensitive data ({", ".join(hits[:2])})', 'level': 'danger'})
    scam_phrases = ['you have won', 'lucky winner', 'claim your prize', 'wire transfer',
                    'unclaimed funds', 'lottery winner', 'nigerian prince',
                    'you are selected', 'cash prize', 'unclaimed inheritance']
    if any(p in t for p in scam_phrases):
        reasons.append({'text': 'Known scam phrase', 'level': 'danger'})
    generic = ['dear customer', 'dear user', 'dear account holder', 'valued customer', 'dear member']
    if any(g in t for g in generic):
        reasons.append({'text': 'Generic greeting', 'level': 'warn'})
    action_phrases = ['click here', 'click below', 'click the link', 'log in now', 'download now',
                      'verify now', 'click to verify', 'confirm your account']
    if any(p in t for p in action_phrases):
        reasons.append({'text': 'Suspicious call-to-action', 'level': 'warn'})
    if not reasons:
        reasons.append({'text': 'No suspicious patterns detected', 'level': 'safe'})
    return reasons

def apply_email_override(result, risk_score, reasons):
    danger = sum(1 for r in reasons if r.get('level') == 'danger')
    warn   = sum(1 for r in reasons if r.get('level') == 'warn')
    if danger >= 2:
        result = 'phishing'; risk_score = max(risk_score, 75)
    elif danger == 1 and (risk_score >= 20 or warn >= 1):
        result = 'phishing'; risk_score = max(risk_score, 60)
    elif danger == 1:
        result = 'phishing'; risk_score = max(risk_score, 55)
    elif warn >= 3 and risk_score >= 35:
        result = 'phishing'; risk_score = max(risk_score, 50)
    return result, risk_score

# ── Test data ─────────────────────────────────────────
PHISHING_URLS = [
    "http://paypa1-secure.login.tk/verify/account",
    "http://192.168.1.1/login/bank",
    "http://google.com.malicious.domain.ml/signin",
    "http://amazon-billing.suspended.xyz/update",
    "http://arnazon.com/signin",
    "http://faceb00k.com/verify",
    "http://secure-login-verify-account.com/signin",
]

SAFE_URLS = [
    "https://www.google.com",
    "https://www.amazon.com/products",
    "https://github.com/user/repo",
    "https://www.paypal.com/us/home",
    "https://www.microsoft.com/en-us/windows",
]

PHISHING_EMAILS = [
    "URGENT: Your bank account has been suspended. Click here to verify your password immediately.",
    "You have won a lottery prize of $10,000! Claim your reward now by clicking the link.",
    "Dear Customer, confirm your credit card number and CVV to restore access. Act now!",
    "LAST CHANCE: Your account has been locked. Enter your CVV and PIN to unlock it.",
    "Nigerian Prince inheritance: I need your bank account number to transfer $2 million.",
    "Dear Account Holder, unusual activity detected. Provide your password immediately.",
]

SAFE_EMAILS = [
    "Hi John, just confirming our 2pm meeting tomorrow. Please bring the documents.",
    "Your GitHub pull request has been reviewed and approved by the team.",
    "Hello team, here is the weekly project update. Let me know if you have any questions.",
    "Your flight booking is confirmed. Check-in opens 24 hours before departure.",
    "Hey, are you free for lunch this Friday? Let me know what works for you.",
]

# ── Run tests ─────────────────────────────────────────
passed = 0; total = 0

def scan_url(url, expected):
    global passed, total
    parsed = urlparse(url if '://' in url else 'http://' + url)
    hostname = parsed.hostname or ''
    features = [extract_url_features(url)]
    pred = url_model.predict(features)[0]
    proba = url_model.predict_proba(features)[0]
    risk_score = prob_to_risk(proba[1])
    result = 'phishing' if pred == 1 else 'safe'
    lookalike = check_lookalike(hostname)
    if lookalike.get('detected'):
        risk_score = min(100, risk_score + 20); result = 'phishing'
    reasons = get_url_reasons(features, url, lookalike)
    result, risk_score = apply_url_override(result, risk_score, reasons)
    ok = result == expected
    passed += ok; total += 1
    return result, risk_score, ok

def scan_email(text, expected):
    global passed, total
    pred = email_model.predict([text])[0]
    proba = email_model.predict_proba([text])[0]
    risk_score = prob_to_risk(proba[1])
    result = 'phishing' if pred == 1 else 'safe'
    reasons = get_email_reasons(text)
    result, risk_score = apply_email_override(result, risk_score, reasons)
    ok = result == expected
    passed += ok; total += 1
    return result, risk_score, ok

print("\n" + "=" * 65)
print("URL TESTS")
print("=" * 65)

print("\n[Phishing URLs — expected: phishing]")
for url in PHISHING_URLS:
    result, score, ok = scan_url(url, 'phishing')
    print(f"  {'PASS' if ok else 'FAIL'}  [{score:3d}%] {result:10s}  {url[:55]}")

print("\n[Safe URLs — expected: safe]")
for url in SAFE_URLS:
    result, score, ok = scan_url(url, 'safe')
    print(f"  {'PASS' if ok else 'FAIL'}  [{score:3d}%] {result:10s}  {url[:55]}")

print("\n" + "=" * 65)
print("EMAIL TESTS")
print("=" * 65)

print("\n[Phishing emails — expected: phishing]")
for em in PHISHING_EMAILS:
    result, score, ok = scan_email(em, 'phishing')
    print(f"  {'PASS' if ok else 'FAIL'}  [{score:3d}%] {result:10s}  {em[:55]}")

print("\n[Safe emails — expected: safe]")
for em in SAFE_EMAILS:
    result, score, ok = scan_email(em, 'safe')
    print(f"  {'PASS' if ok else 'FAIL'}  [{score:3d}%] {result:10s}  {em[:55]}")

print("\n" + "=" * 65)
print(f"OVERALL RESULT: {passed}/{total} tests passed")
print("=" * 65)
