"""
Quick verification test for SecureGuard phishing detection.
Run AFTER starting the Flask server: python app.py
"""
import requests

BASE = "http://localhost:5000"

def check_url(url):
    r = requests.post(f"{BASE}/check_url", json={"url": url}, timeout=10)
    d = r.json()
    return d.get("prediction"), d.get("risk_score", 0)

def check_email(text):
    r = requests.post(f"{BASE}/check_email", json={"text": text}, timeout=10)
    d = r.json()
    return d.get("prediction"), d.get("risk_score", 0)

PHISHING_URLS = [
    "http://paypa1-secure.login.tk/verify/account",
    "http://192.168.1.1/login/bank",
    "http://google.com.malicious.domain.ml/signin",
    "http://amazon-billing.suspended.xyz/update",
    "http://arnazon.com/signin",
    "http://secure-login-verify-account.com/signin",
    "http://faceb00k.com/verify",
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
]

SAFE_EMAILS = [
    "Hi John, just confirming our 2pm meeting tomorrow. Please bring the documents.",
    "Your GitHub pull request has been reviewed and approved by the team.",
    "Hello team, here is the weekly project update. Let me know if you have any questions.",
    "Your flight booking is confirmed. Check-in opens 24 hours before departure.",
]

print("=" * 60)
print("URL TESTS")
print("=" * 60)
passed = 0; total = 0

print("\n[Phishing URLs - expected: phishing]")
for url in PHISHING_URLS:
    pred, score = check_url(url)
    ok = pred == "phishing"
    status = "PASS" if ok else "FAIL"
    print(f"  {status}  [{score:3d}%]  {url[:60]}")
    passed += ok; total += 1

print("\n[Safe URLs - expected: safe]")
for url in SAFE_URLS:
    pred, score = check_url(url)
    ok = pred == "safe"
    status = "PASS" if ok else "FAIL"
    print(f"  {status}  [{score:3d}%]  {url[:60]}")
    passed += ok; total += 1

print("\n" + "=" * 60)
print("EMAIL TESTS")
print("=" * 60)

print("\n[Phishing emails - expected: phishing]")
for em in PHISHING_EMAILS:
    pred, score = check_email(em)
    ok = pred == "phishing"
    status = "PASS" if ok else "FAIL"
    print(f"  {status}  [{score:3d}%]  {em[:60]}")
    passed += ok; total += 1

print("\n[Safe emails - expected: safe]")
for em in SAFE_EMAILS:
    pred, score = check_email(em)
    ok = pred == "safe"
    status = "PASS" if ok else "FAIL"
    print(f"  {status}  [{score:3d}%]  {em[:60]}")
    passed += ok; total += 1

print("\n" + "=" * 60)
print(f"RESULT: {passed}/{total} tests passed")
print("=" * 60)
