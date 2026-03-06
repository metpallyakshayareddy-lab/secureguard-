# ============================================================
# app.py – SecureGuard Flask API (Upgraded)
#
# Features added:
#   - Explainable AI reasons for every prediction
#   - Look-alike / typosquatting domain detection
#   - Login form detection on scanned URLs
#   - Real-time SocketIO alerts for phishing detections
#   - Gmail inbox scanning (/scan_inbox)
#   - Batch email scanning (/batch_scan)
#   - Rule-based override: heuristic danger signals override ML "safe" verdict
#
# HOW TO RUN:
#   1. pip install -r requirements.txt
#   2. python train.py
#   3. python app.py
# ============================================================

import os
import re

from flask import Flask, request, jsonify, session, redirect, send_from_directory
from flask_cors import CORS
import joblib

from features      import extract_url_features
from lookalike     import check_lookalike
from form_detector import detect_login_form

# Gmail auth — graceful: missing credentials.json won't crash the app
try:
    from gmail_reader import fetch_emails
    from auth import get_authorization_url, exchange_code_for_token, build_gmail_service_from_token
    GMAIL_ENABLED = True
except Exception:
    GMAIL_ENABLED = False
    def fetch_emails(*a, **kw): return []
    def get_authorization_url(): return '#'
    def exchange_code_for_token(code): return None
    def build_gmail_service_from_token(token): return None

# ── Detect environment ─────────────────────────────────────
IS_VERCEL = os.environ.get('VERCEL') == '1' or os.environ.get('VERCEL_ENV') is not None

# ── App setup ──────────────────────────────────────────────
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'secureguard-secret-2024')
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE']   = IS_VERCEL   # True on HTTPS (Vercel), False locally
CORS(app, origins='*', supports_credentials=True)

# SocketIO — only initialise when NOT on Vercel (serverless can't hold connections)
if not IS_VERCEL:
    from flask_socketio import SocketIO
    socketio = SocketIO(app, cors_allowed_origins='*', async_mode='eventlet')
else:
    # Stub so the rest of the code can call socketio.emit() without errors
    class _NoOpSocketIO:
        def emit(self, *a, **kw): pass
        def on(self, *a, **kw): return lambda f: f
        def run(self, *a, **kw): pass
    socketio = _NoOpSocketIO()

# ── Load models ────────────────────────────────────────────
url_model   = None
email_model = None

def load_models():
    global url_model, email_model
    for path, name in [('url_model.pkl', 'url'), ('email_model.pkl', 'email')]:
        if os.path.exists(path):
            if name == 'url':
                url_model = joblib.load(path)
            else:
                email_model = joblib.load(path)
            print(f'Loaded {path}')
        else:
            print(f'WARNING: {path} not found – run train.py first.')

load_models()

# ── Helpers ────────────────────────────────────────────────

def prob_to_risk(prob_phishing: float) -> int:
    return int(round(prob_phishing * 100))


def get_url_reasons(features_list: list, url: str,
                    lookalike_result: dict, form_result: dict) -> list:
    """Build human-readable explanation tags for a URL prediction."""
    f = features_list[0]
    # f indices: 0=url_length, 1=hostname_length, 2=path_length, 3=num_dots,
    # 4=num_hyphens, 5=num_at, 6=num_slashes, 7=num_subdomains, 8=has_ip,
    # 9=has_https, 10=has_suspicious_tld, 11=keyword_count,
    # 12=num_params, 13=entropy, 14=has_port, 15=is_trusted_domain
    reasons = []

    if f[8] == 1:
        reasons.append({'text': 'IP address used instead of a domain name', 'level': 'danger'})
    if f[9] == 0:
        reasons.append({'text': 'Non-HTTPS connection (insecure)', 'level': 'warn'})
    if f[10] == 1:
        reasons.append({'text': 'Suspicious domain extension (.tk, .ml, .xyz, etc.)', 'level': 'danger'})
    if f[7] > 3:
        reasons.append({'text': f'Excessive subdomains ({int(f[7])})', 'level': 'danger'})
    if f[11] > 1:
        reasons.append({'text': f'{int(f[11])} phishing keywords detected in URL', 'level': 'danger'})
    if f[0] > 100:
        reasons.append({'text': 'Abnormally long URL', 'level': 'warn'})
    if f[4] > 4:
        reasons.append({'text': 'Excessive hyphens in domain', 'level': 'warn'})
    if f[5] > 0:
        reasons.append({'text': 'Suspicious "@" symbol in URL', 'level': 'danger'})

    if lookalike_result.get('detected'):
        similar = lookalike_result.get('similar_to', '')
        score   = lookalike_result.get('similarity_score', 0)
        reasons.append({
            'text':  f'Possible brand impersonation of {similar} ({score}% match)',
            'level': 'danger',
        })

    if form_result.get('has_login_form'):
        fields = ', '.join(form_result.get('fields_detected', []))
        reasons.append({
            'text':  f'Sensitive login form detected ({fields})',
            'level': 'danger',
        })

    if not reasons:
        reasons.append({'text': 'No major threats detected', 'level': 'safe'})

    return reasons


def apply_url_override(result: str, risk_score: int, reasons: list) -> tuple:
    """
    Rule-based override: if strong heuristic signals are present,
    override an ML 'safe' verdict to 'phishing' and boost risk score.
    Returns (result, risk_score).
    """
    danger_count = sum(1 for r in reasons if r.get('level') == 'danger')
    warn_count   = sum(1 for r in reasons if r.get('level') == 'warn')

    # Any IP-address usage → always phishing
    if any('IP address' in r['text'] for r in reasons):
        result     = 'phishing'
        risk_score = max(risk_score, 80)

    # Suspicious TLD + no HTTPS → very high risk combo
    elif any('Suspicious domain extension' in r['text'] for r in reasons) and \
         any('Non-HTTPS' in r['text'] for r in reasons):
        result     = 'phishing'
        risk_score = max(risk_score, 75)

    # 2+ danger signals → override to phishing
    elif danger_count >= 2:
        result     = 'phishing'
        risk_score = max(risk_score, 65)

    # 1 danger + ≥1 warn → likely phishing
    elif danger_count == 1 and warn_count >= 1:
        if result == 'safe':
            result     = 'phishing'
            risk_score = max(risk_score, 55)

    # Single strong danger signal with moderately high ML score
    elif danger_count == 1 and risk_score >= 30:
        result     = 'phishing'
        risk_score = max(risk_score, 55)

    return result, risk_score


def get_email_reasons(text: str) -> list:
    """Build human-readable explanation tags for an email prediction."""
    t       = text.lower()
    reasons = []

    urgent_words = [
        'urgent', 'immediately', 'act now', 'final notice',
        'account will be closed', 'account has been suspended',
        'account will be suspended', 'last chance', 'final warning',
        'expires tonight', 'within 24 hours', 'respond immediately',
    ]
    if any(w in t for w in urgent_words):
        reasons.append({'text': 'Urgent / threatening language detected', 'level': 'danger'})

    sensitive_words = [
        'password', 'credit card', 'social security number',
        'cvv', 'bank account number', 'date of birth', 'pin number',
        'billing information', 'bank details', 'payment info',
    ]
    hits = [w for w in sensitive_words if w in t]
    if hits:
        sample = ', '.join(hits[:2])
        reasons.append({'text': f'Requests sensitive data ({sample})', 'level': 'danger'})

    scam_phrases = [
        'you have won', 'lucky winner', 'claim your prize',
        'wire transfer', 'unclaimed funds', 'lottery winner',
        'nigerian prince', 'you are selected', 'cash prize',
        'unclaimed inheritance', 'claim your reward',
    ]
    if any(p in t for p in scam_phrases):
        reasons.append({'text': 'Known scam phrase detected', 'level': 'danger'})

    generic = ['dear customer', 'dear user', 'dear account holder', 'valued customer', 'dear member']
    if any(g in t for g in generic):
        reasons.append({'text': 'Impersonal / generic greeting used', 'level': 'warn'})

    link_count = len(re.findall(r'https?://\S+', text))
    if link_count > 3:
        reasons.append({'text': f'Multiple suspicious links ({link_count}) in email', 'level': 'warn'})

    words = text.split()
    caps  = [w for w in words if len(w) > 3 and w.isupper()]
    if len(caps) > 4:
        reasons.append({'text': 'Excessive use of capital letters (SHOUTING)', 'level': 'warn'})

    action_phrases = ['click here', 'click below', 'click the link', 'log in now', 'download now',
                      'verify now', 'click to verify', 'confirm your account']
    if any(p in t for p in action_phrases):
        reasons.append({'text': 'Suspicious call-to-action phrase detected', 'level': 'warn'})

    if not reasons:
        reasons.append({'text': 'No suspicious patterns detected', 'level': 'safe'})

    return reasons


def apply_email_override(result: str, risk_score: int, reasons: list) -> tuple:
    """
    Rule-based override: if heuristic danger signals are present,
    override an ML 'safe' verdict to 'phishing' and boost risk score.
    Returns (result, risk_score).
    """
    danger_count = sum(1 for r in reasons if r.get('level') == 'danger')
    warn_count   = sum(1 for r in reasons if r.get('level') == 'warn')

    # 2+ danger signals → definitely phishing regardless of ML
    if danger_count >= 2:
        result     = 'phishing'
        risk_score = max(risk_score, 75)

    # 1 danger signal + any ML confidence OR any warn → override
    elif danger_count == 1 and (risk_score >= 20 or warn_count >= 1):
        result     = 'phishing'
        risk_score = max(risk_score, 60)

    # 1 danger signal alone (ML was low confidence but danger signal is clear)
    elif danger_count == 1:
        result     = 'phishing'
        risk_score = max(risk_score, 55)

    # No danger but many warnings + ML also uncertain
    elif warn_count >= 3 and risk_score >= 35:
        result     = 'phishing'
        risk_score = max(risk_score, 50)

    return result, risk_score


# ── ENDPOINT 1: URL Scan ────────────────────────────────────
@app.route('/check_url', methods=['POST'])
def check_url():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'Missing "url" field'}), 400

    url = data['url'].strip()
    if not url:
        return jsonify({'error': 'URL cannot be empty'}), 400
    if url_model is None:
        return jsonify({'error': 'URL model not loaded. Run train.py first.'}), 503

    try:
        from urllib.parse import urlparse
        parsed   = urlparse(url if '://' in url else 'http://' + url)
        hostname = parsed.hostname or ''

        features   = [extract_url_features(url)]
        prediction = url_model.predict(features)[0]
        proba      = url_model.predict_proba(features)[0]
        risk_score = prob_to_risk(proba[1])
        result     = 'phishing' if prediction == 1 else 'safe'

        # Look-alike domain detection
        lookalike = check_lookalike(hostname)
        if lookalike.get('detected'):
            risk_score = min(100, risk_score + 20)
            result = 'phishing'

        # Login form detection (lower threshold to 20 to catch more phishing)
        form_result = {'has_login_form': False, 'fields_detected': [], 'error': None}
        if risk_score > 20:
            form_result = detect_login_form(url)
            if form_result.get('has_login_form'):
                risk_score = min(100, risk_score + 15)
                result = 'phishing'

        reasons = get_url_reasons(features, url, lookalike, form_result)

        # ── Rule-based override: heuristics can override ML "safe" verdict ──
        result, risk_score = apply_url_override(result, risk_score, reasons)

        # Real-time SocketIO alert
        if result == 'phishing':
            socketio.emit('phishing_alert', {
                'type':       'URL',
                'content':    url[:70],
                'risk_score': risk_score,
            })

        return jsonify({
            'prediction':   result,
            'risk_score':   risk_score,
            'url':          url,
            'reasons':      reasons,
            'lookalike':    lookalike,
            'has_login_form': form_result.get('has_login_form', False),
            'login_fields': form_result.get('fields_detected', []),
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── ENDPOINT 2: Email Scan ──────────────────────────────────
@app.route('/check_email', methods=['POST'])
def check_email():
    data = request.get_json()
    if not data or 'text' not in data:
        return jsonify({'error': 'Missing "text" field'}), 400

    text = data['text'].strip()
    if not text:
        return jsonify({'error': 'Email text cannot be empty'}), 400
    if email_model is None:
        return jsonify({'error': 'Email model not loaded. Run train.py first.'}), 503

    try:
        prediction = email_model.predict([text])[0]
        proba      = email_model.predict_proba([text])[0]
        risk_score = prob_to_risk(proba[1])
        result     = 'phishing' if prediction == 1 else 'safe'
        reasons    = get_email_reasons(text)

        # ── Rule-based override: heuristics can override ML "safe" verdict ──
        result, risk_score = apply_email_override(result, risk_score, reasons)

        if result == 'phishing':
            socketio.emit('phishing_alert', {
                'type':       'Email',
                'content':    text[:70],
                'risk_score': risk_score,
            })

        return jsonify({
            'prediction': result,
            'risk_score': risk_score,
            'reasons':    reasons,
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 500


# ── ENDPOINT 3: Gmail Inbox Scan ────────────────────────────
@app.route('/scan_inbox', methods=['GET'])
def scan_inbox():
    import json as _json
    max_results = int(request.args.get('max', 10))

    # Accept token from X-Gmail-Token header (stored in localStorage)
    token_header = request.headers.get('X-Gmail-Token')
    if token_header:
        try:
            token_data = _json.loads(token_header)
        except Exception:
            return jsonify({'error': 'Invalid token header', 'needs_login': True}), 401
        service, err = build_gmail_service_from_token(token_data)
        if err:
            return jsonify({'error': err, 'needs_login': True}), 401
        from gmail_reader import _fetch_with_service
        emails, error = _fetch_with_service(service, max_results)
    else:
        # Fall back to developer token.json
        emails, error = fetch_emails(max_results)

    if error:
        return jsonify({'error': error, 'needs_login': True}), 401

    results = []
    for em in emails:
        verdict, risk_score = 'unknown', 0
        if email_model and em['body']:
            try:
                pred  = email_model.predict([em['body']])[0]
                proba = email_model.predict_proba([em['body']])[0]
                risk_score = prob_to_risk(proba[1])
                verdict    = 'phishing' if pred == 1 else 'safe'

                # ── Rule-based override for inbox scan ──
                reasons = get_email_reasons(em['body'])
                verdict, risk_score = apply_email_override(verdict, risk_score, reasons)

            except Exception:
                pass

        results.append({
            'subject':     em['subject'],
            'from':        em['from'],
            'date':        em['date'],
            'prediction':  verdict,
            'risk_score':  risk_score,
            'links_found': len(em.get('links', [])),
        })

    return jsonify({'emails': results, 'total': len(results)})


# ── AUTH: Google OAuth2 Web Flow ────────────────────────────
@app.route('/auth/login')
def auth_login():
    """Redirect user to Google OAuth consent screen."""
    auth_url, state = get_authorization_url()
    if not auth_url:
        return jsonify({'error': state}), 500
    session['oauth_state'] = state
    return redirect(auth_url)


@app.route('/auth/callback')
def auth_callback():
    """Exchange code for token, send it to the opener via postMessage."""
    import json as _json
    code  = request.args.get('code')
    state = request.args.get('state')
    if not code:
        return '<h2>Authorization failed — no code received.</h2>', 400

    token_data, error = exchange_code_for_token(state, code)
    if error:
        return f'<h2 style="color:red">Error: {error}</h2>', 500

    token_json = _json.dumps(token_data)
    return f'''
        <html><body style="font-family:sans-serif;text-align:center;padding:60px;background:#fdf0f8">
            <h2 style="color:#c0507a">&#10003; Gmail Connected!</h2>
            <p>You can close this tab and return to the dashboard.</p>
            <script>
              const token = {_json.dumps(token_json)};
              if (window.opener) {{
                window.opener.postMessage({{type:"gmail_auth_done", token: token}}, "*");
                setTimeout(() => window.close(), 1200);
              }}
            </script>
        </body></html>
    '''


@app.route('/auth/logout')
def auth_logout():
    """Signal logout — frontend deletes token from localStorage."""
    return jsonify({'status': 'logged_out'})


@app.route('/auth/status')
def auth_status():
    """Accepts X-Gmail-Token header to verify connection."""
    token = request.headers.get('X-Gmail-Token')
    return jsonify({'connected': bool(token)})



# ── ENDPOINT: Serve Frontend ───────────────────────────────
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:filename>')
def static_files(filename):
    return send_from_directory('.', filename)


# ── ENDPOINT 5: Health Check ────────────────────────────────
@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status':            'ok',
        'url_model_loaded':  url_model   is not None,
        'email_model_loaded': email_model is not None,
    })


# ── SocketIO events ─────────────────────────────────────────
@socketio.on('connect')
def handle_connect():
    print('Client connected via SocketIO')


# ── Run ─────────────────────────────────────────────────────
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f'\nStarting SecureGuard API on http://localhost:{port}')
    print('Press Ctrl+C to stop.\n')
    socketio.run(app, host='0.0.0.0', port=port, debug=False)
