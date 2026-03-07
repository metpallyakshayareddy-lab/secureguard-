# ============================================================
# auth.py – Google OAuth2 Web Flow (No PKCE)
#
# Manually constructs the OAuth URL and exchanges the code
# directly via HTTP POST to avoid the "missing code verifier"
# error that occurs when the library auto-generates PKCE.
# ============================================================

import os
import json
import secrets
import urllib.parse
import requests as http_requests

SCOPES           = ['https://www.googleapis.com/auth/gmail.readonly']
# Set REDIRECT_URI env var on Vercel to your deployment URL + /auth/callback
REDIRECT_URI     = os.environ.get('REDIRECT_URI', 'http://localhost:5000/auth/callback')
GOOGLE_AUTH_URL  = 'https://accounts.google.com/o/oauth2/auth'
GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token'

_client_cache = {}


def _load_client_info():
    """Load client_id / client_secret from credentials.json or env vars."""
    if _client_cache:
        return _client_cache, None

    # 1) Try environment variables first (for Vercel / production)
    env_id     = os.environ.get('GOOGLE_CLIENT_ID')
    env_secret = os.environ.get('GOOGLE_CLIENT_SECRET')
    if env_id and env_secret:
        _client_cache['client_id']     = env_id
        _client_cache['client_secret'] = env_secret
        return _client_cache, None

    # 2) Fall back to credentials.json (local dev)
    try:
        with open('credentials.json') as f:
            data = json.load(f)
        info = data.get('web') or data.get('installed')
        if not info:
            return None, 'credentials.json has no "web" or "installed" key'
        _client_cache['client_id']     = info['client_id']
        _client_cache['client_secret'] = info['client_secret']
        return _client_cache, None
    except FileNotFoundError:
        return None, 'credentials.json not found — set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET env vars'
    except Exception as e:
        return None, str(e)


def get_authorization_url() -> tuple:
    """
    Build a Google OAuth2 authorization URL WITHOUT PKCE.
    Returns (auth_url, state) or (None, error_message).
    """
    info, err = _load_client_info()
    if err:
        return None, err

    state = secrets.token_urlsafe(16)
    params = {
        'client_id':     info['client_id'],
        'redirect_uri':  REDIRECT_URI,
        'response_type': 'code',
        'scope':         ' '.join(SCOPES),
        'access_type':   'offline',
        'prompt':        'consent',
        'state':         state,
    }
    auth_url = GOOGLE_AUTH_URL + '?' + urllib.parse.urlencode(params)
    return auth_url, state


def exchange_code_for_token(state: str, code: str) -> tuple:
    """
    Exchange the authorization code for access/refresh tokens
    via a direct HTTPS POST — no PKCE involved.
    Returns (token_dict, error) or (None, error_message).
    """
    info, err = _load_client_info()
    if err:
        return None, err

    try:
        resp = http_requests.post(GOOGLE_TOKEN_URL, data={
            'code':          code,
            'client_id':     info['client_id'],
            'client_secret': info['client_secret'],
            'redirect_uri':  REDIRECT_URI,
            'grant_type':    'authorization_code',
        }, timeout=15)

        token = resp.json()
        if 'error' in token:
            return None, token.get('error_description', token['error'])

        return {
            'token':         token.get('access_token'),
            'refresh_token': token.get('refresh_token'),
            'token_uri':     GOOGLE_TOKEN_URL,
            'client_id':     info['client_id'],
            'client_secret': info['client_secret'],
            'scopes':        SCOPES,
        }, None

    except Exception as e:
        return None, str(e)


def build_gmail_service_from_token(token_data: dict):
    """
    Build a Gmail API service from a stored token dict.
    Returns (service, error).
    """
    try:
        from google.oauth2.credentials import Credentials
        from googleapiclient.discovery import build
        from google.auth.transport.requests import Request

        creds = Credentials(
            token=         token_data.get('token'),
            refresh_token= token_data.get('refresh_token'),
            token_uri=     token_data.get('token_uri', GOOGLE_TOKEN_URL),
            client_id=     token_data.get('client_id'),
            client_secret= token_data.get('client_secret'),
            scopes=        token_data.get('scopes', SCOPES),
        )

        if creds.expired and creds.refresh_token:
            creds.refresh(Request())

        service = build('gmail', 'v1', credentials=creds)
        return service, None

    except Exception as e:
        return None, str(e)
