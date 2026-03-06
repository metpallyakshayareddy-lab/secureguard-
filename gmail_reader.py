# ============================================================
# gmail_reader.py – Gmail Inbox Integration
#
# SETUP (one-time):
#   1. Go to https://console.cloud.google.com
#   2. Enable Gmail API
#   3. Create OAuth 2.0 credentials → download as credentials.json
#   4. Place credentials.json in this project folder
#   5. Run once: python gmail_reader.py  (opens browser to authorize)
# ============================================================

import os
import base64
import re

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']


def get_gmail_service():
    """Authenticate and return a Gmail API service object."""
    try:
        from google.oauth2.credentials import Credentials
        from google_auth_oauthlib.flow import InstalledAppFlow
        from google.auth.transport.requests import Request
        from googleapiclient.discovery import build
    except ImportError:
        return None, 'Gmail libraries not installed. Run: pip install google-auth google-auth-oauthlib google-api-python-client'

    creds = None
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            if not os.path.exists('credentials.json'):
                return None, (
                    'credentials.json not found. '
                    'Please follow the Gmail API setup instructions.'
                )
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)

        with open('token.json', 'w') as token_file:
            token_file.write(creds.to_json())

    try:
        service = build('gmail', 'v1', credentials=creds)
        return service, None
    except Exception as e:
        return None, str(e)


def extract_body(payload: dict) -> str:
    """Extract plain text body from Gmail message payload."""
    body = ''
    if 'parts' in payload:
        for part in payload['parts']:
            if part.get('mimeType') == 'text/plain':
                data = part['body'].get('data', '')
                if data:
                    body += base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
    else:
        data = payload.get('body', {}).get('data', '')
        if data:
            body = base64.urlsafe_b64decode(data).decode('utf-8', errors='ignore')
    return body


def fetch_emails(max_results: int = 10) -> tuple:
    """
    Fetch latest unread emails from Gmail inbox.
    Returns (list_of_emails, error_string_or_None)
    """
    service, error = get_gmail_service()
    if error:
        return [], error

    try:
        results = service.users().messages().list(
            userId='me',
            labelIds=['INBOX'],
            maxResults=max_results,
            q='is:unread'
        ).execute()

        messages = results.get('messages', [])
        emails = []

        for msg in messages:
            msg_data = service.users().messages().get(
                userId='me', id=msg['id']
            ).execute()

            headers = {
                h['name']: h['value']
                for h in msg_data['payload']['headers']
            }

            body  = extract_body(msg_data['payload'])
            links = re.findall(r'https?://[^\s<>"\']+', body)

            emails.append({
                'id':      msg['id'],
                'subject': headers.get('Subject', '(No Subject)'),
                'from':    headers.get('From',    'Unknown'),
                'date':    headers.get('Date',    ''),
                'body':    body[:1500],
                'links':   links[:10],
            })

        return emails, None

    except Exception as e:
        return [], str(e)



def _fetch_with_service(service, max_results: int = 10) -> tuple:
    """
    Fetch emails using an already-built Gmail service object.
    Called by app.py when the user logged in via the OAuth web flow.
    """
    try:
        results = service.users().messages().list(
            userId='me',
            labelIds=['INBOX'],
            maxResults=max_results,
            q='is:unread'
        ).execute()

        messages = results.get('messages', [])
        emails = []

        for msg in messages:
            msg_data = service.users().messages().get(
                userId='me', id=msg['id']
            ).execute()

            headers = {
                h['name']: h['value']
                for h in msg_data['payload']['headers']
            }

            body  = extract_body(msg_data['payload'])
            links = re.findall(r'https?://[^\s<>"\']+', body)

            emails.append({
                'id':      msg['id'],
                'subject': headers.get('Subject', '(No Subject)'),
                'from':    headers.get('From',    'Unknown'),
                'date':    headers.get('Date',    ''),
                'body':    body[:1500],
                'links':   links[:10],
            })

        return emails, None

    except Exception as e:
        return [], str(e)


# ── Quick test ──────────────────────────────────────────────
if __name__ == '__main__':
    emails, err = fetch_emails(5)
    if err:
        print('Error:', err)
    else:
        for e in emails:
            print(f"  [{e['from']}]  {e['subject']}")
