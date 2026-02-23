#!/usr/bin/env python3
"""
Email Sentinel — Gmail OAuth2 setup helper.

Usage: python setup_gmail.py --token-path ~/.google_token.json --credentials ~/credentials.json

Requires: google-auth-oauthlib google-auth-httplib2 google-api-python-client
Install:  pip install google-auth-oauthlib google-auth-httplib2 google-api-python-client

SECURITY MANIFEST:
  Env variables accessed: none
  External endpoints: accounts.google.com (OAuth2 flow), gmail.googleapis.com (test)
  Local files written: token_path (Gmail OAuth2 token JSON)
  Local files read: credentials_path (Google Cloud OAuth2 credentials JSON)
"""
import argparse, json, os

def main():
    parser = argparse.ArgumentParser(description="Gmail OAuth2 authorization")
    parser.add_argument("--token-path",       default="~/.google_token.json")
    parser.add_argument("--credentials-path", default="~/credentials.json")
    args = parser.parse_args()

    token_path = os.path.expanduser(args.token_path)
    creds_path = os.path.expanduser(args.credentials_path)

    if not os.path.exists(creds_path):
        print(f"[ERROR] credentials.json not found at {creds_path}")
        print("\nTo get credentials.json:")
        print("1. Go to console.cloud.google.com")
        print("2. Create a project or select existing")
        print("3. Enable Gmail API")
        print("4. Create OAuth 2.0 credentials (Desktop application)")
        print("5. Download as credentials.json")
        return

    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build

    SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]
    flow   = InstalledAppFlow.from_client_secrets_file(creds_path, SCOPES)
    creds  = flow.run_local_server(port=0)

    with open(token_path, "w") as f:
        f.write(creds.to_json())

    print(f"\n✅ Token saved to {token_path}")

    # Test
    service = build("gmail", "v1", credentials=creds)
    profile = service.users().getProfile(userId="me").execute()
    print(f"✅ Authorized as: {profile['emailAddress']}")
    print(f"   Total messages: {profile['messagesTotal']}")

if __name__ == "__main__":
    main()
