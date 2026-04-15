#!/usr/bin/env python3
"""
Quick connectivity test for Microsoft Graph API.
Verifies auth token, lists mailboxes accessible to the app,
and checks permissions. Run before phase1_search_soc_emails.py.
"""

import os
import sys
import json
import msal
import requests

TENANT_ID = os.environ.get("TENANT_ID", "")
CLIENT_ID = os.environ.get("CLIENT_ID", "")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "")
MAILBOX_UPN = os.environ.get("MAILBOX_UPN", "")
GRAPH_BASE = "https://graph.microsoft.com/v1.0"


def get_token():
    authority = f"https://login.microsoftonline.com/{TENANT_ID}"
    app = msal.ConfidentialClientApplication(
        CLIENT_ID, authority=authority, client_credential=CLIENT_SECRET
    )
    result = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])
    if "access_token" not in result:
        print(f"AUTH FAILED: {result.get('error_description', result)}")
        sys.exit(1)
    return result["access_token"]


def graph_get(token, path, params=None):
    url = f"{GRAPH_BASE}{path}" if not path.startswith("http") else path
    r = requests.get(url, headers={"Authorization": f"Bearer {token}"}, params=params, timeout=30)
    return r.status_code, r.json()


def main():
    print("\n=== Microsoft Graph API Connectivity Test ===\n")

    if not all([TENANT_ID, CLIENT_ID, CLIENT_SECRET]):
        print("ERROR: TENANT_ID, CLIENT_ID, CLIENT_SECRET must be set.")
        sys.exit(1)

    print("1. Acquiring access token...", end=" ", flush=True)
    token = get_token()
    print("OK")

    print("2. Verifying organization info...", end=" ", flush=True)
    status, data = graph_get(token, "/organization")
    if status == 200:
        orgs = data.get("value", [])
        if orgs:
            org = orgs[0]
            print(f"OK  ({org.get('displayName', 'unknown')})")
        else:
            print("OK (no org data)")
    else:
        print(f"FAILED ({status}): {data.get('error', {}).get('message', '')}")

    print("3. Checking app permissions (service principals)...", end=" ", flush=True)
    status, data = graph_get(token, "/servicePrincipals",
                             params={"$filter": f"appId eq '{CLIENT_ID}'",
                                     "$select": "displayName,appRoles"})
    if status == 200:
        sps = data.get("value", [])
        print(f"OK  (app: {sps[0].get('displayName', CLIENT_ID) if sps else 'not found'})")
    else:
        print(f"WARN ({status}): {data.get('error', {}).get('message', '')}")

    if MAILBOX_UPN:
        print(f"4. Testing mailbox access for {MAILBOX_UPN}...", end=" ", flush=True)
        status, data = graph_get(token, f"/users/{MAILBOX_UPN}",
                                 params={"$select": "displayName,mail,userPrincipalName"})
        if status == 200:
            print(f"OK  ({data.get('displayName', '')} / {data.get('mail', '')})")
        else:
            err = data.get("error", {})
            print(f"FAILED ({status}): {err.get('message', '')}")
            if status == 403:
                print("\n   --> App may be missing Mail.Read Application permission in Azure AD.")
                print("       Go to Azure AD > App registrations > API permissions > Add Mail.Read (Application)")

        print(f"5. Checking inbox message count for {MAILBOX_UPN}...", end=" ", flush=True)
        status, data = graph_get(
            token,
            f"/users/{MAILBOX_UPN}/messages",
            params={
                "$filter": "from/emailAddress/address eq 'soc@oculusit.com'",
                "$select": "id,subject,receivedDateTime",
                "$top": 5,
                "$orderby": "receivedDateTime desc",
            },
        )
        if status == 200:
            items = data.get("value", [])
            print(f"OK  ({len(items)} returned in this page)")
            print("\n   Most recent SOC emails:")
            for item in items:
                print(f"     {item.get('receivedDateTime','')[:10]}  {item.get('subject','')[:80]}")
        else:
            err = data.get("error", {})
            print(f"FAILED ({status}): {err.get('message', '')}")
            print(f"   Full error: {json.dumps(err, indent=4)}")
    else:
        print("4. Skipping mailbox test (MAILBOX_UPN not set).")
        print("   Set MAILBOX_UPN=your@email.edu and re-run to test mailbox access.")

    print("\n=== Test complete ===\n")


if __name__ == "__main__":
    main()
