#!/bin/python3
import requests
import math
import env
from base64 import b64encode

#Global envs
auth_mode = ''


def get_bearer_token():
    """Prompt the user for a Bearer token. Needs to be Admin Role"""
    return input("Enter your Bearer token: ").strip()


def build_headers(token):
    """Build request headers with a token."""
    global auth_mode
    if hasattr(env, 'OCIS_USER') and hasattr(env, 'OCIS_USER_TOKEN'):
        # Use as username/password
        auth_mode = "basic"
        print(f"Using USER/PASSWORD authentication with user: {env.OCIS_USER}")
        app_token = b64encode(f"{env.OCIS_USER}:{env.OCIS_USER_TOKEN}".encode('utf-8')).decode("ascii")

        return {
            'accept': 'application/json',
            'Authorization': f'Basic {app_token}'
        }
    else:
        # Ask for Bearer token
        auth_mode = "bearer"
        if token is None:
            token = get_bearer_token()
        print("Using Bearer token authentication.")
        
        return {
            'accept': 'application/json',
            'Authorization': f'Bearer {token}'
        }


def validate_token(headers):
    """
    Test if the Bearer token is valid by making a test request.
    Returns True if valid, False otherwise.
    """
    test_url = env.OCIS_URL + "graph/v1.0/me"  # Using a common endpoint for auth validation
    response = requests.get(test_url, headers=headers)
    return response.status_code == 200


def fetch_drives(headers):
    """Fetch all drives from the API."""
    url = env.OCIS_URL + "graph/v1.0/drives"
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        raise Exception(f"Failed to fetch drives: {response.status_code} - {response.text}")

    return response.json().get('value', [])


def analyze_drives(drives):
    """
    Analyze drives and compute statistics.
    Returns a dictionary with all metrics.
    """
    stats = {
        "personal": 0,
        "spaces": 0,
        "personal_disabled": 0,
        "spaces_disabled": 0,
        "user_space": 0,
        "user_space_personal": 0,
        "user_space_shared": 0,
        "quota_normal": 0,
        "quota_nearing": 0,
        "quota_critical": 0,
        "quota_exceeded": 0,
    }

    for drive in drives:
        if drive['driveType'] == "project":
            if "deleted" in drive['root']:
                stats["spaces_disabled"] += 1
            else:
                stats["spaces"] += 1

        elif drive['driveType'] == "personal":
            if "deleted" in drive['root']:
                stats["personal_disabled"] += 1
            else:
                stats["personal"] += 1

        if "quota" in drive and "deleted" not in drive["root"]:
            stats["user_space"] += drive["quota"]["used"]
            if drive['driveType'] == "project":
                stats["user_space_shared"] += drive["quota"]["used"]
            elif drive['driveType'] == "personal":
                stats["user_space_personal"] += drive["quota"]["used"]

        elif drive['driveType'] == "personal":

            state = drive["quota"].get("state", "normal")
            if state == "exceeded":
                stats["quota_exceeded"] += 1
            elif state == "critical":
                stats["quota_critical"] += 1
            elif state == "nearing":
                stats["quota_nearing"] += 1
            else:
                stats["quota_normal"] += 1

    stats["user_space"] = stats["user_space"] / 1024 / 1024 / 1024  # Convert to GB
    stats["user_space_shared"] = stats["user_space_shared"] / 1024 / 1024 / 1024  # Convert to GB
    stats["user_space_personal"] = stats["user_space_personal"] / 1024 / 1024 / 1024  # Convert to GB
    return stats


def print_report(stats):
    """Print a formatted report from the analyzed statistics."""
    print("\nREPORT")
    print("=======")
    print("Spaces            Anzahl(Gelöscht)")
    print("-------")
    print(f"Personal Spaces:     {stats['personal']} ({stats['personal_disabled']})")
    print(f"Shared Spaces:       {stats['spaces']} ({stats['spaces_disabled']})")
    print("\n---")
    print(f"Used Space:          {round(stats['user_space'], 2)} GB")
    print(f"Used personal Space: {round(stats['user_space_personal'], 2)} GB")
    print(f"Used project Space:  {round(stats['user_space_shared'], 2)} GB")
    print("Quota Status:")
    print(f"<75%:                {stats['quota_normal']}")
    print(f"75%-89%:             {stats['quota_nearing']}")
    print(f"90%-99%:             {stats['quota_critical']}")
    print(f"100%:                {stats['quota_exceeded']}")
    print("")


def main(token=None):
    headers = build_headers(token)

    print("\nValidating token...")
    if not validate_token(headers):
        print("Invalid Auth. Please check and try again.")
        return

    try:
        drives = fetch_drives(headers)
        stats = analyze_drives(drives)
        print_report(stats)
    except Exception as e:
        print("Error:", e)


if __name__ == "__main__":
    main()