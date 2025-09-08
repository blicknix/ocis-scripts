#!/bin/python3
import requests
import math
import env


def get_bearer_token():
    """Prompt the user for a Bearer token. Needs to be Admin Role"""
    return input("Enter your Bearer token: ").strip()


def build_headers(token):
    """Build request headers with the Bearer token."""
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
        "personal_deleted": 0,
        "spaces_deleted": 0,
        "user_space": 0,
        "quota_normal": 0,
        "quota_nearing": 0,
        "quota_critical": 0,
        "quota_exceeded": 0,
    }

    for drive in drives:
        if drive['driveType'] == "project":
            if "deleted" in drive['root']:
                stats["spaces_deleted"] += 1
            else:
                stats["spaces"] += 1

        elif drive['driveType'] == "personal":
            if "deleted" in drive['root']:
                stats["personal_deleted"] += 1
            else:
                stats["personal"] += 1

        if "quota" in drive and "deleted" not in drive["root"]:
            stats["user_space"] += drive["quota"]["used"]

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
    return stats


def print_report(stats):
    """Print a formatted report from the analyzed statistics."""
    print("\nREPORT")
    print("=======")
    print("Spaces            Anzahl(Gelöscht)")
    print("-------")
    print(f"Personal Spaces:  {stats['personal']} ({stats['personal_deleted']})")
    print(f"Shared Spaces:    {stats['spaces']} ({stats['spaces_deleted']})")
    print("\n---")
    print(f"Used Space:       {round(stats['user_space'], 2)} GB")
    print("Quota Status:")
    print(f"<75%:             {stats['quota_normal']}")
    print(f"75%-89%:          {stats['quota_nearing']}")
    print(f"90%-99%:          {stats['quota_critical']}")
    print(f"100%:             {stats['quota_exceeded']}")
    print("")


def main(token=None):
    if token is None:
        token = get_bearer_token()
    headers = build_headers(token)

    print("\nValidating token...")
    if not validate_token(headers):
        print("Invalid Bearer token. Please check and try again.")
        return

    try:
        drives = fetch_drives(headers)
        stats = analyze_drives(drives)
        print_report(stats)
    except Exception as e:
        print("Error:", e)


if __name__ == "__main__":
    main()