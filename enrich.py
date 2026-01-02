import os
import requests
import time
from dotenv import load_dotenv

load_dotenv()

VT_KEY = os.getenv("VT_API_KEY")
ABUSE_KEY = os.getenv("ABUSEIPDB_API_KEY")


def check_url_virustotal(url):
    headers = {"x-apikey": VT_KEY}

    submit = requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers=headers,
        data={"url": url}
    )

    if submit.status_code != 200:
        return {"url": url, "error": "VT submit failed"}

    url_id = submit.json()["data"]["id"]
    time.sleep(15)

    report = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{url_id}",
        headers=headers
    )

    stats = report.json()["data"]["attributes"]["stats"]

    return {
        "url": url,
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0)
    }


def check_ip_abuseipdb(ip):
    headers = {
        "Key": ABUSE_KEY,
        "Accept": "application/json"
    }

    response = requests.get(
        "https://api.abuseipdb.com/api/v2/check",
        headers=headers,
        params={"ipAddress": ip, "maxAgeInDays": 90}
    )

    data = response.json()["data"]

    return {
        "ip": ip,
        "abuseScore": data["abuseConfidenceScore"],
        "country": data["countryCode"],
        "isp": data["isp"],
        "reports": data["numDistinctUsers"]
    }
