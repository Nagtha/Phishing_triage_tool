# score.py

import re

TOR_KEYWORDS = ["tor", "exit", "artikel10", "anonymous", "mullvad", "protonvpn"]  # expanded a bit

BENIGN_DOMAINS = {
    "google.com", "www.google.com", "microsoft.com", "www.microsoft.com",
    "azure.com", "office.com", "bing.com", "github.com", "cloudflare.com",
    "login.microsoftonline.com", "accounts.google.com"  # add real login domains
}

# Simple phishing keyword patterns (typosquatting helpers)
PHISHING_PATTERNS = [
    r'microsof[t0]', r'micr0soft', r'microsoft-secure', r'office-365-login',
    r'login-secure', r'verify-account', r'account-verify', r'secure-login',
    r'bit\.ly', r'goo\.gl'  # common shorteners in phishing
]

def is_likely_typosquatting(url: str) -> bool:
    domain = url.lower().split('//')[-1].split('/')[0].split('?')[0]
    for pattern in PHISHING_PATTERNS:
        if re.search(pattern, domain):
            return True
    # Levenshtein-like simple check for microsoft/office
    if "microsoft" in domain or "office" in domain or "365" in domain:
        if len(domain) > 25 or '-' in domain or '0' in domain or 'secure' in domain:
            return True
    return False

def calculate_risk_score(vt_results: list, abuse_result: dict):
    score = 0
    reasons = []

    # 1. AbuseIPDB (IP reputation)
    if abuse_result and "error" not in abuse_result:
        abuse_score = abuse_result.get("abuseConfidenceScore", 0)
        isp = abuse_result.get("isp", "").lower()

        is_tor = any(kw in isp for kw in TOR_KEYWORDS)
        if is_tor:
            reasons.append("Sender IP appears to be a Tor exit node — high abuse reports expected, partially down-weighted")
            score += abuse_score * 0.4      # ← increased from 0.2 — Tor often used in phishing
        else:
            score += abuse_score * 0.6      # ← slight increase for non-Tor
            if abuse_score > 70:
                reasons.append(f"High AbuseIPDB score ({abuse_score}%) — potential malicious sender")

    # 2. VirusTotal + Phishing heuristics
    has_typosquatting = False
    for res in vt_results:
        if "error" in res:
            continue

        url = res.get("url", "").lower()
        malicious = res.get("malicious", 0)
        suspicious = res.get("suspicious", 0)
        harmless = res.get("harmless", 0)
        total = malicious + suspicious + harmless + res.get("undetected", 0)  # safer

        # Typosquatting / phishing pattern check FIRST
        if is_likely_typosquatting(url):
            has_typosquatting = True
            score += 25  # strong boost — phishing hallmark
            reasons.append(f"URL shows phishing/typosquatting patterns ({url}) — high risk indicator")

        # Skip trusted/benign domains after pattern check
        if any(domain in url for domain in BENIGN_DOMAINS):
            reasons.append(f"URL belongs to known trusted domain ({url}) — ignored")
            continue

        # Detection scoring (tuned for phishing)
        if malicious >= 3:                      # ← lowered from 5
            score += malicious * 18             # heavier weight
            reasons.append(f"Strong VT malicious detections ({malicious}/{total})")
        elif malicious >= 1:
            score += malicious * 10 + 10        # base + per detection
            reasons.append(f"Some VT malicious detections ({malicious}/{total}) — suspicious")
        elif suspicious >= 2:
            score += suspicious * 8
            reasons.append(f"Suspicious detections ({suspicious}) — review needed")

        if total > 0 and malicious + suspicious == 0:
            score += 5  # minimal bump for any analysis with no clean sweep

    # Extra boost if typosquatting + any detection
    if has_typosquatting and (malicious > 0 or suspicious > 0):
        score += 15
        reasons.append("Typosquatting combined with VT detections — very high phishing likelihood")

    # Final normalization
    score = max(0, min(int(score), 100))

    # Verdict
    if score >= 70:                             # slightly lower threshold
        verdict = "HIGH – Confirmed Phishing"
    elif score >= 35:
        verdict = "MEDIUM – Suspicious"
    else:
        verdict = "LOW – Likely Benign"

    if not reasons:
        reasons.append("No significant malicious indicators after noise filtering")

    return score, verdict, reasons