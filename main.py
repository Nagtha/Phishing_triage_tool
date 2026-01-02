import json
from enrich import check_url_virustotal, check_ip_abuseipdb
from score import calculate_risk_score
from report import generate_report

def main():
    with open("samples/alert_example.json") as f:
        alert = json.load(f)

    sender_ip = alert["SenderIP"]
    urls = alert["Urls"]

    vt_results = [check_url_virustotal(url) for url in urls]
    abuse_result = check_ip_abuseipdb(sender_ip)

    score, verdict = calculate_risk_score(vt_results, abuse_result)

    generate_report(alert, vt_results, abuse_result, score, verdict)

if __name__ == "__main__":
    main()
