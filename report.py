from tabulate import tabulate
import datetime

def generate_report(alert, vt_results, abuse_result, score, verdict):
    print("\n" + "=" * 60)
    print("PHISHING ALERT TRIAGE REPORT")
    print("=" * 60)

    print(f"\nAlert: {alert['AlertTitle']}")
    print(f"Time: {alert['TimeGenerated']}")
    print(f"\nFinal Verdict: {verdict}")
    print(f"Risk Score: {score}/100\n")

    print("Sender IP Reputation:")
    print(f"IP: {abuse_result['ip']}")
    print(f"Abuse Score: {abuse_result['abuseScore']}%")
    print(f"Country / ISP: {abuse_result['country']} / {abuse_result['isp']}")
    print(f"Reports: {abuse_result['reports']}")

    table = []
    for r in vt_results:
        table.append([r["url"], r["malicious"], r["suspicious"], r["harmless"]])

    print("\nURL Analysis:")
    print(tabulate(
        table,
        headers=["URL", "Malicious", "Suspicious", "Harmless"],
        tablefmt="github"
    ))

    filename = f"report_{datetime.datetime.now().strftime('%Y%m%d_%H%M')}.md"
    with open(filename, "w") as f:
        f.write(f"# Phishing Triage Report\n\n")
        f.write(f"**Verdict:** {verdict}\n")
        f.write(f"**Risk Score:** {score}/100\n")

    print(f"\nReport saved as: {filename}")
