import streamlit as st
import json
from enrich import check_url_virustotal, check_ip_abuseipdb
from score import calculate_risk_score

st.set_page_config(page_title="Phishing Alert Triage Tool", layout="centered")

# ----------------------------
# Header
# ----------------------------
st.title("📧 Phishing Alert Enrichment & Triage Tool")
st.caption("SOC-style phishing alert analysis using threat intelligence")

# ----------------------------
# Upload JSON
# ----------------------------
uploaded_file = st.file_uploader(
    "Upload phishing alert JSON (Sentinel-style)",
    type=["json"]
)

if uploaded_file:
    alert = json.load(uploaded_file)

    st.subheader("📄 Alert Details")
    st.json(alert)

    if st.button("🔍 Run Enrichment & Triage"):
        with st.spinner("Enriching alert with threat intelligence..."):

            sender_ip = alert.get("SenderIP")
            urls = alert.get("Urls", [])

            # ----------------------------
            # Enrichment
            # ----------------------------
            vt_results = []
            for url in urls:
                vt_results.append(check_url_virustotal(url))

            abuse_result = check_ip_abuseipdb(sender_ip)

            # ----------------------------
            # Scoring
            # ----------------------------
            risk_score, verdict, reasons = calculate_risk_score(
                vt_results,
                abuse_result,
            )
            if "typosquatting" in " ".join(reasons).lower():
             st.warning("⚠️ Phishing pattern (typosquatting / suspicious domain) detected — elevated risk even with low VT hits.")
        # ----------------------------
        # Results
        # ----------------------------
        st.divider()
        st.subheader("🧠 Triage Result")

        if verdict.startswith("HIGH"):
            st.error(verdict)
        elif verdict.startswith("MEDIUM"):
            st.warning(verdict)
        else:
            st.success(verdict)

        st.metric(
            "Risk Score",
            f"{risk_score}/100",
            help="Calculated using VirusTotal detections, IP reputation, and noise reduction logic"
        )

        # ----------------------------
        # Decision Reasoning
        # ----------------------------
        st.subheader("🧠 Decision Reasoning")
        for reason in reasons:
            st.write(f"• {reason}")

        reasoning_text = " ".join(reasons)

        if "Tor" in reasoning_text:
            st.info(
                "ℹ️ Sender IP is a known Tor exit node. "
                "Tor exit nodes commonly generate high abuse reports and are a frequent source of false positives."
            )

        if "trusted domain" in reasoning_text:
            st.info(
                "ℹ️ Low VirusTotal detections on trusted domains are often noise and were down-weighted."
            )

        # ----------------------------
        # Sender IP Reputation
        # ----------------------------
        st.subheader("🌐 Sender IP Reputation")
        st.json(abuse_result)

        # ----------------------------
        # URL Analysis
        # ----------------------------
        st.subheader("🔗 URL Analysis (VirusTotal)")
        for r in vt_results:
            st.json(r)

        # ----------------------------
        # SOC Recommendation
        # ----------------------------
        st.subheader("✅ Recommended SOC Action")

        if risk_score >= 75:
            st.success(
                "Quarantine email, block sender IP/domain, reset affected credentials, and initiate incident response."
            )
        elif risk_score >= 40:
            st.warning(
                "Escalate for analyst review, monitor user activity, and validate indicators."
            )
        else:
            st.info(
                "Likely benign or noise-driven alert. Close as false positive with documentation."
            )
