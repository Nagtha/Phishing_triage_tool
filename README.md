# Phishing Alert Enrichment & Triage Tool

This project simulates a SOC-style phishing alert triage workflow similar to Microsoft Sentinel or MxDR environments.

The tool enriches phishing alerts using public threat intelligence sources and applies scoring logic to help analysts quickly decide whether an alert is real, benign noise, or needs escalation.

## What this tool does
- Accepts Sentinel-style phishing alert JSON
- Enriches sender IP using AbuseIPDB
- Enriches URLs using VirusTotal
- Detects phishing patterns such as typosquatting
- Down-weights common noise sources (Tor exit nodes, trusted domains)
- Provides risk score, verdict, reasoning, and SOC action

## Why this matters
SOC teams spend significant time triaging phishing alerts that turn out to be noise.
This tool demonstrates how enrichment and logic can reduce false positives and analyst fatigue.

## Tech stack
- Python
- Streamlit
- VirusTotal API
- AbuseIPDB API

## Demo
A short demo video is available on LinkedIn showing:
- Noise/Benign alert handling
- Malicious phishing alert detection
