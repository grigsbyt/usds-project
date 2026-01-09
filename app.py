import requests
import json
from datetime import datetime
from flask import Flask, jsonify, render_template_string, request
import threading
import os
import secrets

app = Flask(__name__)

# Secure storage: In-memory for simplicity, but in production use encrypted database.
# We'll store in a file encrypted with a key, but for demo, use in-memory.
KEV_DATA = None
SIMULATED_INVENTORY = [
    {"asset_id": "server1", "os": "Windows Server 2019", "vulns": ["CVE-2021-34527", "CVE-2023-23397"]},
    {"asset_id": "server2", "os": "Linux Ubuntu 20.04", "vulns": ["CVE-2021-3156", "CVE-2024-12345"]},
    {"asset_id": "workstation1", "os": "Windows 10", "vulns": ["CVE-2022-30190", "CVE-2021-34527"]},
    {"asset_id": "router1", "os": "Cisco IOS", "vulns": ["CVE-2019-12643"]},
    {"asset_id": "server3", "os": "Red Hat Enterprise Linux 8", "vulns": ["CVE-2023-38408"]},
]

# Original Metric: "Exploitation Recency Score" (ERS)
# Definition: ERS = 100 - (days since added to KEV / 365 * 100), clamped to 0-100.
# Higher score means more recent exploitation, indicating higher urgency.
# Why it helps: Federal agencies deal with large inventories; ERS prioritizes recently exploited vulns,
# as threat actors often reuse fresh exploits. This drives faster patching decisions, reducing window of exposure.

def fetch_kev_data():
    global KEV_DATA
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        response = requests.get(url)
        response.raise_for_status()
        KEV_DATA = response.json()["vulnerabilities"]
        # Store securely: For demo, save to file with random key (not real encryption, illustrative).
        key = secrets.token_hex(16)
        with open("kev_data.enc", "w") as f:
            f.write(key + json.dumps(KEV_DATA))  # Dummy "encryption"
        print("KEV data fetched and stored.")
    except Exception as e:
        print(f"Error fetching KEV: {e}")
        KEV_DATA = []

def load_kev_data():
    global KEV_DATA
    if os.path.exists("kev_data.enc"):
        with open("kev_data.enc", "r") as f:
            data = f.read()
            # Dummy decrypt: skip first 32 chars (hex key)
            KEV_DATA = json.loads(data[32:])
    if KEV_DATA is None:
        fetch_kev_data()

def get_kev_info(cve_id):
    for vuln in KEV_DATA:
        if vuln["cveID"] == cve_id:
            return vuln
    return None

def calculate_ers(date_added):
    if not date_added:
        return 0
    added_date = datetime.strptime(date_added, "%Y-%m-%d")
    days_since = (datetime.now() - added_date).days
    ers = max(0, 100 - (days_since / 365 * 100))
    return round(ers, 2)

# API Endpoints

@app.route('/api/risk_scores', methods=['GET'])
def risk_scores():
    scores = []
    for asset in SIMULATED_INVENTORY:
        risk = 0
        kev_count = 0
        for vuln in asset["vulns"]:
            kev = get_kev_info(vuln)
            if kev:
                kev_count += 1
                risk += calculate_ers(kev["dateAdded"])
        avg_risk = risk / len(asset["vulns"]) if asset["vulns"] else 0
        scores.append({
            "asset_id": asset["asset_id"],
            "kev_vulns": kev_count,
            "average_ers": avg_risk,
            "risk_level": "High" if avg_risk > 70 else "Medium" if avg_risk > 30 else "Low"
        })
    return jsonify(scores)

@app.route('/api/prioritization', methods=['GET'])
def prioritization():
    priorities = []
    for asset in SIMULATED_INVENTORY:
        for vuln in asset["vulns"]:
            kev = get_kev_info(vuln)
            if kev:
                priorities.append({
                    "asset_id": asset["asset_id"],
                    "cve": vuln,
                    "ers": calculate_ers(kev["dateAdded"]),
                    "mitigation": kev.get("shortDescription", "Patch immediately."),
                    "priority": "Critical" if calculate_ers(kev["dateAdded"]) > 80 else "High"
                })
    priorities.sort(key=lambda x: x["ers"], reverse=True)
    return jsonify(priorities[:10])  # Top 10

@app.route('/api/trends', methods=['GET'])
def trends():
    vendor_counts = {}
    for vuln in KEV_DATA:
        vendor = vuln.get("vendorProject", "Unknown")
        vendor_counts[vendor] = vendor_counts.get(vendor, 0) + 1
    top_vendors = sorted(vendor_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    trends_data = {
        "top_exploited_vendors": top_vendors,
        "total_kev": len(KEV_DATA),
        "recent_additions": len([v for v in KEV_DATA if calculate_ers(v["dateAdded"]) > 50])
    }
    return jsonify(trends_data)

# Simple UI
UI_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Security Assessment</title>
    <style>
        body { font-family: Arial; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>Security Review Dashboard</h1>
    <h2>Asset Risk Scores</h2>
    <table>
        <tr><th>Asset ID</th><th>KEV Vulns</th><th>Avg ERS</th><th>Risk Level</th></tr>
        {% for score in risk_scores %}
        <tr><td>{{ score.asset_id }}</td><td>{{ score.kev_vulns }}</td><td>{{ score.average_ers }}</td><td>{{ score.risk_level }}</td></tr>
        {% endfor %}
    </table>
    <h2>Prioritization</h2>
    <table>
        <tr><th>Asset ID</th><th>CVE</th><th>ERS</th><th>Priority</th><th>Mitigation</th></tr>
        {% for prio in prioritization %}
        <tr><td>{{ prio.asset_id }}</td><td>{{ prio.cve }}</td><td>{{ prio.ers }}</td><td>{{ prio.priority }}</td><td>{{ prio.mitigation }}</td></tr>
        {% endfor %}
    </table>
    <h2>Trends</h2>
    <ul>
        <li>Total KEV: {{ trends.total_kev }}</li>
        <li>Recent Additions (ERS > 50): {{ trends.recent_additions }}</li>
        <li>Top Exploited Vendors:
            <ul>
                {% for vendor, count in trends.top_exploited_vendors %}
                <li>{{ vendor }}: {{ count }}</li>
                {% endfor %}
            </ul>
        </li>
    </ul>
</body>
</html>
"""

@app.route('/', methods=['GET'])
def ui():
    risk_scores_data = requests.get("http://127.0.0.1:5000/api/risk_scores").json()
    prioritization_data = requests.get("http://127.0.0.1:5000/api/prioritization").json()
    trends_data = requests.get("http://127.0.0.1:5000/api/trends").json()
    return render_template_string(UI_HTML, risk_scores=risk_scores_data, prioritization=prioritization_data, trends=trends_data)

if __name__ == '__main__':
    load_kev_data()
    app.run(debug=True)