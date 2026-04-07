#!/usr/bin/env python3
"""
🌐 SOC Dashboard — Flask Backend
Serves the web dashboard and alert API
"""

from flask import Flask, jsonify, send_from_directory
import json

app = Flask(__name__, static_folder="static")

@app.route("/")
def index():
    return send_from_directory("static", "index.html")

@app.route("/api/alerts")
def get_alerts():
    alerts = []
    try:
        with open("alerts.json", "r") as f:
            for line in f:
                alerts.append(json.loads(line))
    except:
        pass
    return jsonify(sorted(alerts, key=lambda x: x.get("timestamp", ""), reverse=True)[:50])

@app.route("/api/stats")
def get_stats():
    alerts = []
    try:
        with open("alerts.json", "r") as f:
            alerts = [json.loads(l) for l in f]
    except:
        pass
    return jsonify({
        "total": len(alerts),
        "critical": sum(1 for a in alerts if a["severity"] == "CRITICAL"),
        "high": sum(1 for a in alerts if a["severity"] == "HIGH"),
        "medium": sum(1 for a in alerts if a["severity"] == "MEDIUM"),
        "rules_active": 13,
    })

if __name__ == "__main__":
    print("🌐 SOC Dashboard: http://localhost:5000")
    app.run(host="0.0.0.0", port=5000)
