#!/usr/bin/env python3
"""
🛡️ SIEM Detection Engine v1.0
Listens to Elasticsearch -> Runs detection rules -> Sends Telegram alerts
"""

import time, json, requests
from datetime import datetime, timedelta, timezone
from detection_rules import RULES

# ══════════ CONFIGURATION ══════════
ES_URL = "http://localhost:9200"
ES_INDEX = "winlogbeat-*"
TELEGRAM_TOKEN = "YOUR_BOT_TOKEN"       # <- from @BotFather
TELEGRAM_CHAT_ID = "YOUR_CHAT_ID"       # <- from getUpdates
CHECK_INTERVAL = 10  # seconds
ALERTS_LOG = "alerts.json"
# ════════════════════════════════════

EMOJI = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}


def send_telegram(alert):
    msg = (
        f"{EMOJI.get(alert['severity'], '⚪')} *{alert['severity']}* — {alert['rule_name']}\n"
        f"📋 Rule: {alert['rule_id']} | MITRE: {alert['mitre']}\n"
        f"📝 {alert['description']}\n"
        f"🕐 {alert['timestamp']}"
    )
    try:
        requests.post(
            f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
            json={"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "Markdown"},
            timeout=5
        )
    except Exception as e:
        print(f"  [!] Telegram error: {e}")


def fetch_logs(since):
    query = {
        "query": {"range": {"@timestamp": {"gt": since.isoformat()}}},
        "sort": [{"@timestamp": "asc"}],
        "size": 100
    }
    try:
        r = requests.post(f"{ES_URL}/{ES_INDEX}/_search", json=query, timeout=10)
        return [h["_source"] for h in r.json().get("hits", {}).get("hits", [])]
    except Exception as e:
        print(f"  [!] ES error: {e}")
        return []


def save_alert(alert):
    with open(ALERTS_LOG, "a") as f:
        f.write(json.dumps(alert, ensure_ascii=False) + "\n")
    try:
        requests.post(f"{ES_URL}/siem-alerts/_doc", json=alert, timeout=5)
    except:
        pass


def main():
    print("=" * 50)
    print("🛡️  SIEM Detection Engine v1.0")
    print(f"📡 {ES_URL}/{ES_INDEX}")
    print(f"📋 {len(RULES)} detection rules loaded:")
    for r in RULES:
        print(f"   {r.rule_id} — {r.name} [{r.severity}] ({r.mitre})")
    print("=" * 50)

    last_check = datetime.now(timezone.utc) - timedelta(minutes=5)
    count = 0

    while True:
        logs = fetch_logs(last_check)
        if logs:
            print(f"\n[*] {len(logs)} new logs")
            last_check = datetime.now(timezone.utc)
            for log in logs:
                for rule_func in RULES:
                    try:
                        result = rule_func(log)
                        if result:
                            count += 1
                            alert = {
                                "id": count,
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "rule_id": rule_func.rule_id,
                                "rule_name": rule_func.name,
                                "severity": rule_func.severity,
                                "mitre": rule_func.mitre,
                                "description": result["description"],
                                "raw": result.get("raw", ""),
                            }
                            print(f"  🚨 [{alert['severity']}] {alert['rule_id']}: {alert['description']}")
                            save_alert(alert)
                            send_telegram(alert)
                    except Exception as e:
                        print(f"  [!] {rule_func.rule_id} error: {e}")
        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    main()
