# backend/cti_loader.py
# Pre-loads threat intelligence data at startup
from backend.ai.vulnerability import load_kev

_attack_data = None

def load_attack_data():
    global _attack_data
    import json, os
    path = "db/enterprise-attack.json"
    if not os.path.exists(path):
        print("[CTI] MITRE ATT&CK file not found — skipping")
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            _attack_data = json.load(f)
        count = len(_attack_data.get("objects", []))
        print(f"[CTI] ✓ MITRE ATT&CK loaded ({count} objects)")
        return _attack_data
    except Exception as e:
        print(f"[CTI] ATT&CK load error: {e}")
        return {}

def load_threat_intel():
    print("[INIT] Pre-loading threat intelligence...")
    try:
        kev = load_kev()
        print(f"[INIT] ✓ CISA KEV: {len(kev)} known exploited vulnerabilities")
    except Exception as e:
        print(f"[INIT] CISA KEV unavailable: {e}")
    try:
        load_attack_data()
    except Exception as e:
        print(f"[INIT] MITRE ATT&CK unavailable: {e}")