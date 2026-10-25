# backend/test_config.py
# ─────────────────────────────────────────────────────────────
#  Configuration Verification Script
#  Run this before training to confirm everything is set up
#  Usage: python -m backend.test_config
# ─────────────────────────────────────────────────────────────
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def check(label: str, ok: bool, detail: str = ""):
    status = "✓  OK   " if ok else "✗  FAIL "
    line   = f"  {status}  {label}"
    if detail:
        line += f"  ({detail})"
    print(line)
    return ok


def run_all_checks():
    print("=" * 60)
    print("  SOC Platform — Configuration Check")
    print("=" * 60)
    results = []

    # ── Python packages ───────────────────────────────────────
    print("\n  [ Python packages ]")
    packages = [
        ("flask",           "Flask"),
        ("flask_socketio",  "Flask-SocketIO"),
        ("flask_cors",      "Flask-CORS"),
        ("eventlet",        "Eventlet"),
        ("scapy",           "Scapy"),
        ("sklearn",         "scikit-learn"),
        ("pandas",          "pandas"),
        ("numpy",           "numpy"),
        ("joblib",          "joblib"),
        ("pymongo",         "pymongo"),
        ("requests",        "requests"),
        ("reportlab",       "reportlab"),
    ]
    for mod, name in packages:
        try:
            __import__(mod)
            results.append(check(name, True))
        except ImportError:
            results.append(check(name, False, f"pip install {name.lower()}"))

    # ── Dataset files ─────────────────────────────────────────
    print("\n  [ Dataset files ]")
    from backend.config import NF_UQ_PATH, NF_CIC_PATH, MITRE_ATTACK_PATH

    datasets = [
        (NF_UQ_PATH,        "NF-UQ-NIDS-v2.csv"),
        (NF_CIC_PATH,       "NF-CICIDS2018-v3.csv"),
        (MITRE_ATTACK_PATH, "enterprise-attack.json"),
    ]
    for path, name in datasets:
        exists = os.path.exists(path)
        size   = os.path.getsize(path) if exists else 0
        results.append(check(
            name, exists and size > 1000,
            f"{size/1024/1024:.1f} MB" if exists else "not found"
        ))

    # ── Network capture ───────────────────────────────────────
    print("\n  [ Network interface ]")
    from backend.config import CAPTURE_IFACE

    iface_set = CAPTURE_IFACE is not None and "PASTE-YOUR-GUID" not in CAPTURE_IFACE
    results.append(check(
        "CAPTURE_IFACE configured",
        iface_set,
        CAPTURE_IFACE if iface_set else "edit backend/config.py"
    ))

    if iface_set:
        try:
            from scapy.all import get_if_list
            ifaces = get_if_list()
            found  = CAPTURE_IFACE in ifaces
            results.append(check(
                "Interface exists on this machine", found,
                "not found in interface list" if not found else "ready"
            ))
        except Exception as e:
            results.append(check("Scapy interface check", False, str(e)))

    # ── Model files ───────────────────────────────────────────
    print("\n  [ ML models ]")
    from backend.config import MODEL_PATH, ISO_MODEL_PATH, SCALER_PATH, ENCODER_PATH

    models = [
        (MODEL_PATH,    "attack_model.pkl   (Random Forest)"),
        (ISO_MODEL_PATH,"iso_forest.pkl     (Isolation Forest)"),
        (SCALER_PATH,   "scaler.pkl"),
        (ENCODER_PATH,  "label_encoder.pkl"),
    ]
    models_missing = 0
    for path, name in models:
        exists = os.path.exists(path) and os.path.getsize(path) > 1000
        if not exists:
            models_missing += 1
        results.append(check(
            name, exists,
            "ready" if exists else "run: python -m backend.train"
        ))

    # ── Database ──────────────────────────────────────────────
    print("\n  [ Database ]")
    try:
        from pymongo import MongoClient
        c = MongoClient("mongodb://localhost:27017/",
                         serverSelectionTimeoutMS=2000)
        c.server_info()
        results.append(check("MongoDB", True, "connected"))
    except Exception:
        results.append(check("MongoDB", False,
                             "not running — SQLite fallback will be used"))

    sqlite_dir = os.path.dirname("db/detections.db")
    results.append(check(
        "db/ folder exists",
        os.path.exists("db"),
        "create: mkdir db" if not os.path.exists("db") else "ok"
    ))

    # ── API keys ──────────────────────────────────────────────
    print("\n  [ Threat intelligence API keys ]")
    from backend.config import ABUSEIPDB_KEY, OTX_KEY, VT_KEY

    keys = [
        (ABUSEIPDB_KEY, "AbuseIPDB",   "abuseipdb.com/account/api"),
        (OTX_KEY,       "AlienVault",  "otx.alienvault.com/api"),
        (VT_KEY,        "VirusTotal",  "virustotal.com/gui/my-apikey"),
    ]
    for key, name, url in keys:
        configured = bool(key) and not key.startswith("YOUR")
        results.append(check(
            f"{name} API key",
            configured,
            "configured" if configured else f"optional — register free at {url}"
        ))

    # ── Summary ───────────────────────────────────────────────
    passed = sum(results)
    total  = len(results)
    failed = total - passed

    print(f"\n{'=' * 60}")
    print(f"  Results: {passed}/{total} checks passed"
          f"  ({failed} failed)")

    if models_missing > 0:
        print(f"\n  ⚠  Models not trained yet.")
        print(f"     Run: python -m backend.train")

    if not iface_set:
        print(f"\n  ⚠  Network interface not configured.")
        print(f"     Run this to find your GUID:")
        print(f"       python -c \"from scapy.all import get_if_list,get_if_addr")
        print(f"       [print(i) for i in get_if_list() if '192.168.56' in (lambda x:x)(get_if_addr(i))]\"")
        print(f"     Then paste into backend/config.py  CAPTURE_IFACE = ...")

    if failed == 0:
        print(f"\n  ✓  All checks passed — ready to run!")
        print(f"     python -m backend.train   (first time only)")
        print(f"     python run.py")
    print("=" * 60)


if __name__ == "__main__":
    run_all_checks()