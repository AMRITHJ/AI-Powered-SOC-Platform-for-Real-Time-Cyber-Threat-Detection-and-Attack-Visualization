# install_files.py
# ─────────────────────────────────────────────────────────────
#  SOC Platform — Project Setup Script
#  Run once after cloning to create all required folders
#  Usage: python install_files.py
# ─────────────────────────────────────────────────────────────
import os
import sys

DIRS = [
    "backend/models",
    "backend/ai",
    "backend/threat_intelligence",
    "backend/network",
    "backend/response",
    "backend/utils",
    "backend/api",
    "frontend/static/js",
    "frontend/static/css",
    "db",
    "reports",
    "logs",
]

INIT_DIRS = [
    "backend",
    "backend/ai",
    "backend/threat_intelligence",
    "backend/network",
    "backend/response",
    "backend/utils",
    "backend/api",
]

GITKEEP_DIRS = [
    "backend/models",
    "reports",
    "logs",
]


def create_dirs():
    print("\n[SETUP] Creating folder structure...")
    for d in DIRS:
        os.makedirs(d, exist_ok=True)
        print(f"  ✓  {d}/")


def create_init_files():
    print("\n[SETUP] Creating __init__.py files...")
    for d in INIT_DIRS:
        path = os.path.join(d, "__init__.py")
        if not os.path.exists(path):
            open(path, "w").close()
            print(f"  ✓  {path}")
        else:
            print(f"  –  {path} (exists)")


def create_gitkeep():
    print("\n[SETUP] Creating .gitkeep placeholders...")
    for d in GITKEEP_DIRS:
        path = os.path.join(d, ".gitkeep")
        if not os.path.exists(path):
            open(path, "w").close()
            print(f"  ✓  {path}")


def check_existing_files():
    print("\n[SETUP] Checking existing backend files...")
    core_files = [
        "backend/config.py",
        "backend/app.py",
        "backend/capture.py",
        "backend/classifier.py",
        "backend/database.py",
        "backend/detect.py",
        "backend/honeypot.py",
        "backend/preprocess.py",
        "backend/train.py",
        "backend/validator.py",
        "backend/cti_loader.py",
        "backend/test_config.py",
        "backend/ai/attack_classifier.py",
        "backend/ai/anomaly.py",
        "backend/ai/risk_engine.py",
        "backend/ai/vulnerability.py",
        "backend/threat_intelligence/abuseipdb.py",
        "backend/threat_intelligence/virustotal.py",
        "backend/threat_intelligence/otx.py",
        "backend/network/flow_generator.py",
        "backend/network/scanner.py",
        "backend/network/topology.py",
        "backend/response/alert.py",
        "backend/response/firewall.py",
        "backend/response/quarantine.py",
        "backend/utils/helpers.py",
        "backend/utils/logger.py",
        "backend/api/routes.py",
        "run.py",
        "requirements.txt",
    ]

    missing = []
    for f in core_files:
        if not os.path.exists(f):
            missing.append(f)
            print(f"  ✗  MISSING  {f}")
        else:
            size = os.path.getsize(f)
            if size < 50:
                print(f"  ⚠  EMPTY    {f}  ({size} bytes)")
                missing.append(f)
            else:
                print(f"  ✓  OK       {f}  ({size:,} bytes)")
    return missing


def print_next_steps(missing):
    print("\n" + "=" * 60)
    if missing:
        print(f"  ⚠  {len(missing)} file(s) need content:")
        for f in missing:
            print(f"     – {f}")
        print("\n  Copy the files from the Claude downloads into")
        print("  the matching paths above, then run:")
    else:
        print("  ✓  All files present")
        print("\n  Next steps:")
    print()
    print("  1. Verify config:")
    print("       python -m backend.test_config")
    print()
    print("  2. Get your VMnet1 GUID (if not set in config.py):")
    print("       python -c \"")
    print("       from scapy.all import get_if_list, get_if_addr")
    print("       for i in get_if_list():")
    print("           try:")
    print("               ip = get_if_addr(i)")
    print("               if '192.168.56' in ip: print('GUID:', i)")
    print("           except: pass")
    print("       \"")
    print()
    print("  3. Train ML models (first time only):")
    print("       python -m backend.train")
    print()
    print("  4. Start the platform:")
    print("       python run.py")
    print()
    print("  5. Open browser:")
    print("       http://localhost:5000")
    print("=" * 60)


if __name__ == "__main__":
    print("=" * 60)
    print("  SOC Platform — Project Setup")
    print("  MSc Cyber Security · Middlesex University London")
    print("=" * 60)

    create_dirs()
    create_init_files()
    create_gitkeep()
    missing = check_existing_files()
    print_next_steps(missing)