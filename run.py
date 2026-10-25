# run.py
# ─────────────────────────────────────────────────────────────
# SOC Platform — Entry Point
# MSc Cyber Security · Middlesex University London
#
# Starts:
#   1. Database
#   2. ML models
#   3. Threat intelligence
#   4. Packet capture
#   5. Detection engine
#   6. Honeypot watchers
#   7. Flask/SocketIO dashboard
# ─────────────────────────────────────────────────────────────

import sys
import os
import time
import threading

# Ensure project root is available
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from backend.capture import (
    list_interfaces,
    start_capture_thread,
    get_packet_count,
)

from backend.database import init_sqlite
from backend.classifier import load_models
from backend.cti_loader import load_threat_intel
from backend.detect import start_detection_thread
from backend.honeypot import start_honeypot_threads

from backend.app import (
    socketio,
    app,
    start_platform,
    handle_detection,
    handle_honeypot_session,
    handle_canary_trigger,
)

import backend.detect as detect_module


# ─────────────────────────────────────────────────────────────
# Banner
# ─────────────────────────────────────────────────────────────

def print_banner():
    print("=" * 70)
    print("  SOC Platform v1.0")
    print("  AI-Powered Threat Intelligence & Attack Visualization")
    print("=" * 70)


# ─────────────────────────────────────────────────────────────
# Network interfaces
# ─────────────────────────────────────────────────────────────

def print_interfaces():
    print("\n[INFO] Network interfaces:")

    try:
        interfaces = list_interfaces()

        if not interfaces:
            print("       [WARNING] No interfaces detected")
            return

        for iface in interfaces:
            tag = ""

            # Mark VMnet1 / SOC lab interface where possible
            if "56.1" in str(iface):
                tag = " ← VMnet1 (SOC lab)"

            print(f"       {iface}{tag}")

    except Exception as e:
        print(f"[ERROR] Could not enumerate interfaces: {e}")


# ─────────────────────────────────────────────────────────────
# ML models
# ─────────────────────────────────────────────────────────────

def check_models():

    print("\n[INIT] Loading models (RF + Isolation Forest + LSTM)...")

    try:
        ok = load_models()
    except Exception as e:
        print(f"[ERROR] Model loading failed: {e}")
        print("[WARN] Continuing with rule-based detection")
        return False

    if ok:

        try:
            from backend.ai.attack_classifier import get_model_info

            info = get_model_info()

            print(
                f"[INIT] ✓ Models active: "
                f"{info.get('models_active', 'RF only')}"
            )

            if info.get("rf_accuracy") not in ("N/A", None):
                try:
                    print(
                        f"[INIT]   RF accuracy   : "
                        f"{float(info['rf_accuracy']) * 100:.2f}%"
                    )
                except Exception:
                    pass

            if info.get("lstm_accuracy") not in ("N/A", None):
                try:
                    print(
                        f"[INIT]   LSTM accuracy : "
                        f"{float(info['lstm_accuracy']) * 100:.2f}%"
                    )
                except Exception:
                    pass

        except Exception as e:
            print(f"[WARN] Could not read model information: {e}")

    else:
        print("[WARN] ─────────────────────────────────────────────")
        print("[WARN] No ML models found.")
        print("[WARN] Rule-based detection will still be active.")
        print("[WARN] Train RF with:")
        print("[WARN]     python -m backend.train")
        print("[WARN] Optional LSTM:")
        print("[WARN]     python -m backend.train_lstm")
        print("[WARN] ─────────────────────────────────────────────")

    return ok


# ─────────────────────────────────────────────────────────────
# Runtime monitor
#
# This does NOT perform detection.
# It only proves that:
#   - capture thread is alive
#   - detection thread is alive
#   - packets are actually increasing
#
# This is important for diagnosing the current problem.
# ─────────────────────────────────────────────────────────────

def runtime_monitor(capture_thread, detection_thread):

    previous_packets = 0

    print("[MONITOR] Runtime monitor started")

    while True:

        try:
            current_packets = get_packet_count()

            capture_alive = (
                capture_thread is not None
                and capture_thread.is_alive()
            )

            detection_alive = (
                detection_thread is not None
                and detection_thread.is_alive()
            )

            packet_delta = current_packets - previous_packets

            print(
                f"[MONITOR] "
                f"Packets={current_packets} "
                f"(+{packet_delta}) | "
                f"Capture={'RUNNING' if capture_alive else 'STOPPED'} | "
                f"Detection={'RUNNING' if detection_alive else 'STOPPED'}"
            )

            previous_packets = current_packets

            if not capture_alive:
                print(
                    "[MONITOR][WARNING] "
                    "Packet capture thread is NOT running!"
                )

            if not detection_alive:
                print(
                    "[MONITOR][WARNING] "
                    "Detection thread is NOT running!"
                )

        except Exception as e:
            print(f"[MONITOR] Error: {e}")

        time.sleep(5)


# ─────────────────────────────────────────────────────────────
# Ready message
# ─────────────────────────────────────────────────────────────

def print_ready():

    print("\n" + "=" * 70)
    print("  ✓ SOC Platform is running")
    print("=" * 70)

    print()
    print("  Dashboard     → http://localhost:5000")
    print("  API Status    → http://localhost:5000/api/status")
    print("  Detections    → http://localhost:5000/api/detections")
    print("  Model Info    → http://localhost:5000/api/model")
    print("  Topology      → http://localhost:5000/api/topology")

    print()
    print("  Kali attack simulations:")
    print("    Port scan → nmap -sS 192.168.56.30")
    print("    SSH BF    → hydra -l root -P wordlist.txt ssh://192.168.56.30")
    print("    DDoS      → sudo hping3 --flood -S 192.168.56.30")

    print()
    print("  Press Ctrl+C to stop")
    print("=" * 70)
    print()


# ─────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":

    print_banner()

    # ─────────────────────────────────────────────────────────
    # 1. Interfaces
    # ─────────────────────────────────────────────────────────

    print_interfaces()

    # ─────────────────────────────────────────────────────────
    # 2. Database
    # ─────────────────────────────────────────────────────────

    print("[INIT] Initialising database...")

    try:
        init_sqlite()
        print("[INIT] ✓ Database ready")
    except Exception as e:
        print(f"[ERROR] Database initialisation failed: {e}")
        raise

    # ─────────────────────────────────────────────────────────
    # 3. ML models
    # ─────────────────────────────────────────────────────────

    check_models()

    # ─────────────────────────────────────────────────────────
    # 4. Threat intelligence
    # ─────────────────────────────────────────────────────────

    print("[INIT] Loading threat intelligence...")

    try:
        load_threat_intel()
        print("[INIT] ✓ Threat intelligence loaded")
    except Exception as e:
        print(f"[WARN] Threat intelligence loading failed: {e}")

    # ─────────────────────────────────────────────────────────
    # 5. Connect detection callback
    # ─────────────────────────────────────────────────────────

    print("[INIT] Connecting detection callback...")

    detect_module.on_detection = handle_detection

    if detect_module.on_detection is handle_detection:
        print("[INIT] ✓ Detection callback connected")
    else:
        print("[ERROR] Detection callback was NOT connected!")

    # ─────────────────────────────────────────────────────────
    # 6. Start packet capture
    # ─────────────────────────────────────────────────────────

    print("\n[INIT] Starting packet capture...")

    try:

        capture_thread = start_capture_thread()

        time.sleep(1)

        if capture_thread and capture_thread.is_alive():
            print("[INIT] ✓ Packet capture thread running")
        else:
            print("[ERROR] Packet capture thread stopped!")

    except Exception as e:

        print(f"[ERROR] Failed to start packet capture: {e}")
        raise

    # ─────────────────────────────────────────────────────────
    # 7. Start detection engine
    # ─────────────────────────────────────────────────────────

    print("\n[INIT] Starting detection engine...")

    try:

        detection_thread = start_detection_thread(
            interval=2.0
        )

        time.sleep(1)

        if detection_thread and detection_thread.is_alive():
            print("[INIT] ✓ Detection thread running")
        else:
            print("[ERROR] Detection thread stopped!")

    except Exception as e:

        print(f"[ERROR] Failed to start detection engine: {e}")
        raise

    # ─────────────────────────────────────────────────────────
    # 8. Start honeypot watchers
    # ─────────────────────────────────────────────────────────

    print("\n[INIT] Starting honeypot watchers...")

    try:

        start_honeypot_threads(
            on_cowrie_session=handle_honeypot_session,
            on_canary_trigger=handle_canary_trigger,
        )

        print("[INIT] ✓ Honeypot watchers started")

    except Exception as e:

        print(f"[WARN] Honeypot startup failed: {e}")

    # ─────────────────────────────────────────────────────────
    # 9. Platform initialisation
    # ─────────────────────────────────────────────────────────

    try:

        start_platform()

    except Exception as e:

        print(f"[ERROR] Platform initialisation failed: {e}")
        raise

    # ─────────────────────────────────────────────────────────
    # 10. Runtime monitor
    # ─────────────────────────────────────────────────────────

    monitor_thread = threading.Thread(
        target=runtime_monitor,
        args=(capture_thread, detection_thread),
        daemon=True,
        name="RuntimeMonitor",
    )

    monitor_thread.start()

    # ─────────────────────────────────────────────────────────
    # 11. Ready
    # ─────────────────────────────────────────────────────────

    print_ready()

    # ─────────────────────────────────────────────────────────
    # 12. Flask / SocketIO
    # ─────────────────────────────────────────────────────────

    try:

        socketio.run(
            app,
            host="127.0.0.1",
            port=5000,
            debug=False,
            use_reloader=False,
        )

    except KeyboardInterrupt:

        print("\n[SHUTDOWN] SOC Platform stopping...")

    except Exception as e:

        print(f"\n[ERROR] Flask/SocketIO stopped: {e}")
        raise