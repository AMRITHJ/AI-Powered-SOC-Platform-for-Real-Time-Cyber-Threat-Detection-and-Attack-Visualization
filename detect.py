
# backend/detect.py
# ─────────────────────────────────────────────────────────────
# SOC PLATFORM — Detection Engine
#
# Rule-based:
#   - Port Scan
#   - Brute Force
#   - DDoS
#
# AI:
#   - Random Forest
#   - LSTM
#   - Isolation Forest
#
# Design goals:
#   - Rule detection is independent from ML.
#   - Port scans are detected from TCP SYN initiation packets.
#   - TCP SYN-ACK/server replies are never treated as scans.
#   - Multicast/broadcast traffic is ignored by attack rules.
#   - SSH/Telnet brute-force requires repeated connection attempts
#     plus client-side application payload activity.
#   - DDoS requires strong high-rate attack characteristics.
#   - Normal high-rate application traffic should not automatically
#     become DDoS.
#   - Broad multi-port bursts are treated as PORT_SCAN, not DDoS.
#   - Reverse traffic from the victim is not treated as DDoS.
#   - Heavy packet capture does not hold the detector lock.
#   - Existing callbacks/API are preserved.
#   - Confirmed PORT_SCAN events are enriched with genuine
#     RF / LSTM / Isolation Forest results (rule stays authoritative).
# ─────────────────────────────────────────────────────────────
 
import os
import sys
import time
import threading
import ipaddress
 
from datetime import datetime
 
 
# ============================================================
# PROJECT PATH
# ============================================================
 
BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)
 
if BASE_DIR not in sys.path:
    sys.path.insert(
        0,
        BASE_DIR
    )
 
 
# ============================================================
# CONFIG
# ============================================================
 
from backend.config import (
    PORT_SCAN_THRESHOLD,
    BRUTE_FORCE_THRESHOLD,
    DDOS_PPS_THRESHOLD,
    TIME_WINDOW,
    ATTACK_TTP_MAP,
    MITIGATIONS,
)
 
 
# ============================================================
# CAPTURE STATE
# ============================================================
 
from backend.capture import (
    packet_log,
    packet_lock,
    src_port_hits,
    src_pkt_times,
    src_ssh_times,
    src_tel_times,
    tracking_lock,
)
 
 
# ============================================================
# FLOW ENGINE
# ============================================================
 
from backend.network.flow_generator import (
    get_flow_snapshot,
)
 
 
# ============================================================
# TOPOLOGY
# ============================================================
 
from backend.network.topology import (
    register_attack,
)
 
 
# ============================================================
# AI CLASSIFIERS
# ============================================================
 
from backend.classifier import (
    classify_flow,
    is_ready,
    iso_ready,
)
 
from backend.ai.lstm_classifier import (
    is_ready as lstm_ready,
)
 
 
# ============================================================
# DETECTION CALLBACK
# ============================================================
 
# run.py / app.py connects:
#
#     detect.on_detection = handle_detection
#
# Every generated event is passed to this callback.
 
on_detection = None
 
 
# ============================================================
# KNOWN SOC HOSTS
# ============================================================
 
EXPECTED_ATTACKERS = {
    "192.168.56.10",
}
 
EXPECTED_TARGETS = {
    "192.168.56.30",
}
 
 
# ============================================================
# ATTACKER / VICTIM RELATIONSHIPS
# ============================================================
 
def _is_known_attacker(ip):
    return str(ip) in EXPECTED_ATTACKERS
 
 
def _is_known_target(ip):
    return str(ip) in EXPECTED_TARGETS
 
 
def _is_known_attack_pair(src, dst):
    return (
        _is_known_attacker(src)
        and
        _is_known_target(dst)
    )
 
 
# ============================================================
# ALERT DEDUPLICATION
# ============================================================
 
_last_alerted = {}
 
_alert_lock = threading.Lock()
 
 
def _should_alert(
    src,
    attack_type,
    cooldown=10,
):
    """
    Prevent repeated alert spam for the same source/attack.
 
    Example:
 
        PORT_SCAN:192.168.56.10
 
    will normally be emitted once every cooldown seconds.
    """
 
    key = (
        str(src),
        str(attack_type),
    )
 
    now = time.time()
 
    with _alert_lock:
 
        last = _last_alerted.get(
            key,
            0.0,
        )
 
        if (
            now - last
            < cooldown
        ):
            return False
 
        _last_alerted[key] = now
 
        return True
 
 
def cleanup_alert_history(
    max_age=300,
):
    """
    Remove expired alert cooldown records.
    """
 
    now = time.time()
 
    with _alert_lock:
 
        expired = [
 
            key
 
            for key, timestamp
            in _last_alerted.items()
 
            if (
                now - timestamp
                > max_age
            )
        ]
 
        for key in expired:
 
            del _last_alerted[
                key
            ]
 
 
# ============================================================
# ML PROCESSING CONTROL
# ============================================================
 
_ml_processed = {}
 
_ml_lock = threading.Lock()
 
ML_RECHECK_INTERVAL = 5.0
 
MAX_ML_FLOWS_PER_CYCLE = 5
 
 
def _should_process_ml(
    flow_key,
):
    """
    Prevent identical flows from being sent through the ML
    pipeline on every detection cycle.
    """
 
    now = time.time()
 
    key = str(
        flow_key
    )
 
    with _ml_lock:
 
        last = _ml_processed.get(
            key,
            0.0,
        )
 
        if (
            now - last
            < ML_RECHECK_INTERVAL
        ):
            return False
 
        _ml_processed[key] = now
 
        return True
 
 
def cleanup_ml_history(
    max_age=300,
):
    """
    Remove stale ML processing records.
    """
 
    now = time.time()
 
    with _ml_lock:
 
        expired = [
 
            key
 
            for key, timestamp
            in _ml_processed.items()
 
            if (
                now - timestamp
                > max_age
            )
        ]
 
        for key in expired:
 
            del _ml_processed[
                key
            ]
 
 
# ============================================================
# SAFE CONVERSION
# ============================================================
 
def _safe_float(
    value,
    default=0.0,
):
    try:
 
        number = float(
            value
        )
 
        if number != number:
            return default
 
        return number
 
    except Exception:
 
        return default
 
 
def _safe_int(
    value,
    default=0,
):
    try:
 
        return int(
            value
        )
 
    except Exception:
 
        return default
 
 
# ============================================================
# IP HELPERS
# ============================================================
 
def _is_ignored_destination(
    ip,
):
    """
    Ignore multicast/broadcast/unspecified destinations for
    attack detection.
    """
 
    if not ip:
        return True
 
    try:
 
        address = ipaddress.ip_address(
            str(ip)
        )
 
        if address.is_multicast:
            return True
 
        if address.is_unspecified:
            return True
 
        if address.is_loopback:
            return True
 
        if address.is_broadcast:
            return True
 
    except Exception:
 
        return False
 
    return False
 
 
# ============================================================
# PACKET SNAPSHOT
# ============================================================
 
def _get_recent_packet_snapshot():
    """
    Copy the rolling packet buffer quickly.
 
    The copy operation is protected by packet_lock but all
    expensive analysis happens after the lock is released.
    """
 
    try:
 
        with packet_lock:
 
            return list(
                packet_log
            )
 
    except Exception as e:
 
        print(
            f"[DETECT] Packet snapshot error: {e}"
        )
 
        return []
 
 
def _recent_packets(
    packets,
):
    """
    Return packets inside the configured detection window.
    """
 
    if not packets:
        return []
 
    now = time.time()
 
    cutoff = (
        now
        -
        max(
            TIME_WINDOW,
            1,
        )
    )
 
    result = []
 
    for packet in packets:
 
        ts = _safe_float(
            packet.get(
                "ts_epoch",
                0,
            )
        )
 
        if ts >= cutoff:
 
            result.append(
                packet
            )
 
    return result
 
 
# ============================================================
# EVENT BUILDER
# ============================================================
 
def _make_event(
    src_ip,
    attack_type,
    severity,
    details=None,
    clf_result=None,
    dst_ip=None,
):
    """
    Create the standard SOC event.
    """
 
    ttp = ATTACK_TTP_MAP.get(
        attack_type,
        {},
    )
 
    mitigations = MITIGATIONS.get(
        attack_type,
        [],
    )
 
    clf = (
        clf_result
        if isinstance(
            clf_result,
            dict,
        )
        else {}
    )
 
    return {
 
        "id":
            f"EVT-{int(time.time() * 1000)}",
 
        "timestamp":
            datetime.utcnow().isoformat(),
 
        "src_ip":
            src_ip,
 
        "dst_ip":
            dst_ip or "unknown",
 
        "attack_type":
            attack_type,
 
        "severity":
            severity,
 
        "details":
            details or {},
 
        "mitigations":
            mitigations,
 
        "ttp":
            ttp,
 
        # ----------------------------------------------------
        # Random Forest
        # ----------------------------------------------------
 
        "ml_label":
            clf.get(
                "ml_label"
            ),
 
        "ml_conf":
            clf.get(
                "ml_conf"
            ),
 
        "ml_conf_pct":
            clf.get(
                "ml_conf_pct"
            ),
 
        "class_probs":
            clf.get(
                "class_probs",
                {},
            ),
 
        # ----------------------------------------------------
        # LSTM
        # ----------------------------------------------------
 
        "lstm_label":
            clf.get(
                "lstm_label"
            ),
 
        "lstm_conf":
            clf.get(
                "lstm_conf"
            ),
 
        "lstm_conf_pct":
            clf.get(
                "lstm_conf_pct"
            ),
 
        "lstm_severity":
            clf.get(
                "lstm_severity"
            ),
 
        # ----------------------------------------------------
        # Isolation Forest
        # ----------------------------------------------------
 
        "iso_anomaly":
            clf.get(
                "iso_anomaly"
            ),
 
        "iso_score":
            clf.get(
                "iso_score"
            ),
 
        # ----------------------------------------------------
        # Combined
        # ----------------------------------------------------
 
        "combined":
            clf.get(
                "combined"
            ),
 
        "combined_conf":
            clf.get(
                "combined_conf"
            ),
 
        "models_used":
            clf.get(
                "models_used",
                "RULE",
            ),
 
        # ----------------------------------------------------
        # CTI
        # ----------------------------------------------------
 
        "cti_score":
            None,
 
        "cti_label":
            None,
 
        "cti_details":
            {},
    }
 
 
# ============================================================
# DESTINATION LOOKUP
# ============================================================
 
def _find_destination(
    src_ip,
    preferred_port=None,
):
    """
    Find a useful destination IP associated with the source.
 
    Used only as informational fallback.
    """
 
    try:
 
        snapshot = get_flow_snapshot()
 
        fallback = None
 
        for _, flow in snapshot.items():
 
            if (
                flow.get(
                    "src_ip"
                )
                != src_ip
            ):
                continue
 
            destination = flow.get(
                "dst_ip"
            )
 
            if not destination:
                continue
 
            if _is_ignored_destination(
                destination
            ):
                continue
 
            fallback = destination
 
            if preferred_port is not None:
 
                port = _safe_int(
                    flow.get(
                        "dst_port",
                        0,
                    )
                )
 
                if (
                    port
                    ==
                    _safe_int(
                        preferred_port
                    )
                ):
 
                    return destination
 
        if fallback:
 
            return fallback
 
    except Exception as e:
 
        print(
            f"[DETECT] Destination lookup error: {e}"
        )
 
    return "unknown"
 
 
# ============================================================
# RULE 1 — PRECISE TCP PORT SCAN
# ============================================================
 
def _build_port_scan_state():
    """
    Build port-scan state directly from captured packets.
 
    Only initial TCP SYN packets count:
 
        SYN = 1
        ACK = 0
 
    Therefore a SYN-ACK response from Ubuntu does not count
    as scan activity.
    """
 
    packets = _get_recent_packet_snapshot()
 
    packets = _recent_packets(
        packets
    )
 
    scans = {}
 
    for packet in packets:
 
        if not packet.get(
            "is_lab_traffic",
            False,
        ):
            continue
 
        if (
            str(
                packet.get(
                    "protocol",
                    ""
                )
            ).upper()
            !=
            "TCP"
        ):
            continue
 
        src = packet.get(
            "src_ip"
        )
 
        dst = packet.get(
            "dst_ip"
        )
 
        if not src or not dst:
            continue
 
        if _is_ignored_destination(
            dst
        ):
            continue
 
        dst_port = _safe_int(
            packet.get(
                "dst_port",
                0,
            )
        )
 
        src_port = _safe_int(
            packet.get(
                "src_port",
                0,
            )
        )
 
        if dst_port <= 0:
            continue
 
        flags = _safe_int(
            packet.get(
                "tcp_flags",
                0,
            )
        )
 
        syn = bool(
            flags & 0x02
        )
 
        ack = bool(
            flags & 0x10
        )
 
        if not syn:
            continue
 
        if ack:
            continue
 
        key = (
            src,
            dst,
        )
 
        if key not in scans:
 
            scans[key] = {
 
                "ports":
                    set(),
 
                "timestamps":
                    [],
 
                "attempts":
                    0,
 
                "source_ports":
                    set(),
 
            }
 
        scans[key][
            "ports"
        ].add(
            dst_port
        )
 
        scans[key][
            "timestamps"
        ].append(
            _safe_float(
                packet.get(
                    "ts_epoch",
                    time.time(),
                )
            )
        )
 
        scans[key][
            "attempts"
        ] += 1
 
        if src_port > 0:
 
            scans[key][
                "source_ports"
            ].add(
                src_port
            )
 
    return scans
 
 
# ============================================================
# ML ENRICHMENT FOR A CONFIRMED RULE DETECTION
# ============================================================
 
def _get_ml_result_for_pair(
    src,
    dst,
):
    """
    Run the existing classifier on the most recent flow that
    matches the detected src -> dst pair.
 
    Used to enrich a rule-based event (e.g. PORT_SCAN) with
    genuine RF / LSTM / Isolation Forest output.
 
    Returns {} safely if ML is not ready, no matching flow
    exists, or classification fails. The rule-based detection
    always remains authoritative.
    """
 
    try:
 
        if not (
            is_ready()
            or
            iso_ready()
            or
            lstm_ready()
        ):
 
            return {}
 
        snapshot = get_flow_snapshot()
 
        if not snapshot:
 
            return {}
 
        best_flow = None
 
        best_ts = -1.0
 
        for _, flow in snapshot.items():
 
            if (
                flow.get(
                    "src_ip"
                )
                != src
            ):
                continue
 
            if (
                flow.get(
                    "dst_ip"
                )
                != dst
            ):
                continue
 
            flow_ts = _safe_float(
                flow.get(
                    "flow_start_ts",
                    0,
                )
            )
 
            if (
                best_flow is None
                or
                flow_ts > best_ts
            ):
 
                best_flow = flow
 
                best_ts = flow_ts
 
        if best_flow is None:
 
            return {}
 
        result = classify_flow(
            best_flow,
            src,
        )
 
        if isinstance(
            result,
            dict,
        ):
 
            return result
 
    except Exception as e:
 
        print(
            f"[DETECT] ML enrichment error "
            f"for {src} -> {dst}: {e}"
        )
 
    return {}
 
 
def check_port_scan():
 
    events = []
 
    scan_state = (
        _build_port_scan_state()
    )
 
    for (
        (src, dst),
        state,
    ) in scan_state.items():
 
        ports = state.get(
            "ports",
            set(),
        )
 
        unique_ports = len(
            ports
        )
 
        if unique_ports <= 0:
            continue
 
        print(
            f"[PORT-SCAN CHECK] "
            f"src={src} "
            f"dst={dst} "
            f"unique_ports={unique_ports} "
            f"threshold={PORT_SCAN_THRESHOLD} "
            f"ports={sorted(list(ports))[:20]}"
        )
 
        if (
            unique_ports
            <
            PORT_SCAN_THRESHOLD
        ):
            continue
 
        print(
            f"[ALERT-TRIGGER] "
            f"PORT_SCAN threshold reached "
            f"for {src} -> {dst}: "
            f"{unique_ports} unique ports"
        )
 
        alert_key = (
            f"PORT_SCAN:{dst}"
        )
 
        if not _should_alert(
            src,
            alert_key,
            cooldown=10,
        ):
            continue
 
        sample_ports = sorted(
            list(ports)
        )[:20]
 
        source_port_count = len(
            state.get(
                "source_ports",
                set(),
            )
        )
 
        ml_result = _get_ml_result_for_pair(
            src,
            dst,
        )
 
        event = _make_event(
 
            src_ip=src,
 
            dst_ip=dst,
 
            attack_type="PORT_SCAN",
 
            severity="HIGH",
 
            details={
 
                "unique_ports_scanned":
                    unique_ports,
 
                "sample_ports":
                    sample_ports,
 
                "scan_attempts":
                    state.get(
                        "attempts",
                        0,
                    ),
 
                "unique_source_ports":
                    source_port_count,
 
                "detection_method": (
                    "Rule-Based TCP SYN Scan + ML Enrichment"
                    if ml_result
                    else "Rule-Based TCP SYN Scan"
                ),
 
            },
 
            clf_result=ml_result,
        )
 
        events.append(
            event
        )
 
        try:
 
            register_attack(
                src,
                dst,
                "PORT_SCAN",
                "HIGH",
            )
 
        except Exception as e:
 
            print(
                f"[DETECT] Topology error: {e}"
            )
 
        with tracking_lock:
 
            if src in src_port_hits:
 
                src_port_hits[
                    src
                ].clear()
 
    return events
 
 
# ============================================================
# BRUTE FORCE STATE
# ============================================================
 
def _build_bruteforce_state(
    destination_port,
):
    """
    Build SSH/Telnet connection state directly from packets.
 
    We track:
        - initial SYN attempts
        - client source ports
        - client application payload packets
    """
 
    packets = _get_recent_packet_snapshot()
 
    packets = _recent_packets(
        packets
    )
 
    state = {}
 
    for packet in packets:
 
        if not packet.get(
            "is_lab_traffic",
            False,
        ):
            continue
 
        if str(
            packet.get(
                "protocol",
                ""
            )
        ).upper() != "TCP":
 
            continue
 
        src = packet.get(
            "src_ip"
        )
 
        dst = packet.get(
            "dst_ip"
        )
 
        if not src or not dst:
            continue
 
        if _is_ignored_destination(
            dst
        ):
            continue
 
        dst_port = _safe_int(
            packet.get(
                "dst_port",
                0,
            )
        )
 
        if (
            dst_port
            !=
            destination_port
        ):
            continue
 
        src_port = _safe_int(
            packet.get(
                "src_port",
                0,
            )
        )
 
        flags = _safe_int(
            packet.get(
                "tcp_flags",
                0,
            )
        )
 
        size = _safe_int(
            packet.get(
                "size",
                0,
            )
        )
 
        key = (
            src,
            dst,
        )
 
        if key not in state:
 
            state[key] = {
 
                "syn_attempts":
                    0,
 
                "payload_packets":
                    0,
 
                "source_ports":
                    set(),
 
                "timestamps":
                    [],
 
            }
 
        entry = state[key]
 
        ts = _safe_float(
            packet.get(
                "ts_epoch",
                time.time(),
            )
        )
 
        entry[
            "timestamps"
        ].append(
            ts
        )
 
        syn = bool(
            flags & 0x02
        )
 
        ack = bool(
            flags & 0x10
        )
 
        if syn and not ack:
 
            entry[
                "syn_attempts"
            ] += 1
 
            if src_port > 0:
 
                entry[
                    "source_ports"
                ].add(
                    src_port
                )
 
        psh = bool(
            flags & 0x08
        )
 
        if (
            psh
            and
            size > 60
        ):
 
            entry[
                "payload_packets"
            ] += 1
 
    return state
 
 
# ============================================================
# RULE 2 — BRUTE FORCE
# ============================================================
 
def check_brute_force():
 
    events = []
 
    # ========================================================
    # SSH
    # ========================================================
 
    ssh_state = _build_bruteforce_state(
        22
    )
 
    for (
        (src, dst),
        state,
    ) in ssh_state.items():
 
        attempts = _safe_int(
            state.get(
                "syn_attempts",
                0,
            )
        )
 
        payload_packets = _safe_int(
            state.get(
                "payload_packets",
                0,
            )
        )
 
        source_ports = len(
            state.get(
                "source_ports",
                set(),
            )
        )
 
        print(
            f"[SSH CHECK] "
            f"src={src} "
            f"dst={dst} "
            f"attempts={attempts} "
            f"payload_packets={payload_packets} "
            f"threshold={BRUTE_FORCE_THRESHOLD}"
        )
 
        if (
            attempts
            <
            max(
                BRUTE_FORCE_THRESHOLD,
                3,
            )
        ):
            continue
 
        if payload_packets <= 0:
            continue
 
        print(
            f"[ALERT-TRIGGER] "
            f"SSH BRUTE_FORCE threshold reached "
            f"for {src} -> {dst}: "
            f"{attempts} attempts, "
            f"{payload_packets} payload packets"
        )
 
        alert_key = (
            f"BF_SSH:{dst}"
        )
 
        if not _should_alert(
            src,
            alert_key,
            cooldown=10,
        ):
            continue
 
        rate = (
            attempts
            /
            max(
                TIME_WINDOW,
                1,
            )
        )
 
        event = _make_event(
 
            src_ip=src,
 
            dst_ip=dst,
 
            attack_type="BRUTE_FORCE",
 
            severity="HIGH",
 
            details={
 
                "service":
                    "SSH",
 
                "target_port":
                    22,
 
                "attempt_count":
                    attempts,
 
                "payload_packets":
                    payload_packets,
 
                "unique_source_ports":
                    source_ports,
 
                "rate_per_sec":
                    round(
                        rate,
                        1,
                    ),
 
                "detection_method":
                    "Rule-Based SSH Connection + Application Activity",
 
            },
        )
 
        events.append(
            event
        )
 
        try:
 
            register_attack(
                src,
                dst,
                "BRUTE_FORCE",
                "HIGH",
            )
 
        except Exception as e:
 
            print(
                f"[DETECT] Topology error: {e}"
            )
 
    # ========================================================
    # TELNET
    # ========================================================
 
    telnet_state = _build_bruteforce_state(
        23
    )
 
    for (
        (src, dst),
        state,
    ) in telnet_state.items():
 
        attempts = _safe_int(
            state.get(
                "syn_attempts",
                0,
            )
        )
 
        payload_packets = _safe_int(
            state.get(
                "payload_packets",
                0,
            )
        )
 
        source_ports = len(
            state.get(
                "source_ports",
                set(),
            )
        )
 
        if (
            attempts
            <
            max(
                BRUTE_FORCE_THRESHOLD,
                3,
            )
        ):
            continue
 
        if payload_packets <= 0:
            continue
 
        print(
            f"[ALERT-TRIGGER] "
            f"TELNET BRUTE_FORCE threshold reached "
            f"for {src} -> {dst}: "
            f"{attempts} attempts, "
            f"{payload_packets} payload packets"
        )
 
        alert_key = (
            f"BF_TEL:{dst}"
        )
 
        if not _should_alert(
            src,
            alert_key,
            cooldown=10,
        ):
            continue
 
        rate = (
            attempts
            /
            max(
                TIME_WINDOW,
                1,
            )
        )
 
        event = _make_event(
 
            src_ip=src,
 
            dst_ip=dst,
 
            attack_type="BRUTE_FORCE",
 
            severity="MEDIUM",
 
            details={
 
                "service":
                    "Telnet",
 
                "target_port":
                    23,
 
                "attempt_count":
                    attempts,
 
                "payload_packets":
                    payload_packets,
 
                "unique_source_ports":
                    source_ports,
 
                "rate_per_sec":
                    round(
                        rate,
                        1,
                    ),
 
                "detection_method":
                    "Rule-Based Telnet Connection + Application Activity",
 
            },
        )
 
        events.append(
            event
        )
 
        try:
 
            register_attack(
                src,
                dst,
                "BRUTE_FORCE",
                "MEDIUM",
            )
 
        except Exception as e:
 
            print(
                f"[DETECT] Topology error: {e}"
            )
 
    return events
 
 
# ============================================================
# RULE 3 — DDoS
# ============================================================
 
def check_ddos():
    """
    Detect strong DDoS/flood signatures.
 
    IMPORTANT:
 
    A high packet rate alone is NOT sufficient.
 
    TCP:
        - Must be strongly SYN-oriented.
        - SYN ratio must be high.
        - There must be enough SYN packets.
        - Normal ACK/PSH-heavy application traffic is ignored.
 
    UDP:
        - Requires a substantially higher PPS than the basic
          configured threshold.
        - Requires enough packets in the observation window.
        - Traffic must remain concentrated on one destination
          port.
 
    Additional protections:
        - reverse victim traffic is ignored
        - multicast/broadcast traffic is ignored
        - broad multi-port bursts are ignored
        - port scans remain PORT_SCAN
        - alerts are deduplicated
    """
 
    events = []
 
    # ========================================================
    # CURRENT PACKETS
    # ========================================================
 
    packets = _get_recent_packet_snapshot()
 
    packets = _recent_packets(
        packets
    )
 
    if not packets:
 
        return events
 
    # ========================================================
    # INTERNAL DDoS VALIDATION
    #
    # These deliberately make the DDoS rule stricter than the
    # basic configured PPS threshold.
    # ========================================================
 
    tcp_min_syn_packets = max(
        50,
        int(
            DDOS_PPS_THRESHOLD
            *
            max(
                TIME_WINDOW,
                1,
            )
            *
            0.50
        ),
    )
 
    tcp_min_syn_ratio = 0.70
 
    udp_min_pps = max(
        DDOS_PPS_THRESHOLD * 3.0,
        150.0,
    )
 
    udp_min_packets = max(
        100,
        int(
            udp_min_pps
            *
            max(
                TIME_WINDOW,
                1,
            )
            *
            0.50
        ),
    )
 
    # ========================================================
    # GROUP PACKETS
    #
    # source -> destination -> destination port -> protocol
    # ========================================================
 
    groups = {}
 
    for packet in packets:
 
        if not packet.get(
            "is_lab_traffic",
            False,
        ):
            continue
 
        src = packet.get(
            "src_ip"
        )
 
        dst = packet.get(
            "dst_ip"
        )
 
        protocol = str(
            packet.get(
                "protocol",
                ""
            )
        ).upper()
 
        if not src or not dst:
            continue
 
        if _is_ignored_destination(
            dst
        ):
            continue
 
        if protocol not in (
            "TCP",
            "UDP",
        ):
            continue
 
        src_port = _safe_int(
            packet.get(
                "src_port",
                0,
            )
        )
 
        dst_port = _safe_int(
            packet.get(
                "dst_port",
                0,
            )
        )
 
        if dst_port <= 0:
            continue
 
        timestamp = _safe_float(
            packet.get(
                "ts_epoch",
                0,
            )
        )
 
        size = _safe_int(
            packet.get(
                "size",
                0,
            )
        )
 
        flags = _safe_int(
            packet.get(
                "tcp_flags",
                0,
            )
        )
 
        key = (
            src,
            dst,
            dst_port,
            protocol,
        )
 
        if key not in groups:
 
            groups[key] = {
 
                "timestamps":
                    [],
 
                "packet_count":
                    0,
 
                "bytes":
                    0,
 
                "syn_packets":
                    0,
 
                "syn_ack_packets":
                    0,
 
                "ack_packets":
                    0,
 
                "payload_packets":
                    0,
 
                "source_ports":
                    set(),
 
                "small_packets":
                    0,
 
                "large_packets":
                    0,
 
            }
 
        group = groups[key]
 
        group[
            "timestamps"
        ].append(
            timestamp
        )
 
        group[
            "packet_count"
        ] += 1
 
        group[
            "bytes"
        ] += size
 
        if src_port > 0:
 
            group[
                "source_ports"
            ].add(
                src_port
            )
 
        # Packet size profile
 
        if size <= 80:
 
            group[
                "small_packets"
            ] += 1
 
        else:
 
            group[
                "large_packets"
            ] += 1
 
        # ====================================================
        # TCP FLAG ANALYSIS
        # ====================================================
 
        if protocol == "TCP":
 
            syn = bool(
                flags & 0x02
            )
 
            ack = bool(
                flags & 0x10
            )
 
            psh = bool(
                flags & 0x08
            )
 
            # Initial SYN
 
            if syn and not ack:
 
                group[
                    "syn_packets"
                ] += 1
 
            # SYN-ACK response
 
            elif syn and ack:
 
                group[
                    "syn_ack_packets"
                ] += 1
 
            # ACK traffic
 
            elif ack:
 
                group[
                    "ack_packets"
                ] += 1
 
            # Application payload
 
            if (
                psh
                and
                size > 60
            ):
 
                group[
                    "payload_packets"
                ] += 1
 
    # ========================================================
    # EVALUATE EACH CONVERSATION
    # ========================================================
 
    for (
        (
            src,
            dst,
            dst_port,
            protocol,
        ),
        group,
    ) in groups.items():
 
        packet_count = group[
            "packet_count"
        ]
 
        timestamps = group[
            "timestamps"
        ]
 
        if packet_count < 20:
            continue
 
        if len(timestamps) < 2:
            continue
 
        first_ts = min(
            timestamps
        )
 
        last_ts = max(
            timestamps
        )
 
        elapsed = (
            last_ts
            -
            first_ts
        )
 
        if elapsed <= 0:
 
            elapsed = 0.001
 
        pps = (
            packet_count
            /
            elapsed
        )
 
        # ====================================================
        # VICTIM RESPONSE PROTECTION
        # ====================================================
 
        if (
            _is_known_target(src)
            and
            _is_known_attacker(dst)
        ):
 
            continue
 
        # ====================================================
        # DESTINATION PORT CONCENTRATION
        # ====================================================
 
        pair_ports = set()
 
        for packet in packets:
 
            if (
                packet.get(
                    "src_ip"
                )
                !=
                src
            ):
                continue
 
            if (
                packet.get(
                    "dst_ip"
                )
                !=
                dst
            ):
                continue
 
            port = _safe_int(
                packet.get(
                    "dst_port",
                    0,
                )
            )
 
            if port > 0:
 
                pair_ports.add(
                    port
                )
 
        unique_destination_ports = len(
            pair_ports
        )
 
        # ====================================================
        # PORT SCAN PROTECTION
        # ====================================================
 
        if (
            unique_destination_ports
            >=
            PORT_SCAN_THRESHOLD
        ):
 
            continue
 
        # ====================================================
        # GLOBAL RATE CHECK
        # ====================================================
 
        if (
            pps
            <
            DDOS_PPS_THRESHOLD
        ):
 
            continue
 
        syn_packets = group[
            "syn_packets"
        ]
 
        syn_ack_packets = group[
            "syn_ack_packets"
        ]
 
        ack_packets = group[
            "ack_packets"
        ]
 
        payload_packets = group[
            "payload_packets"
        ]
 
        source_port_count = len(
            group.get(
                "source_ports",
                set(),
            )
        )
 
        syn_ratio = (
            syn_packets
            /
            max(
                packet_count,
                1,
            )
        )
 
        ack_ratio = (
            ack_packets
            /
            max(
                packet_count,
                1,
            )
        )
 
        payload_ratio = (
            payload_packets
            /
            max(
                packet_count,
                1,
            )
        )
 
        # ====================================================
        # TCP FLOOD VALIDATION
        # ====================================================
 
        if protocol == "TCP":
 
            # ------------------------------------------------
            # STRICT SYN FLOOD TEST
            # ------------------------------------------------
            #
            # Normal enterprise traffic generally contains a
            # significant amount of ACK/application traffic.
            #
            # A SYN flood should be heavily SYN-oriented.
            # ------------------------------------------------
 
            if (
                syn_packets
                <
                tcp_min_syn_packets
            ):
 
                print(
                    f"[DDOS FILTER] "
                    f"TCP rejected "
                    f"{src} -> {dst}:{dst_port} "
                    f"| PPS={pps:.1f} "
                    f"| SYN={syn_packets} "
                    f"| ACK={ack_packets} "
                    f"| payload={payload_packets}"
                )
 
                continue
 
            if (
                syn_ratio
                <
                tcp_min_syn_ratio
            ):
 
                print(
                    f"[DDOS FILTER] "
                    f"TCP rejected "
                    f"{src} -> {dst}:{dst_port} "
                    f"| SYN_RATIO={syn_ratio:.3f} "
                    f"| threshold={tcp_min_syn_ratio:.3f}"
                )
 
                continue
 
            # ------------------------------------------------
            # ACK RESPONSE PROTECTION
            #
            # If the traffic contains a large amount of ACK
            # traffic relative to SYN traffic, it is more likely
            # to be established application traffic.
            # ------------------------------------------------
 
            if (
                ack_packets
                >
                syn_packets
                *
                0.75
            ):
 
                print(
                    f"[DDOS FILTER] "
                    f"TCP rejected due to ACK activity "
                    f"{src} -> {dst}:{dst_port} "
                    f"| SYN={syn_packets} "
                    f"| ACK={ack_packets}"
                )
 
                continue
 
            # ------------------------------------------------
            # APPLICATION PAYLOAD PROTECTION
            #
            # Heavy HTTP/HTTPS application traffic normally
            # contains PSH/application packets.
            #
            # A strong payload ratio reduces confidence that
            # this is a raw SYN flood.
            # ------------------------------------------------
 
            if (
                payload_packets
                >
                packet_count
                *
                0.35
                and
                syn_ratio
                <
                0.85
            ):
 
                print(
                    f"[DDOS FILTER] "
                    f"TCP rejected due to application payload "
                    f"{src} -> {dst}:{dst_port} "
                    f"| SYN_RATIO={syn_ratio:.3f} "
                    f"| PAYLOAD_RATIO={payload_ratio:.3f}"
                )
 
                continue
 
        # ====================================================
        # UDP FLOOD VALIDATION
        # ====================================================
 
        elif protocol == "UDP":
 
            # ------------------------------------------------
            # UDP needs a much stronger rate than the base
            # threshold because ordinary DNS/application traffic
            # can legitimately exceed 50 PPS.
            # ------------------------------------------------
 
            if (
                pps
                <
                udp_min_pps
            ):
 
                print(
                    f"[DDOS FILTER] "
                    f"UDP rejected "
                    f"{src} -> {dst}:{dst_port} "
                    f"| PPS={pps:.1f} "
                    f"| required={udp_min_pps:.1f}"
                )
 
                continue
 
            if (
                packet_count
                <
                udp_min_packets
            ):
 
                print(
                    f"[DDOS FILTER] "
                    f"UDP rejected due to insufficient volume "
                    f"{src} -> {dst}:{dst_port} "
                    f"| packets={packet_count} "
                    f"| required={udp_min_packets}"
                )
 
                continue
 
        # ====================================================
        # FINAL ATTACK VALIDATION
        # ====================================================
 
        print(
            f"[DDOS VALIDATED] "
            f"{src} -> {dst}:{dst_port} "
            f"| {protocol} "
            f"| PPS={pps:.1f} "
            f"| packets={packet_count} "
            f"| SYN={syn_packets} "
            f"| SYN_RATIO={syn_ratio:.3f} "
            f"| ACK={ack_packets} "
            f"| PAYLOAD={payload_packets} "
            f"| ports={unique_destination_ports}"
        )
 
        # ====================================================
        # ALERT
        # ====================================================
 
        alert_key = (
            f"DDOS:"
            f"{dst}:"
            f"{dst_port}:"
            f"{protocol}"
        )
 
        if not _should_alert(
            src,
            alert_key,
            cooldown=20,
        ):
 
            continue
 
        duration_ms = max(
            int(
                elapsed
                *
                1000
            ),
            1,
        )
 
        event = _make_event(
 
            src_ip=src,
 
            dst_ip=dst,
 
            attack_type="DDOS",
 
            severity="CRITICAL",
 
            details={
 
                "packets_per_second":
                    round(
                        pps,
                        1,
                    ),
 
                "threshold":
                    DDOS_PPS_THRESHOLD,
 
                "validated_tcp_threshold":
                    tcp_min_syn_packets
                    if protocol == "TCP"
                    else None,
 
                "validated_tcp_syn_ratio":
                    tcp_min_syn_ratio
                    if protocol == "TCP"
                    else None,
 
                "validated_udp_pps":
                    udp_min_pps
                    if protocol == "UDP"
                    else None,
 
                "packet_count":
                    packet_count,
 
                "destination_port":
                    dst_port,
 
                "protocol":
                    protocol,
 
                "unique_destination_ports":
                    unique_destination_ports,
 
                "syn_packets":
                    syn_packets,
 
                "syn_ratio":
                    round(
                        syn_ratio,
                        3,
                    ),
 
                "syn_ack_packets":
                    syn_ack_packets,
 
                "ack_packets":
                    ack_packets,
 
                "ack_ratio":
                    round(
                        ack_ratio,
                        3,
                    ),
 
                "payload_packets":
                    payload_packets,
 
                "payload_ratio":
                    round(
                        payload_ratio,
                        3,
                    ),
 
                "unique_source_ports":
                    source_port_count,
 
                "duration_ms":
                    duration_ms,
 
                "detection_method":
                    "Rule-Based Flood Detection + TCP SYN/UDP Validation",
 
            },
        )
 
        events.append(
            event
        )
 
        try:
 
            register_attack(
                src,
                dst,
                "DDOS",
                "CRITICAL",
            )
 
        except Exception as e:
 
            print(
                f"[DETECT] Topology error: {e}"
            )
 
    return events
 
 
# ============================================================
# ACTIVE PORT SCAN CHECK
# ============================================================
 
def _source_has_active_port_scan(
    src,
    dst=None,
):
    """
    Return True if the current recent packet set already
    contains an active port scan from the source.
 
    This prevents ML from creating a second competing event for
    the same obvious scan.
    """
 
    try:
 
        scan_state = (
            _build_port_scan_state()
        )
 
        for (
            (
                scan_src,
                scan_dst,
            ),
            info,
        ) in scan_state.items():
 
            if scan_src != src:
                continue
 
            if (
                dst is not None
                and
                scan_dst != dst
            ):
                continue
 
            if len(
                info.get(
                    "ports",
                    set()
                )
            ) >= PORT_SCAN_THRESHOLD:
 
                return True
 
    except Exception:
        pass
 
    return False
 
 
# ============================================================
# RULE + ML CONFLICT PROTECTION
# ============================================================
 
def _normalise_attack_label(
    label,
):
    """
    Normalize classifier labels.
    """
 
    if label is None:
 
        return ""
 
    return str(
        label
    ).strip().upper()
 
 
def _is_benign_label(
    label,
):
    return (
        _normalise_attack_label(label)
        in
        {
            "",
            "BENIGN",
            "NORMAL",
            "SAFE",
            "UNKNOWN",
            "NONE",
            "N/A",
            "ERROR",
        }
    )
 
 
def _is_generic_ml_label(
    label,
):
    return (
        _normalise_attack_label(label)
        in
        {
            "",
            "OTHER",
            "UNKNOWN",
            "NONE",
            "N/A",
            "ERROR",
            "SUSPICIOUS",
        }
    )
 
 
# ============================================================
# RULE 4 — ML / LSTM / ISOLATION FOREST
# ============================================================
 
def check_ml_anomalies():
    """
    ML is an enhancement layer.
 
    Rule-based detections remain authoritative.
    """
 
    events = []
 
    if not (
        is_ready()
        or
        iso_ready()
        or
        lstm_ready()
    ):
 
        return events
 
    try:
 
        snapshot = get_flow_snapshot()
 
    except Exception as e:
 
        print(
            f"[DETECT] Flow snapshot error: {e}"
        )
 
        return events
 
    if not snapshot:
 
        return events
 
    flows = list(
        snapshot.items()
    )
 
    flows.sort(
        key=lambda item:
            item[1].get(
                "flow_start_ts",
                0,
            ),
        reverse=True,
    )
 
    processed = 0
 
    for (
        key,
        flow,
    ) in flows:
 
        if (
            processed
            >=
            MAX_ML_FLOWS_PER_CYCLE
        ):
 
            break
 
        if not _should_process_ml(
            key
        ):
 
            continue
 
        src = flow.get(
            "src_ip",
            "",
        )
 
        if not src:
            continue
 
        dst = flow.get(
            "dst_ip",
            "",
        )
 
        if _source_has_active_port_scan(
            src,
            dst,
        ):
 
            continue
 
        processed += 1
 
        try:
 
            clf = classify_flow(
                flow,
                src,
            )
 
        except Exception as e:
 
            print(
                f"[DETECT] ML error "
                f"for {src}: {e}"
            )
 
            continue
 
        if not isinstance(
            clf,
            dict,
        ):
 
            continue
 
        # ====================================================
        # RF
        # ====================================================
 
        rf_label = (
            clf.get(
                "ml_label"
            )
        )
 
        rf_label_normalized = (
            _normalise_attack_label(
                rf_label
            )
        )
 
        rf_attack = (
            not _is_benign_label(
                rf_label_normalized
            )
            and
            not _is_generic_ml_label(
                rf_label_normalized
            )
        )
 
        rf_conf = _safe_float(
            clf.get(
                "ml_conf",
                0,
            )
        )
 
        # ====================================================
        # LSTM
        # ====================================================
 
        lstm_label = (
            clf.get(
                "lstm_label"
            )
        )
 
        lstm_label_normalized = (
            _normalise_attack_label(
                lstm_label
            )
        )
 
        lstm_attack = (
            not _is_benign_label(
                lstm_label_normalized
            )
            and
            not _is_generic_ml_label(
                lstm_label_normalized
            )
        )
 
        lstm_conf = _safe_float(
            clf.get(
                "lstm_conf",
                0,
            )
        )
 
        # ====================================================
        # ISO
        # ====================================================
 
        iso_flag = bool(
            clf.get(
                "iso_anomaly",
                False,
            )
        )
 
        # ====================================================
        # DEBUG MODEL RESULT
        # ====================================================
 
        print(
            f"[ML CHECK] "
            f"src={src} "
            f"dst={dst} "
            f"RF={rf_label_normalized or 'N/A'} "
            f"RF_CONF={rf_conf:.3f} "
            f"LSTM={lstm_label_normalized or 'N/A'} "
            f"LSTM_CONF={lstm_conf:.3f} "
            f"ISO={iso_flag}"
        )
 
        # ====================================================
        # TRIGGER CONDITIONS
        # ====================================================
 
        triggered = (
 
            (
                rf_attack
                and
                rf_conf >= 0.65
            )
 
            or
 
            (
                lstm_attack
                and
                lstm_conf >= 0.70
                and
                iso_flag
            )
 
            or
 
            (
                rf_attack
                and
                lstm_attack
                and
                rf_conf >= 0.55
            )
 
            or
 
            (
                iso_flag
                and
                (
                    rf_attack
                    or
                    lstm_attack
                )
            )
        )
 
        if not triggered:
 
            continue
 
        # ====================================================
        # DETERMINE ATTACK TYPE
        # ====================================================
 
        combined_label = (
            clf.get(
                "combined"
            )
        )
 
        combined_normalized = (
            _normalise_attack_label(
                combined_label
            )
        )
 
        candidates = [
 
            (
                combined_normalized,
                _safe_float(
                    clf.get(
                        "combined_conf",
                        0,
                    )
                ),
            ),
 
            (
                rf_label_normalized,
                rf_conf,
            ),
 
            (
                lstm_label_normalized,
                lstm_conf,
            ),
        ]
 
        attack_type = ""
 
        for (
            label,
            confidence,
        ) in candidates:
 
            if not label:
                continue
 
            if _is_benign_label(
                label
            ):
                continue
 
            if _is_generic_ml_label(
                label
            ):
                continue
 
            attack_type = label
 
            break
 
        if not attack_type:
 
            if iso_flag:
 
                attack_type = (
                    "SUSPICIOUS"
                )
 
            else:
 
                attack_type = (
                    "OTHER"
                )
 
        # ====================================================
        # RULE PROTECTION
        # ====================================================
 
        if (
            attack_type
            in
            {
                "OTHER",
                "SUSPICIOUS",
            }
            and
            _source_has_active_port_scan(
                src,
                dst,
            )
        ):
 
            continue
 
        # ====================================================
        # DEDUPLICATION
        # ====================================================
 
        alert_key = (
            f"ML:"
            f"{attack_type}:"
            f"{dst}"
        )
 
        if not _should_alert(
            src,
            alert_key,
            cooldown=20,
        ):
 
            continue
 
        # ====================================================
        # SEVERITY
        # ====================================================
 
        severity = str(
            clf.get(
                "severity",
                "MEDIUM",
            )
        ).upper()
 
        if severity in (
            "",
            "UNKNOWN",
            "NONE",
        ):
 
            severity = "MEDIUM"
 
        # ====================================================
        # EVENT
        # ====================================================
 
        event = _make_event(
 
            src_ip=src,
 
            dst_ip=(
                dst or
                "unknown"
            ),
 
            attack_type=attack_type,
 
            severity=severity,
 
            details={
 
                "detection_method":
                    "ML + LSTM + Isolation Forest",
 
                "flow_key":
                    str(key),
 
                "rf_label":
                    rf_label,
 
                "rf_confidence":
                    clf.get(
                        "ml_conf_pct"
                    ),
 
                "lstm_label":
                    lstm_label,
 
                "lstm_confidence":
                    clf.get(
                        "lstm_conf_pct"
                    ),
 
                "iso_anomaly":
                    iso_flag,
 
                "iso_score":
                    clf.get(
                        "iso_score"
                    ),
 
            },
 
            clf_result=clf,
        )
 
        events.append(
            event
        )
 
        try:
 
            register_attack(
                src,
                dst or "unknown",
                attack_type,
                severity,
            )
 
        except Exception as e:
 
            print(
                f"[DETECT] Topology error: {e}"
            )
 
    return events
 
 
# ============================================================
# CLEAN TRACKING
# ============================================================
 
def cleanup_tracking():
 
    now = time.time()
 
    cutoff = (
        now
        -
        max(
            TIME_WINDOW,
            1,
        )
    )
 
    with tracking_lock:
 
        # ----------------------------------------------------
        # Packet timestamps
        # ----------------------------------------------------
 
        for src in list(
            src_pkt_times.keys()
        ):
 
            src_pkt_times[src] = [
 
                timestamp
 
                for timestamp
                in src_pkt_times[src]
 
                if timestamp >= cutoff
 
            ]
 
            if not src_pkt_times[src]:
 
                del src_pkt_times[
                    src
                ]
 
        # ----------------------------------------------------
        # SSH
        # ----------------------------------------------------
 
        for src in list(
            src_ssh_times.keys()
        ):
 
            src_ssh_times[src] = [
 
                timestamp
 
                for timestamp
                in src_ssh_times[src]
 
                if timestamp >= cutoff
 
            ]
 
            if not src_ssh_times[src]:
 
                del src_ssh_times[
                    src
                ]
 
        # ----------------------------------------------------
        # Telnet
        # ----------------------------------------------------
 
        for src in list(
            src_tel_times.keys()
        ):
 
            src_tel_times[src] = [
 
                timestamp
 
                for timestamp
                in src_tel_times[src]
 
                if timestamp >= cutoff
 
            ]
 
            if not src_tel_times[src]:
 
                del src_tel_times[
                    src
                ]
 
        # ----------------------------------------------------
        # Legacy port state
        # ----------------------------------------------------
 
        for src in list(
            src_port_hits.keys()
        ):
 
            recent_times = (
                src_pkt_times.get(
                    src,
                    [],
                )
            )
 
            if not recent_times:
 
                src_port_hits[
                    src
                ].clear()
 
                continue
 
            last_seen = max(
                recent_times
            )
 
            if (
                now - last_seen
                >
                TIME_WINDOW
            ):
 
                src_port_hits[
                    src
                ].clear()
 
 
# ============================================================
# DETECTION STATE DEBUG
# ============================================================
 
def print_detection_state():
 
    with tracking_lock:
 
        ports = {
 
            src:
                len(
                    ports
                )
 
            for src, ports
            in src_port_hits.items()
 
            if ports
        }
 
        packets = {
 
            src:
                len(
                    times
                )
 
            for src, times
            in src_pkt_times.items()
 
            if times
        }
 
        ssh = {
 
            src:
                len(
                    times
                )
 
            for src, times
            in src_ssh_times.items()
 
            if times
        }
 
        telnet = {
 
            src:
                len(
                    times
                )
 
            for src, times
            in src_tel_times.items()
 
            if times
        }
 
    if ports:
 
        print(
            f"[DETECT-STATE] "
            f"LEGACY_PORTS={ports}"
        )
 
    if packets:
 
        print(
            f"[DETECT-STATE] "
            f"PACKETS={packets}"
        )
 
    if ssh:
 
        print(
            f"[DETECT-STATE] "
            f"LEGACY_SSH={ssh}"
        )
 
    if telnet:
 
        print(
            f"[DETECT-STATE] "
            f"LEGACY_TELNET={telnet}"
        )
 
 
# ============================================================
# DETECTION LOOP
# ============================================================
 
def run_detection_loop(
    interval=2.0,
):
 
    print(
        f"[DETECT] Loop started "
        f"(interval={interval}s)"
    )
 
    models = []
 
    try:
 
        if is_ready():
            models.append(
                "RF"
            )
 
    except Exception:
        pass
 
    try:
 
        if iso_ready():
            models.append(
                "ISO"
            )
 
    except Exception:
        pass
 
    try:
 
        if lstm_ready():
            models.append(
                "LSTM"
            )
 
    except Exception:
        pass
 
    print(
        "[DETECT] Models active: "
        +
        (
            " + ".join(
                models
            )
            if models
            else
            "none (rule-based only)"
        )
    )
 
    print(
        "[DETECT] Rules active:"
    )
 
    print(
        f"          Port Scan : "
        f"{PORT_SCAN_THRESHOLD} unique TCP SYN ports"
    )
 
    print(
        f"          Brute Force: "
        f"{BRUTE_FORCE_THRESHOLD} SSH/Telnet attempts "
        f"+ application activity"
    )
 
    print(
        f"          DDoS       : "
        f"{DDOS_PPS_THRESHOLD} PPS base threshold "
        f"+ strong flood validation"
    )
 
    print(
        f"          Window     : "
        f"{TIME_WINDOW}s"
    )
 
    print(
        "[DETECT] Waiting for attack traffic..."
    )
 
    last_cleanup = time.time()
 
    last_state = time.time()
 
    while True:
 
        loop_start = time.time()
 
        try:
 
            all_events = []
 
            # =================================================
            # RULES FIRST
            # =================================================
 
            try:
 
                all_events.extend(
                    check_port_scan()
                )
 
            except Exception as e:
 
                print(
                    f"[DETECT] "
                    f"Port-scan cycle error: {e}"
                )
 
            try:
 
                all_events.extend(
                    check_brute_force()
                )
 
            except Exception as e:
 
                print(
                    f"[DETECT] "
                    f"Brute-force cycle error: {e}"
                )
 
            try:
 
                all_events.extend(
                    check_ddos()
                )
 
            except Exception as e:
 
                print(
                    f"[DETECT] "
                    f"DDoS cycle error: {e}"
                )
 
            # =================================================
            # ML SECOND
            # =================================================
 
            try:
 
                all_events.extend(
                    check_ml_anomalies()
                )
 
            except Exception as e:
 
                print(
                    f"[DETECT] "
                    f"ML cycle error: {e}"
                )
 
            # =================================================
            # SEND EVENTS
            # =================================================
 
            for event in all_events:
 
                print()
 
                print(
                    "=" * 62
                )
 
                print(
                    "[ALERT GENERATED]"
                )
 
                print(
                    f"  Type     : "
                    f"{event.get('attack_type', 'UNKNOWN')}"
                )
 
                print(
                    f"  Severity : "
                    f"{event.get('severity', 'UNKNOWN')}"
                )
 
                print(
                    f"  Source   : "
                    f"{event.get('src_ip', 'unknown')}"
                )
 
                print(
                    f"  Target   : "
                    f"{event.get('dst_ip', 'unknown')}"
                )
 
                print(
                    f"  Method   : "
                    f"{event.get('details', {}).get('detection_method', 'Unknown')}"
                )
 
                print(
                    "=" * 62
                )
 
                if on_detection:
 
                    try:
 
                        on_detection(
                            event
                        )
 
                        print(
                            "[DETECT] "
                            "Detection callback delivered"
                        )
 
                    except Exception as e:
 
                        print(
                            "[DETECT] "
                            f"Detection callback error: {e}"
                        )
 
                else:
 
                    print(
                        "[DETECT] "
                        "WARNING: Detection callback is not connected"
                    )
 
            # =================================================
            # PERIODIC STATE
            # =================================================
 
            if (
                time.time()
                -
                last_state
                >= 10
            ):
 
                print_detection_state()
 
                last_state = time.time()
 
            # =================================================
            # PERIODIC CLEANUP
            # =================================================
 
            if (
                time.time()
                -
                last_cleanup
                >= 10
            ):
 
                cleanup_tracking()
 
                cleanup_alert_history()
 
                cleanup_ml_history()
 
                last_cleanup = time.time()
 
            # =================================================
            # PERFORMANCE
            # =================================================
 
            cycle_time = (
                time.time()
                -
                loop_start
            )
 
            if cycle_time > 1.5:
 
                print(
                    f"[DETECT] "
                    f"WARNING: slow detection cycle "
                    f"{cycle_time:.2f}s"
                )
 
        except Exception as e:
 
            print(
                f"[DETECT] Loop error: {e}"
            )
 
        time.sleep(
            max(
                0.1,
                interval,
            )
        )
 
 
# ============================================================
# START DETECTION THREAD
# ============================================================
 
def start_detection_thread(
    interval=2.0,
):
 
    t = threading.Thread(
 
        target=run_detection_loop,
 
        kwargs={
            "interval":
                interval,
        },
 
        daemon=True,
 
        name="Detection",
 
    )
 
    t.start()
 
    print(
        "[DETECT] Thread started"
    )
 
    return t
 
