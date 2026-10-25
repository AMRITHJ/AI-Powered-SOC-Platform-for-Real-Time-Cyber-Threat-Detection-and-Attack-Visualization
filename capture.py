# backend/capture.py
import os
import sys
import time
import threading
import ipaddress

from datetime import datetime
from collections import defaultdict

from scapy.all import (
    sniff,
    IP,
    TCP,
    UDP,
    ICMP,
    DNS,
    DNSQR,
    DNSRR,
    get_if_list,
    get_if_addr,
)


# ============================================================
# PROJECT PATH
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


# ============================================================
# PROJECT IMPORTS
# ============================================================

from backend.config import (
    CAPTURE_IFACE,
    TIME_WINDOW,
    LAB_SUBNET,
)

from backend.network.flow_generator import update_flow


# ============================================================
# CONSTANTS
# ============================================================

MAX_PACKET_BUFFER = 10000

TCP_FLAG_SYN = 0x02
TCP_FLAG_ACK = 0x10

EXPECTED_ATTACKERS = {
    "192.168.56.10",
}

EXPECTED_TARGETS = {
    "192.168.56.30",
}


# ============================================================
# PACKET STORAGE
# ============================================================

packet_log = []

# Used only for packet-buffer/statistics state.
packet_lock = threading.RLock()


# ============================================================
# DETECTION TRACKING LOCK
# ============================================================

# Detection state has its own lock so a heavy packet burst does
# not hold the packet-buffer lock while detect.py inspects state.
tracking_lock = threading.RLock()


# ============================================================
# GLOBAL PACKET COUNTER
# ============================================================

# Complete number of successfully parsed IPv4 packets captured
# on the selected VMware interface during this process.
#
# This intentionally includes harmless VMware/Windows traffic.
# Detection and flow processing are filtered separately.
total_packets_count = 0


# ============================================================
# CAPTURE STATE
# ============================================================

_running = False
_capture_thread = None
_active_interface = None

capture_started_at = None
last_packet_time = None


# ============================================================
# CAPTURE DIAGNOSTICS
# ============================================================

capture_packets_by_source = defaultdict(int)
capture_packets_by_destination = defaultdict(int)
capture_packets_by_protocol = defaultdict(int)
capture_packets_by_port = defaultdict(int)

capture_non_lab_packets = 0
capture_lab_packets = 0
capture_parse_errors = 0

# Packets that are suitable for flow/detection processing after
# multicast/broadcast/noise filtering.
capture_detection_packets = 0

# Packets involving the expected Kali/Ubuntu pair.
soc_lab_packets = 0
last_soc_packet_log = 0.0


# ============================================================
# BEHAVIOURAL TRACKING
# ============================================================

# Public structures retained for detect.py compatibility.
src_port_hits = defaultdict(set)
src_pkt_times = defaultdict(list)
src_ssh_times = defaultdict(list)
src_tel_times = defaultdict(list)

# Internal timestamp map used to make src_port_hits obey
# TIME_WINDOW. The original implementation used only a set,
# which meant scanned ports remained forever.
_src_port_hit_times = defaultdict(dict)


# ============================================================
# APPLICATION PROTOCOL MAPPING
# ============================================================

_L7 = {
    21: 21,
    22: 5,
    23: 23,
    25: 6,
    53: 53,
    80: 7,
    443: 7,
    3306: 3306,
    8080: 7,
}


# ============================================================
# INTERFACE HELPERS
# ============================================================

def list_interfaces():
    """Return all interfaces visible to Scapy/Npcap."""

    try:
        return get_if_list()
    except Exception as e:
        print(
            f"[CAPTURE] Failed to enumerate interfaces: {e}"
        )
        return []


def get_interface_ip(iface):
    """Safely obtain an interface IPv4 address."""

    if not iface:
        return None

    try:
        ip = get_if_addr(iface)

        if ip and ip != "0.0.0.0":
            return str(ip)

    except Exception as e:
        print(
            "[CAPTURE] Interface IP lookup failed "
            f"for {iface}: {e}"
        )

    return None


def _lab_network():
    """
    Return LAB_SUBNET as an ipaddress network object.

    config.py may provide either a string or an already-created
    IPv4Network object.
    """

    try:
        if isinstance(
            LAB_SUBNET,
            (
                ipaddress.IPv4Network,
                ipaddress.IPv6Network,
            )
        ):
            return LAB_SUBNET

        return ipaddress.ip_network(
            str(LAB_SUBNET),
            strict=False
        )

    except Exception:
        return None


def ip_in_lab(ip):
    """Return True when an address belongs to LAB_SUBNET."""

    if not ip:
        return False

    network = _lab_network()

    if network is None:
        return False

    try:
        address = ipaddress.ip_address(
            str(ip).strip()
        )

        return address in network

    except (
        ValueError,
        TypeError,
    ):
        return False


def _valid_unicast_ip(ip):
    """
    Return True for an IPv4 address suitable for flow/detection
    processing.

    Multicast, unspecified and limited/global broadcast traffic
    should still be counted by packet statistics but should not
    be sent into ML/rule processing as attack flows.
    """

    if not ip:
        return False

    try:
        address = ipaddress.ip_address(
            str(ip).strip()
        )

        if not isinstance(
            address,
            ipaddress.IPv4Address
        ):
            return False

        if (
            address.is_multicast
            or address.is_unspecified
        ):
            return False

        # IPv4 limited broadcast.
        if str(address) == "255.255.255.255":
            return False

        return True

    except (
        ValueError,
        TypeError,
    ):
        return False


def is_known_soc_host(ip):
    """Return True for known SOC laboratory hosts."""

    if not ip:
        return False

    value = str(ip).strip()

    return (
        value in EXPECTED_ATTACKERS
        or value in EXPECTED_TARGETS
    )


def is_known_soc_pair(
    src_ip,
    dst_ip,
):
    """Return True for direct Kali <-> Ubuntu lab traffic."""

    src = str(src_ip or "").strip()
    dst = str(dst_ip or "").strip()

    return (
        src in EXPECTED_ATTACKERS
        and dst in EXPECTED_TARGETS
    ) or (
        src in EXPECTED_TARGETS
        and dst in EXPECTED_ATTACKERS
    )


def interface_matches_lab(iface):
    """Return True when an interface address is in LAB_SUBNET."""

    return ip_in_lab(
        get_interface_ip(iface)
    )


# ============================================================
# FIND CAPTURE INTERFACE
# ============================================================

def find_lab_interface():
    """
    Select the capture interface.

    Priority:
        1. Configured CAPTURE_IFACE when it exists AND belongs
           to LAB_SUBNET.
        2. Auto-discovered interface inside LAB_SUBNET.
        3. Existing configured interface as a warned fallback.
        4. First available interface as a last resort.

    This avoids silently preferring a configured but incorrect
    adapter over the actual VMware lab adapter.
    """

    print()
    print("=" * 62)
    print("[CAPTURE] Searching for capture interface")
    print("=" * 62)

    interfaces = list_interfaces()

    if not interfaces:
        print(
            "[CAPTURE] ERROR: No Npcap interfaces found."
        )
        return CAPTURE_IFACE

    print("[CAPTURE] Available interfaces:")

    lab_candidates = []

    for iface in interfaces:
        ip = get_interface_ip(iface)
        lab = ip_in_lab(ip)

        print(
            f"    {iface}"
            f" | IPv4={ip or 'N/A'}"
            f" | LAB={'YES' if lab else 'NO'}"
        )

        if lab:
            lab_candidates.append(
                (iface, ip)
            )

    configured_exists = (
        bool(CAPTURE_IFACE)
        and CAPTURE_IFACE in interfaces
    )

    configured_ip = (
        get_interface_ip(CAPTURE_IFACE)
        if CAPTURE_IFACE
        else None
    )

    if CAPTURE_IFACE:
        print()
        print(
            "[CAPTURE] Configured interface:"
            f" {CAPTURE_IFACE}"
        )
        print(
            "[CAPTURE] Configured IPv4:"
            f" {configured_ip or 'N/A'}"
        )

    # Preferred configured lab interface.
    if (
        configured_exists
        and ip_in_lab(configured_ip)
    ):
        print(
            "[CAPTURE] ✓ Configured interface belongs "
            "to SOC lab."
        )
        return CAPTURE_IFACE

    # Prefer a verified lab interface over a wrong configured one.
    if lab_candidates:
        iface, ip = lab_candidates[0]

        print()
        print(
            "[CAPTURE] ✓ VMware SOC lab interface found:"
        )
        print(f"          {iface}")
        print(f"          IPv4: {ip}")

        if configured_exists and iface != CAPTURE_IFACE:
            print(
                "[CAPTURE] WARNING: configured interface "
                "does not match the lab subnet; using the "
                "verified lab interface instead."
            )

        return iface

    # Configured fallback only when no verified lab adapter exists.
    if configured_exists:
        print()
        print(
            "[CAPTURE] WARNING: No interface could be verified "
            "inside LAB_SUBNET."
        )
        print(
            "[CAPTURE] Falling back to configured interface:"
            f" {CAPTURE_IFACE}"
        )
        return CAPTURE_IFACE

    fallback = interfaces[0]

    print()
    print(
        "[CAPTURE] WARNING: No verified VMware lab interface."
    )
    print(
        "[CAPTURE] Using first available interface:"
        f" {fallback}"
    )

    return fallback


# ============================================================
# PACKET PARSER
# ============================================================

def parse_packet(pkt):
    """
    Convert a Scapy IPv4 packet into the internal dictionary
    consumed by flow_generator.py and detect.py.
    """

    if not pkt.haslayer(IP):
        return None

    try:
        now = time.time()
        size = len(pkt)

        ip_layer = pkt[IP]

        src_ip = str(ip_layer.src).strip()
        dst_ip = str(ip_layer.dst).strip()

        protocol_num = int(
            ip_layer.proto
        )

        p = {
            "timestamp":
                datetime.utcnow().isoformat(),

            "ts_epoch":
                now,

            "src_ip":
                src_ip,

            "dst_ip":
                dst_ip,

            "protocol":
                "OTHER",

            "protocol_num":
                protocol_num,

            "src_port":
                0,

            "dst_port":
                0,

            "tcp_flags":
                0,

            "client_tcp_flags":
                0,

            "server_tcp_flags":
                0,

            "tcp_payload_len":
                0,

            "size":
                size,

            "min_ttl":
                int(ip_layer.ttl),

            "max_ttl":
                int(ip_layer.ttl),

            "min_ip_pkt_len":
                size,

            "max_ip_pkt_len":
                size,

            "longest_pkt":
                size,

            "shortest_pkt":
                size,

            "in_bytes":
                size,

            "in_pkts":
                1,

            "out_bytes":
                0,

            "out_pkts":
                0,

            "icmp_type":
                0,

            "icmp_ipv4_type":
                0,

            "dns_query_id":
                0,

            "dns_query_type":
                0,

            "dns_ttl_answer":
                0,

            "ftp_ret_code":
                0,

            "l7_proto":
                0,

            "flow_duration_ms":
                0,

            "src_to_dst_sec_bytes":
                0,

            "dst_to_src_sec_bytes":
                0,

            "src_to_dst_avg_throughput":
                0,

            "dst_to_src_avg_throughput":
                0,

            "retrans_in_bytes":
                0,

            "retrans_in_pkts":
                0,

            "retrans_out_bytes":
                0,

            "retrans_out_pkts":
                0,

            "tcp_win_max_in":
                0,

            "tcp_win_max_out":
                0,

            "duration_in":
                0,

            "duration_out":
                0,

            "is_lab_traffic":
                False,

            "is_detection_traffic":
                False,

            "expected_attacker":
                False,

            "expected_target":
                False,
        }


        # ====================================================
        # TCP
        # ====================================================

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]

            src_port = int(tcp.sport)
            dst_port = int(tcp.dport)
            flags = int(tcp.flags)

            try:
                payload_len = len(
                    bytes(tcp.payload)
                )
            except Exception:
                payload_len = 0

            p.update({
                "protocol":
                    "TCP",

                "src_port":
                    src_port,

                "dst_port":
                    dst_port,

                "tcp_flags":
                    flags,

                "client_tcp_flags":
                    flags,

                "tcp_win_max_in":
                    int(tcp.window),

                "tcp_payload_len":
                    payload_len,

                "l7_proto":
                    _L7.get(
                        dst_port,
                        _L7.get(
                            src_port,
                            0
                        )
                    ),
            })


        # ====================================================
        # UDP
        # ====================================================

        elif pkt.haslayer(UDP):
            udp = pkt[UDP]

            src_port = int(udp.sport)
            dst_port = int(udp.dport)

            p.update({
                "protocol":
                    "UDP",

                "src_port":
                    src_port,

                "dst_port":
                    dst_port,

                "l7_proto":
                    _L7.get(
                        dst_port,
                        _L7.get(
                            src_port,
                            0
                        )
                    ),
            })

            if pkt.haslayer(DNS):
                try:
                    dns = pkt[DNS]

                    p["dns_query_id"] = int(
                        dns.id or 0
                    )

                    # qtype, not the DNS qr query/response flag.
                    if (
                        dns.qd is not None
                        and isinstance(
                            dns.qd,
                            DNSQR
                        )
                    ):
                        p["dns_query_type"] = int(
                            dns.qd.qtype or 0
                        )

                    if (
                        dns.an is not None
                        and isinstance(
                            dns.an,
                            DNSRR
                        )
                    ):
                        p["dns_ttl_answer"] = int(
                            dns.an.ttl or 0
                        )

                except Exception:
                    pass


        # ====================================================
        # ICMP
        # ====================================================

        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]

            try:
                icmp_type = int(
                    icmp.type
                )
            except Exception:
                icmp_type = 0

            p.update({
                "protocol":
                    "ICMP",

                "icmp_type":
                    icmp_type,

                "icmp_ipv4_type":
                    icmp_type,
            })


        # ====================================================
        # LAB CLASSIFICATION
        # ====================================================

        src_lab = ip_in_lab(src_ip)
        dst_lab = ip_in_lab(dst_ip)

        known_src = is_known_soc_host(
            src_ip
        )

        known_dst = is_known_soc_host(
            dst_ip
        )

        known_pair = is_known_soc_pair(
            src_ip,
            dst_ip
        )

        lab = (
            src_lab
            or dst_lab
            or known_src
            or known_dst
            or known_pair
        )

        p["is_lab_traffic"] = lab

        p["expected_attacker"] = (
            src_ip in EXPECTED_ATTACKERS
        )

        p["expected_target"] = (
            dst_ip in EXPECTED_TARGETS
        )

        # Multicast/broadcast packets are valid captured traffic,
        # but they are background noise for flow/rule processing.
        p["is_detection_traffic"] = (
            lab
            and _valid_unicast_ip(src_ip)
            and _valid_unicast_ip(dst_ip)
        )

        return p

    except Exception as e:
        print(
            f"[CAPTURE] Packet parse error: {e}"
        )
        return None


# ============================================================
# LAB / DETECTION TRAFFIC CHECKS
# ============================================================

def is_lab_traffic(p):
    """Return True when either endpoint belongs to the SOC lab."""

    if not p:
        return False

    src = str(
        p.get(
            "src_ip",
            ""
        )
    ).strip()

    dst = str(
        p.get(
            "dst_ip",
            ""
        )
    ).strip()

    if not src or not dst:
        return False

    if (
        ip_in_lab(src)
        or ip_in_lab(dst)
    ):
        return True

    if (
        is_known_soc_host(src)
        or is_known_soc_host(dst)
    ):
        return True

    return is_known_soc_pair(
        src,
        dst
    )


def is_detection_traffic(p):
    """
    Return True when a captured packet should enter the flow and
    behavioural detection pipeline.
    """

    if not p:
        return False

    if p.get(
        "is_detection_traffic",
        False
    ):
        return True

    src = str(
        p.get(
            "src_ip",
            ""
        )
    ).strip()

    dst = str(
        p.get(
            "dst_ip",
            ""
        )
    ).strip()

    return (
        is_lab_traffic(p)
        and _valid_unicast_ip(src)
        and _valid_unicast_ip(dst)
    )


# ============================================================
# BEHAVIOURAL TRACKING
# ============================================================

def _prune_time_list(
    values,
    cutoff
):
    """Return only timestamps inside the active detection window."""

    return [
        timestamp
        for timestamp in values
        if timestamp >= cutoff
    ]


def _track(p):
    """
    Update the behavioural counters consumed by detect.py.

    Key fixes:
      - Port scans count only TCP SYN packets without ACK.
      - Unique scanned ports expire with TIME_WINDOW.
      - SSH/Telnet attempts count connection SYN attempts instead
        of every packet in an established session.
      - General packet-rate tracking remains per-source so DDoS
        rules still have packet timing information.
    """

    if not p:
        return

    if not is_detection_traffic(p):
        return

    src = str(
        p.get(
            "src_ip",
            ""
        )
    ).strip()

    if not src:
        return

    now = float(
        p.get(
            "ts_epoch",
            time.time()
        )
    )

    cutoff = (
        now
        - float(TIME_WINDOW)
    )

    protocol = str(
        p.get(
            "protocol",
            ""
        )
    ).upper()

    dst_port = int(
        p.get(
            "dst_port",
            0
        )
        or 0
    )

    flags = int(
        p.get(
            "tcp_flags",
            0
        )
        or 0
    )

    is_tcp_syn = (
        protocol == "TCP"
        and bool(flags & TCP_FLAG_SYN)
        and not bool(flags & TCP_FLAG_ACK)
    )


    with tracking_lock:

        # ----------------------------------------------------
        # General packet-rate timing
        # ----------------------------------------------------

        src_pkt_times[src].append(
            now
        )

        src_pkt_times[src] = (
            _prune_time_list(
                src_pkt_times[src],
                cutoff
            )
        )


        # ----------------------------------------------------
        # Port-scan timing
        # ----------------------------------------------------

        port_times = (
            _src_port_hit_times[src]
        )

        expired_ports = [
            port
            for port, timestamp
            in port_times.items()
            if timestamp < cutoff
        ]

        for port in expired_ports:
            port_times.pop(
                port,
                None
            )

        if (
            is_tcp_syn
            and dst_port > 0
        ):
            port_times[dst_port] = now

        # Preserve the public set expected by detect.py, but make
        # it represent only ports scanned in the active window.
        src_port_hits[src].clear()
        src_port_hits[src].update(
            port_times.keys()
        )


        # ----------------------------------------------------
        # SSH connection attempts
        # ----------------------------------------------------

        src_ssh_times[src] = (
            _prune_time_list(
                src_ssh_times[src],
                cutoff
            )
        )

        if (
            is_tcp_syn
            and dst_port == 22
        ):
            src_ssh_times[src].append(
                now
            )


        # ----------------------------------------------------
        # Telnet connection attempts
        # ----------------------------------------------------

        src_tel_times[src] = (
            _prune_time_list(
                src_tel_times[src],
                cutoff
            )
        )

        if (
            is_tcp_syn
            and dst_port == 23
        ):
            src_tel_times[src].append(
                now
            )


# ============================================================
# PACKET CALLBACK
# ============================================================

def packet_callback(pkt):
    global total_packets_count
    global last_packet_time
    global capture_non_lab_packets
    global capture_lab_packets
    global capture_parse_errors
    global capture_detection_packets
    global soc_lab_packets
    global last_soc_packet_log

    p = parse_packet(pkt)

    if not p:
        try:
            if pkt.haslayer(IP):
                with packet_lock:
                    capture_parse_errors += 1
        except Exception:
            pass

        return


    # ========================================================
    # CLASSIFICATION
    # ========================================================

    lab = is_lab_traffic(
        p
    )

    detection_traffic = (
        is_detection_traffic(
            p
        )
    )

    p["is_lab_traffic"] = lab
    p["is_detection_traffic"] = (
        detection_traffic
    )


    # ========================================================
    # BASIC VALUES
    # ========================================================

    src = p["src_ip"]
    dst = p["dst_ip"]
    protocol = p["protocol"]

    src_port = int(
        p.get(
            "src_port",
            0
        )
        or 0
    )

    dst_port = int(
        p.get(
            "dst_port",
            0
        )
        or 0
    )


    # ========================================================
    # PACKET STORAGE + STATISTICS
    # ========================================================

    with packet_lock:
        total_packets_count += 1
        last_packet_time = time.time()

        packet_log.append(
            p
        )

        overflow = (
            len(packet_log)
            - MAX_PACKET_BUFFER
        )

        if overflow > 0:
            del packet_log[
                :overflow
            ]

        if lab:
            capture_lab_packets += 1
        else:
            capture_non_lab_packets += 1

        if detection_traffic:
            capture_detection_packets += 1

        capture_packets_by_source[
            src
        ] += 1

        capture_packets_by_destination[
            dst
        ] += 1

        capture_packets_by_protocol[
            protocol
        ] += 1

        if dst_port:
            capture_packets_by_port[
                dst_port
            ] += 1

        count = total_packets_count


    # ========================================================
    # GENERAL DEBUG OUTPUT
    # ========================================================

    if (
        count <= 20
        or count % 1000 == 0
    ):
        print(
            "[CAPTURE] "
            f"{'LAB' if lab else 'NON-LAB'} "
            f"packet #{count}: "
            f"{src}:{src_port}"
            " -> "
            f"{dst}:{dst_port}"
            f" | {protocol}"
            f" | detection={'YES' if detection_traffic else 'NO'}"
            f" | size={p.get('size', 0)}"
        )


    # ========================================================
    # EXPECTED KALI <-> UBUNTU TRAFFIC
    # ========================================================

    if is_known_soc_pair(
        src,
        dst
    ):
        with packet_lock:
            soc_lab_packets += 1
            current_soc_count = (
                soc_lab_packets
            )

        now = time.time()

        if (
            now
            - last_soc_packet_log
            >= 1.0
        ):
            print(
                "[CAPTURE] ★ SOC ATTACK TRAFFIC: "
                f"{src}:{src_port}"
                " -> "
                f"{dst}:{dst_port}"
                f" | {protocol}"
                f" | total={current_soc_count}"
            )

            last_soc_packet_log = now


    # ========================================================
    # FLOW ENGINE
    # ========================================================

    # Do not feed multicast/broadcast VMware background noise
    # into the feature/ML pipeline.
    if detection_traffic:
        try:
            update_flow(
                p
            )

        except Exception as e:
            print(
                f"[CAPTURE] Flow update error: {e}"
            )


    # ========================================================
    # DETECTION TRACKING
    # ========================================================

    if detection_traffic:
        try:
            _track(
                p
            )

        except Exception as e:
            print(
                "[CAPTURE] Behaviour tracking error: "
                f"{e}"
            )


# ============================================================
# START CAPTURE
# ============================================================

def start_capture(
    iface=None
):
    global _running
    global capture_started_at
    global _active_interface

    if _running:
        print(
            "[CAPTURE] Capture already running."
        )
        return

    # ========================================================
    # RESET NEW CAPTURE SESSION
    # ========================================================
    #
    # A new capture start represents a fresh live monitoring
    # session. Reset only in-memory packet/statistics and
    # behavioural tracking state.
    #
    # This does NOT delete SQLite detections, forensic reports,
    # datasets, trained models, or any persistent project data.
    #
    
    reset_packet_count()

    print(
        "[CAPTURE] New monitoring session initialized."
    )

    selected_iface = (
        iface
        or find_lab_interface()
    )

    if not selected_iface:
        print(
            "[CAPTURE] ERROR: No capture interface available."
        )
        _running = False
        return

    _active_interface = (
        selected_iface
    )

    _running = True
    capture_started_at = (
        time.time()
    )

    print()
    print("=" * 62)
    print("[CAPTURE] Starting network capture")
    print("=" * 62)
    print(
        f"[CAPTURE] Interface : {selected_iface}"
    )
    print(
        f"[CAPTURE] IPv4      : "
        f"{get_interface_ip(selected_iface) or 'N/A'}"
    )
    print(
        f"[CAPTURE] Lab       : {LAB_SUBNET}"
    )
    print(
        "[CAPTURE] Expected attacker : "
        "192.168.56.10"
    )
    print(
        "[CAPTURE] Expected target   : "
        "192.168.56.30"
    )
    print(
        "[CAPTURE] BPF filter        : IPv4"
    )
    print(
        "[CAPTURE] Packet stats      : all captured IPv4"
    )
    print(
        "[CAPTURE] Flow/detection    : lab unicast traffic"
    )
    print(
        "[CAPTURE] Port-scan state   : TCP SYN within TIME_WINDOW"
    )
    print(
        "[CAPTURE] Packet lock       : packet_lock"
    )
    print(
        "[CAPTURE] Tracking lock     : tracking_lock"
    )
    print(
        "[CAPTURE] Session counter   : RESET TO 0"
    )
    print("=" * 62)

    try:
        sniff(
            iface=selected_iface,
            prn=packet_callback,
            store=False,
            filter="ip",
            stop_filter=lambda _:
                not _running,
        )

    except Exception as e:
        _running = False

        print()
        print(
            "[CAPTURE] ❌ Sniff failed"
        )
        print(
            f"[CAPTURE] Error: {e}"
        )
        print(
            "[CAPTURE] Check:"
        )
        print(
            "          1. Npcap installation"
        )
        print(
            "          2. VMware adapter"
        )
        print(
            "          3. Selected interface"
        )
        print(
            "          4. Administrator privileges"
        )

        raise

    finally:
        _running = False
        print(
            "[CAPTURE] Sniff loop stopped."
        )


# ============================================================
# STOP CAPTURE
# ============================================================

def stop_capture():
    """
    Request capture shutdown.

    Scapy's stop_filter is evaluated when a packet is received,
    so on a completely idle interface the sniff call may return
    after the next packet arrives.
    """

    global _running

    _running = False

    print(
        "[CAPTURE] Capture stopping..."
    )


# ============================================================
# START CAPTURE THREAD
# ============================================================

def start_capture_thread(
    iface=None
):
    global _capture_thread

    if (
        _capture_thread is not None
        and _capture_thread.is_alive()
    ):
        print(
            "[CAPTURE] Capture thread already running."
        )
        return _capture_thread

    t = threading.Thread(
        target=start_capture,
        args=(iface,),
        daemon=True,
        name="Capture",
    )

    t.start()

    _capture_thread = t

    print(
        "[CAPTURE] Thread started"
    )

    return t


# ============================================================
# GET TOTAL PACKET COUNT
# ============================================================

def get_packet_count():
    with packet_lock:
        return total_packets_count


# ============================================================
# GET RECENT PACKETS
# ============================================================

def get_recent_packets(
    n=100
):
    try:
        n = max(
            1,
            int(n)
        )
    except Exception:
        n = 100

    with packet_lock:
        return list(
            packet_log[-n:]
        )


# ============================================================
# GET PACKET BUFFER SIZE
# ============================================================

def get_packet_buffer_size():
    with packet_lock:
        return len(
            packet_log
        )


# ============================================================
# GET CAPTURE STATISTICS
# ============================================================

def get_capture_stats():
    with packet_lock:
        return {
            "total_packets":
                total_packets_count,

            "buffer_size":
                len(packet_log),

            "active_interface":
                _active_interface,

            "active_interface_ip":
                get_interface_ip(
                    _active_interface
                ),

            "running":
                _running,

            "thread_alive":
                (
                    _capture_thread is not None
                    and _capture_thread.is_alive()
                ),

            "capture_started_at":
                capture_started_at,

            "last_packet_time":
                last_packet_time,

            "lab_packets":
                capture_lab_packets,

            "non_lab_packets":
                capture_non_lab_packets,

            "detection_packets":
                capture_detection_packets,

            "soc_lab_packets":
                soc_lab_packets,

            "parse_errors":
                capture_parse_errors,

            "packets_by_source":
                dict(
                    capture_packets_by_source
                ),

            "packets_by_destination":
                dict(
                    capture_packets_by_destination
                ),

            "packets_by_protocol":
                dict(
                    capture_packets_by_protocol
                ),

            "packets_by_port":
                dict(
                    capture_packets_by_port
                ),
        }


# ============================================================
# CAPTURE THREAD STATUS
# ============================================================

def is_capture_thread_alive():
    return (
        _capture_thread is not None
        and _capture_thread.is_alive()
    )


# ============================================================
# LAST PACKET TIME
# ============================================================

def get_last_packet_time():
    with packet_lock:
        return last_packet_time


# ============================================================
# ACTIVE INTERFACE
# ============================================================

def get_active_interface():
    return _active_interface


# ============================================================
# CAPTURE RUNTIME
# ============================================================

def get_capture_runtime():
    if not capture_started_at:
        return 0

    return (
        time.time()
        - capture_started_at
    )


# ============================================================
# RESET CAPTURE
# ============================================================

def reset_packet_count():
    global total_packets_count
    global last_packet_time
    global capture_lab_packets
    global capture_non_lab_packets
    global capture_detection_packets
    global capture_parse_errors
    global soc_lab_packets
    global last_soc_packet_log

    with packet_lock:
        total_packets_count = 0
        last_packet_time = None

        capture_lab_packets = 0
        capture_non_lab_packets = 0
        capture_detection_packets = 0

        capture_parse_errors = 0

        soc_lab_packets = 0
        last_soc_packet_log = 0.0

        packet_log.clear()

        capture_packets_by_source.clear()
        capture_packets_by_destination.clear()
        capture_packets_by_protocol.clear()
        capture_packets_by_port.clear()

    with tracking_lock:
        src_port_hits.clear()
        src_pkt_times.clear()
        src_ssh_times.clear()
        src_tel_times.clear()
        _src_port_hit_times.clear()

    print(
        "[CAPTURE] Packet counters and behavioural state reset."
    )


# ============================================================
# CAPTURE RUNNING STATUS
# ============================================================

def is_capture_running():
    return _running


# ============================================================
# FULL RUNTIME STATUS
# ============================================================

def get_runtime_status():
    return {
        "running":
            is_capture_running(),

        "thread_alive":
            is_capture_thread_alive(),

        "interface":
            get_active_interface(),

        "interface_ip":
            get_interface_ip(
                get_active_interface()
            ),

        "packet_count":
            get_packet_count(),

        "buffer_size":
            get_packet_buffer_size(),

        "runtime_seconds":
            round(
                get_capture_runtime(),
                2
            ),

        "last_packet_time":
            get_last_packet_time(),
    }
