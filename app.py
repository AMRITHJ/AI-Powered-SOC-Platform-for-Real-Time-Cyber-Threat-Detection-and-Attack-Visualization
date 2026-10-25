# backend/app.py
# ─────────────────────────────────────────────────────────────
# SOC Platform — Flask + SocketIO Application
#
# Handles:
#   - Dashboard
#   - API routes
#   - Detection event handling
#   - CTI enrichment
#   - Risk scoring
#   - Database persistence
#   - SocketIO real-time alerts
#   - Telegram alerts
#   - Honeypot redirection
#
# IMPORTANT:
# Detection events are emitted immediately.
# CTI / risk / forensic enrichment is performed afterwards
# so slow external services do not delay real-time SOC alerts.
#
# SOCKET.IO DESIGN:
#   - Uses threading mode instead of Eventlet.
#   - Longer heartbeat timeout for attack-load stability.
#   - Initial and enriched detections use the same event ID.
#   - History is returned only to the requesting browser.
#   - Packet statistics are emitted every 2 seconds.
# ─────────────────────────────────────────────────────────────

import os
import sys
import threading
from datetime import datetime

from flask import (
    Flask,
    send_from_directory,
    request,
)

from flask_socketio import SocketIO
from flask_cors import CORS


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

FRONTEND_DIR = os.path.join(
    BASE_DIR,
    "frontend"
)


# ============================================================
# PROJECT IMPORT PATH
# ============================================================

if BASE_DIR not in sys.path:
    sys.path.insert(
        0,
        BASE_DIR
    )


# ============================================================
# BACKEND IMPORTS
# ============================================================

from backend.config import REPORTS_DIR

from backend.database import (
    init_sqlite,
    save_detection,
    get_recent_detections,
)

from backend.ai.risk_engine import (
    risk_from_event
)

from backend.threat_intelligence import (
    abuseipdb,
    virustotal,
    otx,
)

from backend.ai.vulnerability import (
    enrich_port
)

from backend.response.alert import (
    send_event_alert
)

from backend.response.firewall import (
    redirect_to_honeypot
)

from backend.forensics import (
    generate_detection_report
)

from backend.api.routes import (
    api as api_blueprint
)


# ============================================================
# FLASK APPLICATION
# ============================================================

app = Flask(
    __name__,
    static_folder=FRONTEND_DIR,
    static_url_path=""
)

app.config["SECRET_KEY"] = (
    "soc-mdu-2026"
)

CORS(app)


# ============================================================
# SOCKETIO
# ============================================================

"""
Threading mode is intentionally used here.

Why:
- Packet capture already runs in a normal Python thread.
- Detection already runs in a normal Python thread.
- CTI/forensics run in background threads.
- Heavy Random Forest/LSTM activity can block Eventlet's
  cooperative heartbeat processing.
- Longer ping timeout prevents temporary CPU-heavy detection
  cycles from immediately disconnecting the dashboard.

ping_interval = 20 seconds
ping_timeout  = 60 seconds
"""

socketio = SocketIO(
    app,
    cors_allowed_origins="*",
    async_mode="threading",
    ping_interval=20,
    ping_timeout=60,
    logger=False,
    engineio_logger=False,
)


# ============================================================
# REGISTER API BLUEPRINT
# ============================================================

app.register_blueprint(
    api_blueprint
)


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/")
def index():

    return send_from_directory(
        FRONTEND_DIR,
        "index.html"
    )


@app.route("/<path:filename>")
def frontend_files(
    filename
):

    return send_from_directory(
        FRONTEND_DIR,
        filename
    )


# ============================================================
# EVENT NORMALIZATION
# ============================================================

def _prepare_event(event):
    """
    Ensure the basic fields required by the frontend,
    database and SocketIO are present.

    Does not change the project's event structure.
    """

    if not isinstance(
        event,
        dict
    ):

        return None

    event.setdefault(
        "id",
        f"EVT-{int(datetime.utcnow().timestamp() * 1000)}"
    )

    event.setdefault(
        "timestamp",
        datetime.utcnow().isoformat()
    )

    event.setdefault(
        "src_ip",
        "UNKNOWN"
    )

    event.setdefault(
        "dst_ip",
        "unknown"
    )

    event.setdefault(
        "attack_type",
        "UNKNOWN"
    )

    event.setdefault(
        "severity",
        "MEDIUM"
    )

    event.setdefault(
        "details",
        {}
    )

    event.setdefault(
        "mitigations",
        []
    )

    event.setdefault(
        "ttp",
        {}
    )

    event.setdefault(
        "cti_score",
        None
    )

    event.setdefault(
        "cti_label",
        None
    )

    event.setdefault(
        "cti_details",
        {}
    )

    return event


# ============================================================
# SOCKETIO EVENT EMITTER
# ============================================================

def _emit_detection(
    event,
    stage="initial"
):
    """
    Emit a detection safely.

    stage:
        initial  -> immediately after detection
        enriched -> after CTI/risk/forensics

    The same event ID is preserved for initial + enriched.
    """

    if not isinstance(
        event,
        dict
    ):

        return False

    try:

        socketio.emit(
            "new_detection",
            event
        )

        print(
            "[APP] SocketIO detection emitted "
            f"({stage}): "
            f"[{event.get('severity', 'UNKNOWN')}] "
            f"{event.get('attack_type', 'UNKNOWN')} "
            f"from "
            f"{event.get('src_ip', 'UNKNOWN')} "
            f"| id={event.get('id', 'UNKNOWN')}"
        )

        return True

    except Exception as e:

        print(
            f"[APP] SocketIO error ({stage}): {e}"
        )

        return False


# ============================================================
# DETECTION EVENT HANDLER
# ============================================================

def handle_detection(
    event: dict
):
    """
    Called by backend.detect whenever an attack is detected.

    Processing strategy:

        1. Validate event
        2. Immediately save basic detection
        3. Immediately emit dashboard alert
        4. Run CTI/risk/forensics asynchronously
        5. Emit enriched event
        6. Send Telegram for HIGH/CRITICAL
        7. Redirect CRITICAL events when appropriate

    This prevents CTI/API/PDF delays from blocking
    real-time dashboard alerts.
    """

    event = _prepare_event(
        event
    )

    if event is None:

        print(
            "[APP] ERROR: Invalid detection event"
        )

        return

    print(
        "[APP] Detection received: "
        f"{event.get('attack_type')} "
        f"from "
        f"{event.get('src_ip')} "
        f"| id={event.get('id')}"
    )


    # ========================================================
    # IMMEDIATE EVENT PREPARATION
    # ========================================================

    event.setdefault(
        "cti_score",
        None
    )

    event.setdefault(
        "cti_label",
        None
    )

    event.setdefault(
        "cti_details",
        {}
    )

    event["processing_stage"] = (
        "initial"
    )


    # ========================================================
    # IMMEDIATE DATABASE SAVE
    # ========================================================

    try:

        save_detection(
            event
        )

        print(
            "[APP] Initial detection saved: "
            f"{event.get('attack_type')} "
            f"| id={event.get('id')}"
        )

    except Exception as e:

        print(
            f"[APP] Initial database error: {e}"
        )


    # ========================================================
    # IMMEDIATE DASHBOARD EMIT
    # ========================================================

    _emit_detection(
        event,
        stage="initial"
    )


    # ========================================================
    # BACKGROUND ENRICHMENT
    # ========================================================

    def _process():

        src_ip = event.get(
            "src_ip",
            ""
        )

        details = (
            event.get(
                "details"
            )
            or
            {}
        )

        dst_port = details.get(
            "target_port",
            event.get(
                "dst_port",
                0
            )
        )


        # ====================================================
        # 1. CTI ENRICHMENT
        # ====================================================

        cti = {}

        try:

            if src_ip:

                try:

                    abuse = abuseipdb.query(
                        src_ip
                    )

                except Exception as e:

                    print(
                        "[APP] AbuseIPDB error: "
                        f"{e}"
                    )

                    abuse = {}

                try:

                    vt = virustotal.query(
                        src_ip
                    )

                except Exception as e:

                    print(
                        "[APP] VirusTotal error: "
                        f"{e}"
                    )

                    vt = {}

                try:

                    otx_result = otx.query(
                        src_ip
                    )

                except Exception as e:

                    print(
                        "[APP] OTX error: "
                        f"{e}"
                    )

                    otx_result = {}

            else:

                abuse = {}
                vt = {}
                otx_result = {}


            # ------------------------------------------------
            # Port vulnerability enrichment
            # ------------------------------------------------

            if dst_port:

                try:

                    vuln = enrich_port(
                        dst_port
                    )

                except Exception as e:

                    print(
                        "[APP] Vulnerability enrichment "
                        f"error: {e}"
                    )

                    vuln = {}

            else:

                vuln = {}


            cti = {

                "abuseipdb":
                    abuse,

                "virustotal":
                    vt,

                "otx":
                    otx_result,

                "kev_count":
                    vuln.get(
                        "kev_hits",
                        0
                    ),

                "max_epss":
                    vuln.get(
                        "max_epss",
                        0.0
                    ),

                "cves":
                    vuln.get(
                        "cves",
                        []
                    ),
            }

        except Exception as e:

            print(
                f"[APP] CTI error: {e}"
            )

            cti = {}


        # ====================================================
        # 2. RISK SCORE
        # ====================================================

        try:

            risk = risk_from_event(
                event,
                cti
            )

            if isinstance(
                risk,
                dict
            ):

                event["cti_score"] = (
                    risk.get(
                        "risk_score"
                    )
                )

                event["cti_label"] = (
                    risk.get(
                        "risk_label"
                    )
                )

                event["risk_breakdown"] = (
                    risk.get(
                        "breakdown",
                        {}
                    )
                )

        except Exception as e:

            print(
                f"[APP] Risk engine error: {e}"
            )


        event["cti_details"] = (
            cti
        )


        # ====================================================
        # 3. FORENSIC REPORT
        # ====================================================

        try:

            pdf = generate_detection_report(
                event,
                cti=cti
            )

            if pdf:

                event["pdf_report"] = (
                    os.path.basename(
                        pdf
                    )
                )

                print(
                    "[APP] Forensic report created: "
                    f"{event['pdf_report']}"
                )

        except Exception as e:

            print(
                f"[APP] PDF error: {e}"
            )


        # ====================================================
        # 4. ENRICHED STAGE
        # ====================================================

        event["processing_stage"] = (
            "enriched"
        )


        # ====================================================
        # 5. SEND ENRICHED EVENT
        # ====================================================

        _emit_detection(
            event,
            stage="enriched"
        )


        # ====================================================
        # 6. TELEGRAM
        # ====================================================

        if event.get(
            "severity"
        ) in (
            "HIGH",
            "CRITICAL"
        ):

            try:

                send_event_alert(
                    event
                )

                print(
                    "[APP] Telegram alert sent: "
                    f"{event.get('attack_type')}"
                )

            except Exception as e:

                print(
                    f"[APP] Telegram alert error: {e}"
                )


        # ====================================================
        # 7. CRITICAL → HONEYPOT
        # ====================================================

        ml_conf = event.get(
            "ml_conf",
            0
        )

        try:

            ml_conf = float(
                ml_conf or 0
            )

        except Exception:

            ml_conf = 0


        if (
            event.get(
                "severity"
            )
            ==
            "CRITICAL"
            and
            ml_conf >= 0.85
        ):

            try:

                redirect_to_honeypot(
                    src_ip
                )

                print(
                    "[APP] Critical source redirected "
                    f"to honeypot: {src_ip}"
                )

            except Exception as e:

                print(
                    f"[APP] Honeypot redirect error: {e}"
                )


    # ========================================================
    # START ENRICHMENT THREAD
    # ========================================================

    threading.Thread(
        target=_process,
        daemon=True,
        name=f"DetectionProcessor-{event.get('id', 'unknown')}"
    ).start()


# ============================================================
# DETECTION CALLBACK CONNECTION
# ============================================================

try:

    from backend import detect

    detect.on_detection = (
        handle_detection
    )

    print(
        "[APP] ✓ Detection callback connected"
    )

except Exception as e:

    print(
        "[APP] !!! Detection callback "
        f"connection failed: {e}"
    )


# ============================================================
# HONEYPOT SESSION HANDLER
# ============================================================

def _prepare_honeypot_socket_payload(
    session: dict
):
    """
    Build a browser-safe Cowrie session payload.

    backend.honeypot already persists the completed Cowrie
    session before invoking this callback. app.py therefore
    must not save the same session a second time.

    Raw attempted credentials may remain in the forensic/database
    copy managed by backend.honeypot, but they are masked before
    being sent to browsers over Socket.IO.
    """

    if not isinstance(
        session,
        dict
    ):

        return None


    payload = dict(
        session
    )


    commands = (
        session.get(
            "commands"
        )
        or
        []
    )

    files = (
        session.get(
            "files"
        )
        or
        []
    )


    payload["command_count"] = len(
        commands
    )

    payload["file_count"] = len(
        files
    )

    payload.setdefault(
        "attack_type",
        "HONEYPOT_ACTIVITY"
    )

    payload.setdefault(
        "severity",
        "HIGH"
    )

    payload.setdefault(
        "source",
        "cowrie"
    )

    payload.setdefault(
        "protocol",
        "ssh"
    )


    password = str(
        session.get(
            "password",
            ""
        )
        or
        ""
    )

    if password:

        payload["password"] = (
            "*" * min(
                max(
                    len(password),
                    4
                ),
                16
            )
        )

    else:

        payload["password"] = ""


    passwords = (
        session.get(
            "passwords"
        )
        or
        []
    )

    payload["passwords"] = [
        (
            "*" * min(
                max(
                    len(
                        str(password_value)
                    ),
                    4
                ),
                16
            )
        )
        for password_value in passwords
        if password_value is not None
    ]


    payload["details"] = {

        "session_id":
            session.get(
                "session_id",
                ""
            ),

        "sensor":
            session.get(
                "sensor",
                ""
            ),

        "protocol":
            session.get(
                "protocol",
                "ssh"
            ),

        "src_port":
            session.get(
                "src_port",
                0
            ),

        "dst_port":
            session.get(
                "dst_port",
                2222
            ),

        "username":
            session.get(
                "username",
                ""
            ),

        "login_success":
            bool(
                session.get(
                    "login_success",
                    False
                )
            ),

        "login_attempts":
            session.get(
                "login_attempts",
                0
            ),

        "failed_logins":
            session.get(
                "failed_logins",
                0
            ),

        "successful_logins":
            session.get(
                "successful_logins",
                0
            ),

        "command_count":
            len(
                commands
            ),

        "file_count":
            len(
                files
            ),

        "duration_sec":
            session.get(
                "duration_sec",
                0.0
            ),

        "client_version":
            session.get(
                "client_version",
                ""
            ),

        "hassh":
            session.get(
                "hassh",
                ""
            ),

        "ttylog":
            session.get(
                "ttylog",
                ""
            ),

        "ttylog_sha256":
            session.get(
                "ttylog_sha256",
                ""
            ),
    }


    return payload


def handle_honeypot_session(
    session: dict
):
    """
    Receive a completed Cowrie session from backend.honeypot
    and publish it to connected dashboard clients.

    Persistence is intentionally NOT repeated here because
    backend.honeypot saves the completed session before calling
    this handler.
    """

    payload = (
        _prepare_honeypot_socket_payload(
            session
        )
    )


    if payload is None:

        print(
            "[APP] Honeypot session ignored: "
            "invalid payload"
        )

        return


    try:

        socketio.emit(
            "honeypot_session",
            payload
        )

    except Exception as e:

        print(
            f"[APP] Honeypot SocketIO error: {e}"
        )


    print(
        "[APP] Honeypot session: "
        f"{payload.get('src_ip')} -> "
        f"{payload.get('dst_ip')} "
        f"| user="
        f"{payload.get('username') or '-'} "
        f"| cmds="
        f"{payload.get('command_count', 0)} "
        f"| files="
        f"{payload.get('file_count', 0)} "
        f"| duration="
        f"{float(payload.get('duration_sec', 0.0) or 0.0):.1f}s"
    )


# ============================================================
# OPEN CANARY
# ============================================================

def handle_canary_trigger(
    event: dict
):

    try:

        socketio.emit(
            "canary_trigger",
            event
        )

    except Exception as e:

        print(
            f"[APP] Canary SocketIO error: {e}"
        )


    print(
        "[APP] OpenCanary: "
        f"{event.get('service')} "
        f"from "
        f"{event.get('src_ip')}"
    )


# ============================================================
# SOCKETIO — CONNECT
# ============================================================

@socketio.on("connect")
def on_connect():

    try:

        from backend.ai.attack_classifier import (
            get_model_info
        )

        model_info = (
            get_model_info()
        )

    except Exception as e:

        print(
            f"[WS] Model info error: {e}"
        )

        model_info = {}


    sid = getattr(
        request,
        "sid",
        None
    )


    print(
        "[WS] Client connected"
        +
        (
            f" | sid={sid}"
            if sid
            else
            ""
        )
    )


    try:

        socketio.emit(
            "server_ready",
            {

                "message":
                    "SOC Platform connected",

                "timestamp":
                    datetime.utcnow().isoformat(),

                "model":
                    model_info,

            },
            to=sid
        )

    except Exception as e:

        print(
            f"[WS] server_ready emit error: {e}"
        )


# ============================================================
# SOCKETIO — DISCONNECT
# ============================================================

@socketio.on("disconnect")
def on_disconnect():

    sid = getattr(
        request,
        "sid",
        None
    )


    print(
        "[WS] Client disconnected"
        +
        (
            f" | sid={sid}"
            if sid
            else
            ""
        )
    )


# ============================================================
# SOCKETIO — HISTORY
# ============================================================

@socketio.on("request_history")
def on_request_history(
    data
):

    try:

        limit = (

            data.get(
                "limit",
                20
            )

            if isinstance(
                data,
                dict
            )

            else

            20
        )


        try:

            limit = int(
                limit
            )

        except Exception:

            limit = 20


        limit = max(
            1,
            min(
                limit,
                200
            )
        )


        history = (
            get_recent_detections(
                limit
            )
        )


        sid = getattr(
            request,
            "sid",
            None
        )


        # History belongs only to the browser that requested it.
        #
        # The previous implementation emitted history globally,
        # which meant every connected client could receive another
        # client's history request.

        socketio.emit(
            "history",
            history,
            to=sid
        )


        print(
            "[WS] History sent: "
            f"{len(history)} events"
            +
            (
                f" | sid={sid}"
                if sid
                else
                ""
            )
        )


    except Exception as e:

        print(
            f"[WS] History error: {e}"
        )


# ============================================================
# PACKET STATS BACKGROUND TASK
# ============================================================

def _packet_stats_loop():
    """
    Emit packet/traffic statistics every two seconds.

    Backend payload contract:

        packet_stats = {
            total,
            pps,
            incoming,
            outgoing,
            timestamp
        }

    socket.js listens for "packet_stats".
    """

    from backend.capture import (
        get_packet_count
    )


    last = 0


    while True:

        # Use Socket.IO's sleep helper rather than time.sleep().
        #
        # This works correctly with the configured Socket.IO
        # async backend and avoids unnecessary blocking.

        socketio.sleep(
            2
        )


        try:

            current = int(
                get_packet_count() or 0
            )


            delta = max(
                0,
                current - last
            )


            pps = (
                delta /
                2.0
            )


            last = (
                current
            )


            payload = {

                "total":
                    current,

                "pps":
                    round(
                        pps,
                        1
                    ),

                "incoming":
                    round(
                        pps * 0.7,
                        1
                    ),

                "outgoing":
                    round(
                        pps * 0.3,
                        1
                    ),

                "timestamp":
                    datetime.utcnow().isoformat(),

            }


            socketio.emit(
                "packet_stats",
                payload
            )


        except Exception as e:

            print(
                f"[STATS] {e}"
            )


# ============================================================
# STARTUP STATE
# ============================================================

_platform_start_lock = (
    threading.Lock()
)

_platform_started = (
    False
)


# ============================================================
# STARTUP
# ============================================================

def start_platform():
    """
    Called from run.py after all primary threads are started.

    This function is guarded so packet-stat background tasks
    cannot accidentally be started more than once.
    """

    global _platform_started


    with _platform_start_lock:

        if _platform_started:

            print(
                "[APP] Platform already initialised"
            )

            return


        _platform_started = (
            True
        )


    init_sqlite()


    # ========================================================
    # PACKET STATISTICS TASK
    # ========================================================

    try:

        socketio.start_background_task(
            _packet_stats_loop
        )

        print(
            "[APP] Packet stats emitter started"
        )

    except Exception as e:

        print(
            "[APP] Packet stats emitter failed: "
            f"{e}"
        )


    print(
        "[APP] Platform initialised"
    )


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route(
    "/api/health",
    methods=["GET"]
)
def health_check():

    return {

        "status":
            "ok",

        "service":
            "SOC Platform Backend",

        "socket_mode":
            socketio.async_mode,

        "timestamp":
            datetime.utcnow().isoformat(),

    }, 200