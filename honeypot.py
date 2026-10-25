# backend/honeypot.py
# ─────────────────────────────────────────────────────────────
# Honeypot Module
#
# Supports:
#   • Cowrie SSH honeypot JSON events
#   • Local/shared Cowrie log files
#   • Remote Cowrie log monitoring over SSH
#   • Optional OpenCanary monitoring
#
# Calls:
#   • on_session_close(session)
#   • on_trigger(trigger)
#
# Existing project structure and database integration preserved.
# ─────────────────────────────────────────────────────────────

import os
import sys
import json
import time
import threading
import subprocess
from datetime import datetime, timezone
from typing import Optional, Dict, Any


sys.path.insert(
    0,
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
)

from backend.database import save_honeypot_session
from backend.utils.logger import get_logger


log = get_logger("honeypot")


# ─────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────

# Monitoring mode:
#
#   ssh   -> Windows SOC connects to Cowrie VM through SSH and
#            tails the remote cowrie.json file.
#
#   file  -> Read Cowrie JSON from a local path / mounted share.
#
# Default is SSH because Cowrie currently runs on:
#   192.168.56.40
#
COWRIE_MODE = os.getenv(
    "COWRIE_MODE",
    "ssh",
).strip().lower()


# ── Cowrie SSH configuration ─────────────────────────────────

COWRIE_HOST = os.getenv(
    "COWRIE_HOST",
    "192.168.56.40",
).strip()

COWRIE_SSH_PORT = int(
    os.getenv(
        "COWRIE_SSH_PORT",
        "22",
    )
)

COWRIE_SSH_USER = os.getenv(
    "COWRIE_SSH_USER",
    "socadmin",
).strip()

COWRIE_REMOTE_LOG = os.getenv(
    "COWRIE_REMOTE_LOG",
    "/home/socadmin/my-honeypot/var/log/cowrie/cowrie.json",
).strip()


# ── Local/shared Cowrie logfile ──────────────────────────────
#
# Used only when:
#
#   COWRIE_MODE=file
#
# This can point to a local copy or mounted network share.
#
COWRIE_LOG = os.getenv(
    "COWRIE_LOG",
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "logs",
        "cowrie.json",
    ),
)


# ── OpenCanary configuration ─────────────────────────────────

OPENCANARY_ENABLED = (
    os.getenv(
        "OPENCANARY_ENABLED",
        "false",
    )
    .strip()
    .lower()
    in {"1", "true", "yes", "on"}
)

OPENCANARY_LOG = os.getenv(
    "OPENCANARY_LOG",
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "logs",
        "opencanary.log",
    ),
)


# ── General watcher configuration ────────────────────────────

FILE_POLL_INTERVAL = float(
    os.getenv(
        "HONEYPOT_FILE_POLL_INTERVAL",
        "0.5",
    )
)

RECONNECT_DELAY = float(
    os.getenv(
        "HONEYPOT_RECONNECT_DELAY",
        "5",
    )
)

LOG_WAIT_INTERVAL = float(
    os.getenv(
        "HONEYPOT_LOG_WAIT_INTERVAL",
        "10",
    )
)


# ─────────────────────────────────────────────────────────────
# Internal helpers
# ─────────────────────────────────────────────────────────────

def _utc_now_iso() -> str:
    """Return current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _parse_timestamp(value: Any) -> Optional[datetime]:
    """
    Parse Cowrie ISO-8601 timestamps.

    Example:
        2026-09-10T10:46:26.418096Z
    """

    if not value:
        return None

    try:
        text = str(value).strip()

        if text.endswith("Z"):
            text = text[:-1] + "+00:00"

        dt = datetime.fromisoformat(text)

        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)

        return dt

    except Exception:
        return None


def _timestamp_to_epoch(value: Any) -> float:
    """Convert ISO Cowrie timestamp to Unix epoch."""

    dt = _parse_timestamp(value)

    if dt is None:
        return time.time()

    return dt.timestamp()


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _mask_password(password: str) -> str:
    """
    Return a masked representation for logs/UI metadata.

    The original credential is still retained inside the session
    dictionary for existing forensic/database compatibility.
    """

    if not password:
        return ""

    return "*" * min(max(len(password), 4), 16)


def _new_cowrie_session(
    sid: str,
    evt: Dict[str, Any],
) -> Dict[str, Any]:

    timestamp = evt.get("timestamp") or _utc_now_iso()

    return {
        # Existing fields preserved
        "session_id": sid,
        "src_ip": evt.get("src_ip", ""),
        "start_ts": _timestamp_to_epoch(timestamp),
        "timestamp": timestamp,
        "username": "",
        "passwords": [],
        "password": "",
        "commands": [],
        "files": [],
        "duration_sec": 0.0,
        "source": "cowrie",

        # Additional useful Cowrie metadata
        "protocol": evt.get("protocol", "ssh"),
        "src_port": _safe_int(evt.get("src_port")),
        "dst_ip": evt.get("dst_ip", ""),
        "dst_port": _safe_int(evt.get("dst_port")),
        "sensor": evt.get("sensor", ""),
        "uuid": evt.get("uuid", ""),
        "client_version": "",
        "hassh": "",
        "login_success": False,
        "login_attempts": 0,
        "failed_logins": 0,
        "successful_logins": 0,
        "command_count": 0,
        "file_count": 0,
        "ttylog": "",
        "ttylog_sha256": "",
        "end_timestamp": "",
        "last_event_timestamp": timestamp,
    }


# ─────────────────────────────────────────────────────────────
# Cowrie event parser
# ─────────────────────────────────────────────────────────────

def _parse_cowrie_line(
    line: str,
    sessions: dict,
    on_session_close=None,
):
    """
    Parse one Cowrie JSON event.

    Sessions are stored until the exact event:

        cowrie.session.closed

    is received.

    cowrie.log.closed MUST NOT be treated as the session close
    event because Cowrie sends it immediately before
    cowrie.session.closed.
    """

    if not line:
        return

    try:
        evt = json.loads(line.strip())

    except json.JSONDecodeError:
        return

    except Exception as exc:
        log.debug(f"Failed parsing Cowrie JSON line: {exc}")
        return

    eid = str(evt.get("eventid", "")).strip()

    if not eid:
        return

    sid = str(
        evt.get("session")
        or evt.get("uuid")
        or "unknown"
    )

    # Some Cowrie events may not contain a session identifier.
    # Ignore those rather than mixing unrelated events together.
    if sid == "unknown":
        return

    if sid not in sessions:
        sessions[sid] = _new_cowrie_session(
            sid,
            evt,
        )

    session = sessions[sid]

    # Update general metadata when available.
    if evt.get("src_ip"):
        session["src_ip"] = evt.get("src_ip")

    if evt.get("src_port") is not None:
        session["src_port"] = _safe_int(evt.get("src_port"))

    if evt.get("dst_ip"):
        session["dst_ip"] = evt.get("dst_ip")

    if evt.get("dst_port") is not None:
        session["dst_port"] = _safe_int(evt.get("dst_port"))

    if evt.get("protocol"):
        session["protocol"] = evt.get("protocol")

    if evt.get("sensor"):
        session["sensor"] = evt.get("sensor")

    if evt.get("uuid"):
        session["uuid"] = evt.get("uuid")

    if evt.get("timestamp"):
        session["last_event_timestamp"] = evt.get("timestamp")

    # ─────────────────────────────────────────────────────────
    # Connection
    # ─────────────────────────────────────────────────────────

    if eid == "cowrie.session.connect":

        timestamp = evt.get("timestamp")

        if timestamp:
            session["timestamp"] = timestamp
            session["start_ts"] = _timestamp_to_epoch(timestamp)

        log.info(
            "Cowrie connection: "
            f"{session['src_ip']}:{session['src_port']} -> "
            f"{session['dst_ip']}:{session['dst_port']}"
        )

    # ─────────────────────────────────────────────────────────
    # SSH client version
    # ─────────────────────────────────────────────────────────

    elif eid == "cowrie.client.version":

        session["client_version"] = evt.get(
            "version",
            "",
        )

    # ─────────────────────────────────────────────────────────
    # SSH HASSH fingerprint
    # ─────────────────────────────────────────────────────────

    elif eid == "cowrie.client.kex":

        session["hassh"] = evt.get(
            "hassh",
            "",
        )

    # ─────────────────────────────────────────────────────────
    # Login success
    # ─────────────────────────────────────────────────────────

    elif eid == "cowrie.login.success":

        username = str(
            evt.get(
                "username",
                "",
            )
        )

        password = str(
            evt.get(
                "password",
                "",
            )
        )

        session["username"] = username

        session["login_success"] = True
        session["login_attempts"] += 1
        session["successful_logins"] += 1

        if password:
            session["passwords"].append(password)
            session["password"] = password

        log.info(
            "Cowrie login success: "
            f"{session['src_ip']} | "
            f"user={username} | "
            f"password={_mask_password(password)}"
        )

    # ─────────────────────────────────────────────────────────
    # Login failure
    # ─────────────────────────────────────────────────────────

    elif eid == "cowrie.login.failed":

        username = str(
            evt.get(
                "username",
                "",
            )
        )

        password = str(
            evt.get(
                "password",
                "",
            )
        )

        if username:
            session["username"] = username

        session["login_attempts"] += 1
        session["failed_logins"] += 1

        if password:
            session["passwords"].append(password)
            session["password"] = password

        log.info(
            "Cowrie login failed: "
            f"{session['src_ip']} | "
            f"user={username} | "
            f"password={_mask_password(password)}"
        )

    # ─────────────────────────────────────────────────────────
    # Commands
    # ─────────────────────────────────────────────────────────

    elif eid == "cowrie.command.input":

        command = str(
            evt.get(
                "input",
                "",
            )
        ).strip()

        if command:

            session["commands"].append(
                {
                    "time": evt.get(
                        "timestamp",
                        "",
                    ),
                    "command": command,
                }
            )

            session["command_count"] = len(
                session["commands"]
            )

            log.info(
                "Cowrie command: "
                f"{session['src_ip']} | "
                f"{command}"
            )

    # ─────────────────────────────────────────────────────────
    # File/download activity
    # ─────────────────────────────────────────────────────────

    elif eid in {
        "cowrie.session.file_download",
        "cowrie.session.file_upload",
    } or "file_download" in eid or "file_upload" in eid:

        file_record = {
            "timestamp": evt.get(
                "timestamp",
                "",
            ),
            "url": evt.get(
                "url",
                "",
            ),
            "filename": (
                evt.get("filename")
                or evt.get("outfile")
                or evt.get("destination")
                or ""
            ),
            "shasum": (
                evt.get("shasum")
                or evt.get("sha256")
                or ""
            ),
            "eventid": eid,
        }

        session["files"].append(
            file_record
        )

        session["file_count"] = len(
            session["files"]
        )

    # ─────────────────────────────────────────────────────────
    # TTY log closed
    #
    # IMPORTANT:
    # This is NOT the Cowrie session-close event.
    # Do not save/delete the session here.
    # ─────────────────────────────────────────────────────────

    elif eid == "cowrie.log.closed":

        session["ttylog"] = evt.get(
            "ttylog",
            "",
        )

        session["ttylog_sha256"] = evt.get(
            "shasum",
            "",
        )

        duration_ms = evt.get(
            "duration_ms"
        )

        if duration_ms is not None:
            session["duration_sec"] = (
                _safe_float(duration_ms) / 1000.0
            )

    # ─────────────────────────────────────────────────────────
    # Exact Cowrie session close
    # ─────────────────────────────────────────────────────────

    elif eid == "cowrie.session.closed":

        session["end_timestamp"] = evt.get(
            "timestamp",
            _utc_now_iso(),
        )

        duration_ms = evt.get(
            "duration_ms"
        )

        if duration_ms is not None:

            session["duration_sec"] = (
                _safe_float(duration_ms) / 1000.0
            )

        else:

            end_epoch = _timestamp_to_epoch(
                session["end_timestamp"]
            )

            session["duration_sec"] = max(
                0.0,
                end_epoch - session["start_ts"],
            )

        session["command_count"] = len(
            session["commands"]
        )

        session["file_count"] = len(
            session["files"]
        )

        try:

            save_honeypot_session(
                session
            )

            log.info(
                "Cowrie session closed: "
                f"{session['src_ip']} | "
                f"user={session['username'] or '-'} | "
                f"cmds={session['command_count']} | "
                f"files={session['file_count']} | "
                f"duration={session['duration_sec']:.1f}s"
            )

        except Exception as exc:

            log.exception(
                "Failed saving Cowrie session "
                f"{sid}: {exc}"
            )

        if on_session_close:

            try:

                on_session_close(
                    session
                )

            except Exception as exc:

                log.exception(
                    "Cowrie session callback failed "
                    f"for {sid}: {exc}"
                )

        sessions.pop(
            sid,
            None,
        )


# ─────────────────────────────────────────────────────────────
# Cowrie local-file watcher
# ─────────────────────────────────────────────────────────────

def _tail_cowrie_file(
    log_path: str,
    on_session_close=None,
):
    """
    Tail Cowrie JSON from a local file or mounted network share.

    Only new lines are processed after the watcher starts.
    """

    sessions = {}

    log.info(
        f"Watching Cowrie local log: {log_path}"
    )

    while True:

        try:

            while not os.path.exists(log_path):

                log.warning(
                    "Cowrie log not found at "
                    f"{log_path}; retrying in "
                    f"{LOG_WAIT_INTERVAL:.0f}s..."
                )

                time.sleep(
                    LOG_WAIT_INTERVAL
                )

            with open(
                log_path,
                "r",
                encoding="utf-8",
                errors="ignore",
            ) as file_handle:

                # Only process events generated after watcher startup.
                file_handle.seek(
                    0,
                    os.SEEK_END,
                )

                log.info(
                    "Cowrie local log opened successfully"
                )

                while True:

                    line = file_handle.readline()

                    if line:

                        _parse_cowrie_line(
                            line,
                            sessions,
                            on_session_close,
                        )

                    else:

                        time.sleep(
                            FILE_POLL_INTERVAL
                        )

        except Exception as exc:

            log.exception(
                "Cowrie local log watcher error: "
                f"{exc}"
            )

            time.sleep(
                RECONNECT_DELAY
            )


# ─────────────────────────────────────────────────────────────
# Cowrie SSH watcher
# ─────────────────────────────────────────────────────────────

def _build_cowrie_ssh_command() -> list:
    """
    Build OpenSSH command used by the Windows SOC host.

    BatchMode=yes prevents the background watcher from hanging
    forever waiting for an interactive password prompt.

    SSH key authentication should therefore be configured between:

        Windows SOC host
            ->
        socadmin@192.168.56.40
    """

    remote_command = (
        f"tail -n 0 -F {COWRIE_REMOTE_LOG}"
    )

    return [
        "ssh",
        "-p",
        str(COWRIE_SSH_PORT),
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=3",
        f"{COWRIE_SSH_USER}@{COWRIE_HOST}",
        remote_command,
    ]


def _tail_cowrie_ssh(
    on_session_close=None,
):
    """
    Stream Cowrie JSON directly from the honeypot VM using SSH.

    This avoids:
      • Samba
      • SMB shares
      • UNC paths
      • copying logs manually
      • additional Python SSH dependencies

    The Windows OpenSSH client is used.
    """

    sessions = {}

    log.info(
        "Watching Cowrie remotely over SSH: "
        f"{COWRIE_SSH_USER}@{COWRIE_HOST}:"
        f"{COWRIE_SSH_PORT} "
        f"{COWRIE_REMOTE_LOG}"
    )

    while True:

        process = None

        try:

            command = _build_cowrie_ssh_command()

            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="ignore",
                bufsize=1,
            )

            log.info(
                "Cowrie SSH log-stream process started"
            )

            if process.stdout is None:

                raise RuntimeError(
                    "Unable to read SSH stdout"
                )

            for line in process.stdout:

                if not line:
                    continue

                _parse_cowrie_line(
                    line,
                    sessions,
                    on_session_close,
                )

            return_code = process.poll()

            stderr_text = ""

            if process.stderr is not None:

                try:

                    stderr_text = (
                        process.stderr.read()
                        or ""
                    ).strip()

                except Exception:
                    stderr_text = ""

            if stderr_text:

                log.warning(
                    "Cowrie SSH stream stopped: "
                    f"{stderr_text}"
                )

            else:

                log.warning(
                    "Cowrie SSH stream stopped "
                    f"(exit={return_code})"
                )

        except FileNotFoundError:

            log.error(
                "OpenSSH client 'ssh' was not found. "
                "Install/enable the Windows OpenSSH Client "
                "or use COWRIE_MODE=file."
            )

        except Exception as exc:

            log.exception(
                "Cowrie SSH watcher error: "
                f"{exc}"
            )

        finally:

            if process is not None:

                try:

                    if process.poll() is None:
                        process.terminate()

                except Exception:
                    pass

        log.info(
            "Reconnecting Cowrie SSH stream in "
            f"{RECONNECT_DELAY:.0f}s..."
        )

        time.sleep(
            RECONNECT_DELAY
        )


# ─────────────────────────────────────────────────────────────
# Public Cowrie watcher
# ─────────────────────────────────────────────────────────────

def tail_cowrie(
    log_path: str = COWRIE_LOG,
    on_session_close=None,
):
    """
    Start Cowrie monitoring.

    Mode is selected through COWRIE_MODE:

        ssh
        file
    """

    if COWRIE_MODE == "ssh":

        _tail_cowrie_ssh(
            on_session_close=on_session_close,
        )

        return

    if COWRIE_MODE == "file":

        _tail_cowrie_file(
            log_path=log_path,
            on_session_close=on_session_close,
        )

        return

    log.error(
        "Invalid COWRIE_MODE="
        f"{COWRIE_MODE!r}. "
        "Expected 'ssh' or 'file'."
    )


# ─────────────────────────────────────────────────────────────
# OpenCanary parser
# ─────────────────────────────────────────────────────────────

def tail_opencanary(
    log_path: str = OPENCANARY_LOG,
    on_trigger=None,
):
    """
    Tail OpenCanary JSON log and emit trigger events.

    OpenCanary is currently optional and disabled by default.
    """

    log.info(
        f"Watching OpenCanary log: {log_path}"
    )

    service_map = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        8080: "HTTP",
        2222: "SSH",
        2223: "Telnet",
    }

    while True:

        try:

            while not os.path.exists(log_path):

                log.warning(
                    "OpenCanary log not found at "
                    f"{log_path}; retrying in "
                    f"{LOG_WAIT_INTERVAL:.0f}s..."
                )

                time.sleep(
                    LOG_WAIT_INTERVAL
                )

            with open(
                log_path,
                "r",
                encoding="utf-8",
                errors="ignore",
            ) as file_handle:

                file_handle.seek(
                    0,
                    os.SEEK_END,
                )

                while True:

                    line = file_handle.readline()

                    if not line:

                        time.sleep(
                            FILE_POLL_INTERVAL
                        )

                        continue

                    try:

                        evt = json.loads(
                            line.strip()
                        )

                    except json.JSONDecodeError:
                        continue

                    except Exception:
                        continue

                    dst_port = _safe_int(
                        evt.get(
                            "dst_port",
                            0,
                        )
                    )

                    service = service_map.get(
                        dst_port,
                        f"Port {dst_port}",
                    )

                    trigger = {
                        "timestamp": (
                            evt.get("local_time")
                            or evt.get("timestamp")
                            or _utc_now_iso()
                        ),
                        "src_ip": evt.get(
                            "src_ip",
                            "",
                        ),
                        "src_port": _safe_int(
                            evt.get(
                                "src_port",
                                0,
                            )
                        ),
                        "dst_ip": evt.get(
                            "dst_ip",
                            "",
                        ),
                        "dst_port": dst_port,
                        "service": service,
                        "source": "opencanary",
                    }

                    if (
                        trigger["src_ip"]
                        and on_trigger
                    ):

                        try:

                            on_trigger(
                                trigger
                            )

                        except Exception as exc:

                            log.exception(
                                "OpenCanary trigger callback "
                                f"failed: {exc}"
                            )

        except Exception as exc:

            log.exception(
                "OpenCanary watcher error: "
                f"{exc}"
            )

            time.sleep(
                RECONNECT_DELAY
            )


# ─────────────────────────────────────────────────────────────
# Start honeypot watcher threads
# ─────────────────────────────────────────────────────────────

def start_honeypot_threads(
    on_cowrie_session=None,
    on_canary_trigger=None,
) -> list:
    """
    Start honeypot watcher threads.

    Cowrie:
        enabled automatically.

    OpenCanary:
        only enabled when OPENCANARY_ENABLED=true.
    """

    threads = []

    # ── Cowrie ───────────────────────────────────────────────

    cowrie_thread = threading.Thread(
        target=tail_cowrie,
        kwargs={
            "on_session_close": on_cowrie_session,
        },
        daemon=True,
        name="CowrieWatcher",
    )

    cowrie_thread.start()

    threads.append(
        cowrie_thread
    )

    log.info(
        "Cowrie watcher thread started "
        f"(mode={COWRIE_MODE})"
    )

    # ── OpenCanary ───────────────────────────────────────────

    if OPENCANARY_ENABLED:

        canary_thread = threading.Thread(
            target=tail_opencanary,
            kwargs={
                "on_trigger": on_canary_trigger,
            },
            daemon=True,
            name="OpenCanaryWatcher",
        )

        canary_thread.start()

        threads.append(
            canary_thread
        )

        log.info(
            "OpenCanary watcher thread started"
        )

    else:

        log.info(
            "OpenCanary watcher disabled"
        )

    return threads