# ============================================================
# SOC PLATFORM — DATABASE
# backend/database.py
# ============================================================

import os
import sys
import sqlite3
import json
import threading

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
    MONGO_URI,
    MONGO_DB,
    SQLITE_PATH,
)


# ============================================================
# MONGODB
#
# MongoDB remains optional.
#
# IMPORTANT:
# Dashboard/history reads use SQLite as the authoritative
# source so MongoDB cannot make old/stale history reappear.
# ============================================================

try:

    from pymongo import MongoClient

    _client = MongoClient(
        MONGO_URI,
        serverSelectionTimeoutMS=3000,
    )

    _client.server_info()

    _db = _client[MONGO_DB]

    detections_col = _db[
        "detections"
    ]

    sessions_col = _db[
        "honeypot_sessions"
    ]

    cti_cache_col = _db[
        "cti_cache"
    ]

    MONGO_OK = True

    print(
        f"[DB] MongoDB connected → {MONGO_DB}"
    )

except Exception as e:

    MONGO_OK = False

    _client = None
    _db = None

    detections_col = None
    sessions_col = None
    cti_cache_col = None

    print(
        "[DB] MongoDB unavailable — SQLite only mode"
    )


# ============================================================
# SQLITE LOCK
#
# Detection events can be generated from background threads.
# ============================================================

_db_lock = threading.RLock()


# ============================================================
# LIVE SESSION COUNTERS
#
# These are intentionally NOT persisted.
#
# They represent the current backend session only.
# Therefore restarting the platform resets them to zero.
# ============================================================

_session_lock = threading.Lock()

_session_detection_count = 0


# ============================================================
# SQLITE CONNECTION
# ============================================================

def _conn():
    """
    Create a SQLite connection.

    timeout:
        Gives another thread time to release the database.

    check_same_thread=False:
        Allows the connection object to be safely used by
        helper functions when required. Connections are still
        created per operation.
    """

    return sqlite3.connect(
        SQLITE_PATH,
        timeout=10,
        check_same_thread=False,
    )


# ============================================================
# SQLITE INITIALIZATION
# ============================================================

def init_sqlite():
    """
    Create required database tables if they do not exist.

    Existing databases are preserved.
    """

    os.makedirs(
        os.path.dirname(SQLITE_PATH)
        or ".",
        exist_ok=True,
    )

    with _db_lock:

        conn = _conn()

        try:

            # ------------------------------------------------
            # Detection table
            # ------------------------------------------------

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS detections(

                    id INTEGER PRIMARY KEY AUTOINCREMENT,

                    event_id TEXT,

                    timestamp TEXT NOT NULL,

                    src_ip TEXT NOT NULL,

                    dst_ip TEXT,

                    attack_type TEXT NOT NULL,

                    severity TEXT NOT NULL,

                    ml_label TEXT,

                    ml_conf REAL,

                    iso_anomaly INTEGER,

                    cti_score REAL,

                    cti_label TEXT,

                    ttp_id TEXT,

                    ttp_tactic TEXT,

                    details TEXT,

                    mitigations TEXT
                )
                """
            )


            # ------------------------------------------------
            # Honeypot sessions
            # ------------------------------------------------

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS honeypot_sessions(

                    id INTEGER PRIMARY KEY AUTOINCREMENT,

                    session_id TEXT,

                    timestamp TEXT,

                    src_ip TEXT,

                    username TEXT,

                    password TEXT,

                    commands TEXT,

                    duration_sec REAL,

                    source TEXT
                )
                """
            )


            # ------------------------------------------------
            # Useful indexes
            # ------------------------------------------------

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_detections_timestamp
                ON detections(timestamp)
                """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_detections_attack_type
                ON detections(attack_type)
                """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_detections_src_ip
                ON detections(src_ip)
                """
            )

            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS
                idx_detections_event_id
                ON detections(event_id)
                """
            )


            conn.commit()

        finally:

            conn.close()


    print(
        f"[DB] SQLite ready → {SQLITE_PATH}"
    )


# ============================================================
# SAVE DETECTION
# ============================================================

def save_detection(event: dict):
    """
    Save one detection.

    SQLite is authoritative for dashboard/history queries.

    Duplicate event IDs are ignored so an event cannot be
    accidentally inserted multiple times.

    Returns:
        True  -> saved
        False -> duplicate or failed
    """

    global _session_detection_count


    if not isinstance(
        event,
        dict
    ):

        print(
            "[DB] Invalid detection event."
        )

        return False


    event_id = event.get(
        "id"
    )

    timestamp = event.get(
        "timestamp",
        datetime.utcnow().isoformat(),
    )

    src_ip = event.get(
        "src_ip"
    )

    dst_ip = event.get(
        "dst_ip"
    )

    attack_type = event.get(
        "attack_type"
    )

    severity = event.get(
        "severity"
    )


    # --------------------------------------------------------
    # Required data validation
    # --------------------------------------------------------

    if not event_id:

        event_id = (
            f"EVT-"
            f"{int(datetime.utcnow().timestamp() * 1000)}"
        )

        event["id"] = event_id


    if not src_ip:
        src_ip = "UNKNOWN"


    if not attack_type:
        attack_type = "UNKNOWN"


    if not severity:
        severity = "MEDIUM"


    details = event.get(
        "details",
        {}
    )

    if not isinstance(
        details,
        dict
    ):

        details = {
            "value": str(details)
        }


    mitigations = event.get(
        "mitigations",
        []
    )

    if not isinstance(
        mitigations,
        list
    ):

        mitigations = [
            str(mitigations)
        ]


    ttp = event.get(
        "ttp",
        {}
    )

    if not isinstance(
        ttp,
        dict
    ):

        ttp = {}


    # ========================================================
    # SQLITE
    # ========================================================

    saved = False

    with _db_lock:

        conn = _conn()

        try:

            # ------------------------------------------------
            # Prevent duplicate event insertion.
            # ------------------------------------------------

            existing = conn.execute(
                """
                SELECT id
                FROM detections
                WHERE event_id = ?
                LIMIT 1
                """,
                (
                    event_id,
                ),
            ).fetchone()


            if existing:

                print(
                    "[DB] Duplicate detection ignored → "
                    f"{event_id}"
                )

                return False


            # ------------------------------------------------
            # Insert
            # ------------------------------------------------

            conn.execute(
                """
                INSERT INTO detections
                (
                    event_id,
                    timestamp,
                    src_ip,
                    dst_ip,
                    attack_type,
                    severity,
                    ml_label,
                    ml_conf,
                    iso_anomaly,
                    cti_score,
                    cti_label,
                    ttp_id,
                    ttp_tactic,
                    details,
                    mitigations
                )
                VALUES
                (
                    ?,?,?,?,?,?,?,?,?,?,?,?,?,?,?
                )
                """,
                (
                    event_id,

                    timestamp,

                    src_ip,

                    dst_ip,

                    attack_type,

                    severity,

                    event.get(
                        "ml_label"
                    ),

                    event.get(
                        "ml_conf"
                    ),

                    1
                    if event.get(
                        "iso_anomaly"
                    )
                    else 0,

                    event.get(
                        "cti_score"
                    ),

                    event.get(
                        "cti_label"
                    ),

                    ttp.get(
                        "tech_id"
                    ),

                    ttp.get(
                        "tactic"
                    ),

                    json.dumps(
                        details,
                        default=str,
                    ),

                    json.dumps(
                        mitigations,
                        default=str,
                    ),
                ),
            )

            conn.commit()

            saved = True

        except Exception as e:

            print(
                f"[DB] SQLite save error: {e}"
            )

        finally:

            conn.close()


    if saved:

        with _session_lock:

            _session_detection_count += 1

        print(
            "[DB] Detection saved → "
            f"{attack_type} "
            f"from {src_ip}"
        )


    # ========================================================
    # MONGODB
    #
    # Optional mirror only.
    #
    # Mongo failures must never stop SQLite/dashboard use.
    # ========================================================

    if (
        saved
        and
        MONGO_OK
        and
        detections_col is not None
    ):

        try:

            document = {

                k: v

                for k, v
                in event.items()

                if k != "_id"

            }

            # Avoid duplicate MongoDB event IDs too.
            detections_col.update_one(
                {
                    "id": event_id
                },
                {
                    "$setOnInsert": document
                },
                upsert=True,
            )

        except Exception as e:

            print(
                f"[DB] Mongo mirror error: {e}"
            )


    return saved


# ============================================================
# UPDATE DETECTION
# ============================================================

def update_detection(
    event_id: str,
    event: dict,
):
    """
    Update an existing detection record.

    This is useful after CTI/risk/forensic enrichment.

    It avoids inserting the same detection a second time.
    """

    if not event_id:
        return False


    if not isinstance(
        event,
        dict
    ):

        return False


    details = event.get(
        "details",
        {}
    )

    if not isinstance(
        details,
        dict
    ):

        details = {
            "value": str(details)
        }


    mitigations = event.get(
        "mitigations",
        []
    )

    if not isinstance(
        mitigations,
        list
    ):

        mitigations = [
            str(mitigations)
        ]


    ttp = event.get(
        "ttp",
        {}
    )

    if not isinstance(
        ttp,
        dict
    ):

        ttp = {}


    updated = False


    with _db_lock:

        conn = _conn()

        try:

            cursor = conn.execute(
                """
                UPDATE detections
                SET
                    timestamp = ?,
                    src_ip = ?,
                    dst_ip = ?,
                    attack_type = ?,
                    severity = ?,
                    ml_label = ?,
                    ml_conf = ?,
                    iso_anomaly = ?,
                    cti_score = ?,
                    cti_label = ?,
                    ttp_id = ?,
                    ttp_tactic = ?,
                    details = ?,
                    mitigations = ?
                WHERE event_id = ?
                """,
                (
                    event.get(
                        "timestamp",
                        datetime.utcnow().isoformat(),
                    ),

                    event.get(
                        "src_ip",
                        "UNKNOWN",
                    ),

                    event.get(
                        "dst_ip",
                    ),

                    event.get(
                        "attack_type",
                        "UNKNOWN",
                    ),

                    event.get(
                        "severity",
                        "MEDIUM",
                    ),

                    event.get(
                        "ml_label"
                    ),

                    event.get(
                        "ml_conf"
                    ),

                    1
                    if event.get(
                        "iso_anomaly"
                    )
                    else 0,

                    event.get(
                        "cti_score"
                    ),

                    event.get(
                        "cti_label"
                    ),

                    ttp.get(
                        "tech_id"
                    ),

                    ttp.get(
                        "tactic"
                    ),

                    json.dumps(
                        details,
                        default=str,
                    ),

                    json.dumps(
                        mitigations,
                        default=str,
                    ),

                    event_id,
                ),
            )

            conn.commit()

            updated = (
                cursor.rowcount > 0
            )

        except Exception as e:

            print(
                f"[DB] Update error: {e}"
            )

        finally:

            conn.close()


    # --------------------------------------------------------
    # MongoDB mirror update
    # --------------------------------------------------------

    if (
        updated
        and
        MONGO_OK
        and
        detections_col is not None
    ):

        try:

            document = {
                k: v
                for k, v
                in event.items()
                if k != "_id"
            }

            detections_col.update_one(
                {
                    "id": event_id
                },
                {
                    "$set": document
                },
                upsert=False,
            )

        except Exception as e:

            print(
                f"[DB] Mongo update error: {e}"
            )


    return updated


# ============================================================
# SAVE HONEYPOT SESSION
# ============================================================

def save_honeypot_session(
    session: dict
):

    try:

        conn = _conn()

        try:

            conn.execute(
                """
                INSERT INTO honeypot_sessions
                (
                    session_id,
                    timestamp,
                    src_ip,
                    username,
                    password,
                    commands,
                    duration_sec,
                    source
                )
                VALUES
                (
                    ?,?,?,?,?,?,?,?
                )
                """,
                (
                    session.get(
                        "session_id"
                    ),

                    session.get(
                        "timestamp",
                        datetime.utcnow().isoformat(),
                    ),

                    session.get(
                        "src_ip"
                    ),

                    session.get(
                        "username"
                    ),

                    session.get(
                        "password"
                    ),

                    json.dumps(
                        session.get(
                            "commands",
                            []
                        ),
                        default=str,
                    ),

                    session.get(
                        "duration_sec",
                        0
                    ),

                    session.get(
                        "source",
                        "cowrie"
                    ),
                ),
            )

            conn.commit()

        finally:

            conn.close()

    except Exception as e:

        print(
            f"[DB] Session error: {e}"
        )


    # --------------------------------------------------------
    # MongoDB
    # --------------------------------------------------------

    if (
        MONGO_OK
        and
        sessions_col is not None
    ):

        try:

            sessions_col.insert_one(
                {
                    k: v
                    for k, v
                    in session.items()
                    if k != "_id"
                }
            )

        except Exception as e:

            print(
                f"[DB] Mongo session error: {e}"
            )


# ============================================================
# GET RECENT DETECTIONS
#
# Historical records only.
#
# IMPORTANT:
# SQLite is authoritative for dashboard history.
# ============================================================

def get_recent_detections(
    limit: int = 50
) -> list:

    try:

        limit = int(
            limit
        )

    except Exception:

        limit = 50


    limit = max(
        1,
        min(
            limit,
            500
        )
    )


    with _db_lock:

        conn = _conn()

        try:

            rows = conn.execute(
                """
                SELECT
                    event_id,
                    timestamp,
                    src_ip,
                    dst_ip,
                    attack_type,
                    severity,
                    ml_label,
                    ml_conf,
                    iso_anomaly,
                    cti_score,
                    cti_label,
                    ttp_id,
                    ttp_tactic,
                    details,
                    mitigations
                FROM detections
                ORDER BY id DESC
                LIMIT ?
                """,
                (
                    limit,
                ),
            ).fetchall()

        except Exception as e:

            print(
                f"[DB] Detection history error: {e}"
            )

            return []

        finally:

            conn.close()


    columns = [

        "event_id",
        "timestamp",
        "src_ip",
        "dst_ip",
        "attack_type",
        "severity",
        "ml_label",
        "ml_conf",
        "iso_anomaly",
        "cti_score",
        "cti_label",
        "ttp_id",
        "ttp_tactic",
        "details",
        "mitigations",

    ]


    results = []


    for row in rows:

        data = dict(
            zip(
                columns,
                row
            )
        )


        # ----------------------------------------------------
        # Decode JSON
        # ----------------------------------------------------

        try:

            data["details"] = json.loads(
                data["details"]
            )

        except Exception:

            pass


        try:

            data["mitigations"] = json.loads(
                data["mitigations"]
            )

        except Exception:

            pass


        # ----------------------------------------------------
        # Compatibility:
        #
        # Some frontend code expects "id".
        # ----------------------------------------------------

        data["id"] = data.get(
            "event_id"
        )


        # ----------------------------------------------------
        # Compatibility aliases
        # ----------------------------------------------------

        data["attack"] = data.get(
            "attack_type"
        )

        data["source_ip"] = data.get(
            "src_ip"
        )

        data["destination_ip"] = data.get(
            "dst_ip"
        )


        results.append(
            data
        )


    return results


# ============================================================
# GET HONEYPOT SESSIONS
# ============================================================

def get_honeypot_sessions(
    limit: int = 20
) -> list:

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


    with _db_lock:

        conn = _conn()

        try:

            rows = conn.execute(
                """
                SELECT
                    session_id,
                    timestamp,
                    src_ip,
                    username,
                    password,
                    commands,
                    duration_sec,
                    source
                FROM honeypot_sessions
                ORDER BY id DESC
                LIMIT ?
                """,
                (
                    limit,
                ),
            ).fetchall()

        except Exception as e:

            print(
                f"[DB] Session read error: {e}"
            )

            return []

        finally:

            conn.close()


    columns = [

        "session_id",
        "timestamp",
        "src_ip",
        "username",
        "password",
        "commands",
        "duration_sec",
        "source",

    ]


    result = []


    for row in rows:

        data = dict(
            zip(
                columns,
                row
            )
        )


        try:

            data["commands"] = json.loads(
                data["commands"]
            )

        except Exception:

            pass


        result.append(
            data
        )


    return result


# ============================================================
# HISTORICAL DETECTION STATS
#
# These statistics include the stored database history.
#
# They intentionally do NOT represent the current runtime
# session only.
# ============================================================

def get_detection_stats():

    try:

        with _db_lock:

            conn = _conn()

            try:

                severity = dict(
                    conn.execute(
                        """
                        SELECT
                            severity,
                            COUNT(*)
                        FROM detections
                        GROUP BY severity
                        """
                    ).fetchall()
                )


                attack_types = dict(
                    conn.execute(
                        """
                        SELECT
                            attack_type,
                            COUNT(*)
                        FROM detections
                        GROUP BY attack_type
                        """
                    ).fetchall()
                )


                total = conn.execute(
                    """
                    SELECT COUNT(*)
                    FROM detections
                    """
                ).fetchone()[0]

            finally:

                conn.close()


        return {

            "total":
                total,

            "by_severity":
                severity,

            "by_type":
                attack_types,

        }


    except Exception as e:

        print(
            f"[DB] Stats error: {e}"
        )

        return {

            "total":
                0,

            "by_severity":
                {},

            "by_type":
                {},

        }


# ============================================================
# CURRENT SESSION DETECTION STATS
#
# Used for live dashboard counters.
# Resets when backend restarts.
# ============================================================

def get_session_detection_count():

    with _session_lock:

        return _session_detection_count


def get_session_detection_stats():

    current_total = (
        get_session_detection_count()
    )


    with _db_lock:

        conn = _conn()

        try:

            # ------------------------------------------------
            # Get events created during this runtime as closely
            # as possible from session start count.
            #
            # The primary live counter is maintained in memory.
            # ------------------------------------------------

            rows = conn.execute(
                """
                SELECT
                    attack_type,
                    COUNT(*)
                FROM detections
                GROUP BY attack_type
                """
            ).fetchall()

        except Exception:

            rows = []

        finally:

            conn.close()


    return {

        "total":
            current_total,

        "by_type":
            dict(rows),

    }


# ============================================================
# CLEAR DETECTIONS
#
# Removes historical detections from SQLite and MongoDB.
#
# IMPORTANT:
# Call intentionally, not automatically at startup.
# ============================================================

def clear_detections():

    global _session_detection_count


    # ========================================================
    # SQLITE
    # ========================================================

    try:

        with _db_lock:

            conn = _conn()

            try:

                conn.execute(
                    "DELETE FROM detections"
                )

                conn.commit()

            finally:

                conn.close()


        print(
            "[DB] SQLite detections cleared"
        )


    except Exception as e:

        print(
            f"[DB] SQLite clear error: {e}"
        )


    # ========================================================
    # MONGODB
    # ========================================================

    if (
        MONGO_OK
        and
        detections_col is not None
    ):

        try:

            result = (
                detections_col.delete_many({})
            )

            print(
                "[DB] MongoDB detections cleared → "
                f"{result.deleted_count}"
            )

        except Exception as e:

            print(
                f"[DB] Mongo clear error: {e}"
            )


    # ========================================================
    # RESET LIVE SESSION COUNTER
    # ========================================================

    with _session_lock:

        _session_detection_count = 0


# ============================================================
# EXPORT CSV
# ============================================================

def export_csv(
    path: str = "reports/detections_export.csv"
) -> str:

    import csv


    directory = (
        os.path.dirname(path)
    )

    if directory:

        os.makedirs(
            directory,
            exist_ok=True
        )


    try:

        with _db_lock:

            conn = _conn()

            try:

                rows = conn.execute(
                    """
                    SELECT
                        event_id,
                        timestamp,
                        src_ip,
                        dst_ip,
                        attack_type,
                        severity,
                        ml_label,
                        ml_conf,
                        iso_anomaly,
                        cti_score,
                        cti_label,
                        ttp_id,
                        ttp_tactic
                    FROM detections
                    ORDER BY id
                    """
                ).fetchall()

            finally:

                conn.close()


        headers = [

            "event_id",
            "timestamp",
            "src_ip",
            "dst_ip",
            "attack_type",
            "severity",
            "ml_label",
            "ml_conf",
            "iso_anomaly",
            "cti_score",
            "cti_label",
            "ttp_id",
            "ttp_tactic",

        ]


        with open(
            path,
            "w",
            newline="",
            encoding="utf-8",
        ) as f:

            writer = csv.writer(
                f
            )

            writer.writerow(
                headers
            )

            writer.writerows(
                rows
            )


        print(
            f"[DB] Exported "
            f"{len(rows)} rows → {path}"
        )

        return path


    except Exception as e:

        print(
            f"[DB] Export error: {e}"
        )

        return ""

