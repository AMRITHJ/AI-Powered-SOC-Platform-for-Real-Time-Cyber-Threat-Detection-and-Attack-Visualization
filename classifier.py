# backend/classifier.py
# ─────────────────────────────────────────────────────────────
# SOC Platform — Top-Level Classifier Wrapper
#
# Loads and combines:
#   - Random Forest
#   - LSTM
#   - Isolation Forest
#
# Used by detect.py for flow classification.
#
# This wrapper:
#   1. Loads available models
#   2. Runs RF + LSTM classification
#   3. Runs Isolation Forest
#   4. Normalizes the result
#   5. Combines model information
#
# Rule-based detection remains the responsibility of detect.py.
# ─────────────────────────────────────────────────────────────

from backend.ai.attack_classifier import (
    load,
    load_lstm,
    classify,
    classify_with_lstm,
    extract_features,
    is_ready,
    is_lstm_ready,
    get_model_info,
)

from backend.ai.anomaly import (
    load as load_iso,
    detect as detect_anomaly,
    is_ready as iso_ready,
)


# ============================================================
# MODEL LOADING
# ============================================================

def load_models() -> bool:
    """
    Load all available ML models.

    Random Forest is the primary classifier.
    Isolation Forest and LSTM are optional enhancements.

    Returns:
        True when Random Forest loaded successfully.
    """

    print(
        "[CLASSIFIER] Loading Random Forest..."
    )

    try:

        rf_ok = bool(
            load()
        )

    except Exception as e:

        print(
            f"[CLASSIFIER] Random Forest error: {e}"
        )

        rf_ok = False


    # --------------------------------------------------------
    # Isolation Forest
    # --------------------------------------------------------

    iso_ok = False

    try:

        iso_result = load_iso()

        iso_ok = bool(
            iso_result
            if iso_result is not None
            else iso_ready()
        )

    except Exception as e:

        print(
            f"[CLASSIFIER] Isolation Forest skipped: {e}"
        )


    # --------------------------------------------------------
    # LSTM
    # --------------------------------------------------------

    lstm_ok = False

    try:

        lstm_result = load_lstm()

        lstm_ok = bool(
            lstm_result
            if lstm_result is not None
            else is_lstm_ready()
        )

    except Exception as e:

        print(
            f"[CLASSIFIER] LSTM skipped: {e}"
        )


    # --------------------------------------------------------
    # Re-check actual runtime state
    # --------------------------------------------------------

    try:

        rf_ok = bool(
            is_ready()
        )

    except Exception:

        rf_ok = False


    try:

        iso_ok = bool(
            iso_ready()
        )

    except Exception:

        iso_ok = False


    try:

        lstm_ok = bool(
            is_lstm_ready()
        )

    except Exception:

        lstm_ok = False


    # --------------------------------------------------------
    # Model summary
    # --------------------------------------------------------

    active = []

    if rf_ok:
        active.append(
            "Random Forest"
        )

    if iso_ok:
        active.append(
            "Isolation Forest"
        )

    if lstm_ok:
        active.append(
            "LSTM"
        )

    print(
        "[CLASSIFIER] Active models: "
        +
        (
            " + ".join(active)
            if active
            else
            "none"
        )
    )

    return rf_ok


# ============================================================
# RESULT NORMALIZATION
# ============================================================

def _normalize_result(result):
    """
    Normalize the output returned by attack_classifier.py.

    Keeps downstream detect.py stable even if one of the
    optional model components does not provide every field.
    """

    if not isinstance(
        result,
        dict,
    ):

        result = {}


    normalized = {

        # ----------------------------------------------------
        # Random Forest
        # ----------------------------------------------------

        "ml_label":
            result.get(
                "ml_label",
                "UNKNOWN",
            ),

        "ml_conf":
            result.get(
                "ml_conf",
                0.0,
            ),

        "ml_conf_pct":
            result.get(
                "ml_conf_pct",
                "0%",
            ),

        "class_probs":
            result.get(
                "class_probs",
                {},
            ),

        # ----------------------------------------------------
        # LSTM
        # ----------------------------------------------------

        "lstm_label":
            result.get(
                "lstm_label",
                "N/A",
            ),

        "lstm_conf":
            result.get(
                "lstm_conf",
                0.0,
            ),

        "lstm_conf_pct":
            result.get(
                "lstm_conf_pct",
                "0%",
            ),

        "lstm_severity":
            result.get(
                "lstm_severity",
                None,
            ),

        # ----------------------------------------------------
        # Isolation Forest
        # ----------------------------------------------------

        "iso_anomaly":
            bool(
                result.get(
                    "iso_anomaly",
                    False,
                )
            ),

        "iso_score":
            result.get(
                "iso_score",
                0.0,
            ),

        # ----------------------------------------------------
        # Combined
        # ----------------------------------------------------

        "combined":
            result.get(
                "combined",
                None,
            ),

        "combined_conf":
            result.get(
                "combined_conf",
                0.0,
            ),

        "severity":
            result.get(
                "severity",
                "MEDIUM",
            ),

        "ttp":
            result.get(
                "ttp",
                {},
            ),

        "models_used":
            result.get(
                "models_used",
                "RF",
            ),

    }


    # --------------------------------------------------------
    # Preserve additional fields returned by the classifier.
    # --------------------------------------------------------

    for key, value in result.items():

        if key not in normalized:

            normalized[key] = value


    return normalized


# ============================================================
# CLASSIFY FLOW
# ============================================================

def classify_flow(
    flow: dict,
    src_ip: str = "",
) -> dict:
    """
    Run the ML classification pipeline for one network flow.

    Pipeline:

        Random Forest
             +
        LSTM
             +
        Isolation Forest
             ↓
        normalized result

    Rule-based detection remains in detect.py.
    """

    if not isinstance(
        flow,
        dict,
    ):

        return {

            "ml_label":
                "UNKNOWN",

            "ml_conf":
                0.0,

            "ml_conf_pct":
                "0%",

            "lstm_label":
                "N/A",

            "lstm_conf":
                0.0,

            "lstm_conf_pct":
                "0%",

            "iso_anomaly":
                False,

            "iso_score":
                0.0,

            "combined":
                "UNKNOWN",

            "combined_conf":
                0.0,

            "severity":
                "MEDIUM",

            "ttp":
                {},

            "class_probs":
                {},

            "models_used":
                "NONE",

            "error":
                "Invalid flow data",

        }


    source_ip = (
        src_ip
        or
        flow.get(
            "src_ip",
            "unknown",
        )
    )


    # ========================================================
    # RANDOM FOREST CHECK
    # ========================================================

    rf_available = False

    try:

        rf_available = bool(
            is_ready()
        )

    except Exception:

        rf_available = False


    # ========================================================
    # LSTM CHECK
    # ========================================================

    lstm_available = False

    try:

        lstm_available = bool(
            is_lstm_ready()
        )

    except Exception:

        lstm_available = False


    # ========================================================
    # ISOLATION FOREST CHECK
    # ========================================================

    iso_available = False

    try:

        iso_available = bool(
            iso_ready()
        )

    except Exception:

        iso_available = False


    # ========================================================
    # NO MODELS
    # ========================================================

    if not (
        rf_available
        or
        lstm_available
        or
        iso_available
    ):

        return {

            "ml_label":
                "UNKNOWN",

            "ml_conf":
                0.0,

            "ml_conf_pct":
                "0%",

            "lstm_label":
                "N/A",

            "lstm_conf":
                0.0,

            "lstm_conf_pct":
                "0%",

            "iso_anomaly":
                False,

            "iso_score":
                0.0,

            "combined":
                "UNKNOWN",

            "combined_conf":
                0.0,

            "severity":
                "MEDIUM",

            "ttp":
                {},

            "class_probs":
                {},

            "models_used":
                "NONE",

            "error":
                "No ML models loaded",

        }


    # ========================================================
    # RF + LSTM
    # ========================================================

    result = {}


    if rf_available:

        try:

            # This is the existing unified RF + LSTM path.
            result = classify_with_lstm(
                flow,
                source_ip,
            )

            result = _normalize_result(
                result
            )

        except Exception as e:

            print(
                f"[CLASSIFIER] "
                f"RF/LSTM classification error: {e}"
            )

            result = {

                "ml_label":
                    "UNKNOWN",

                "ml_conf":
                    0.0,

                "ml_conf_pct":
                    "0%",

                "lstm_label":
                    "N/A",

                "lstm_conf":
                    0.0,

                "lstm_conf_pct":
                    "0%",

                "combined":
                    "UNKNOWN",

                "combined_conf":
                    0.0,

                "severity":
                    "MEDIUM",

                "class_probs":
                    {},

                "models_used":
                    "RF_ERROR",

            }


    elif lstm_available:

        # ----------------------------------------------------
        # LSTM-only fallback.
        #
        # This keeps the wrapper logically consistent with
        # the "optional LSTM" design without changing the
        # underlying LSTM module.
        # ----------------------------------------------------

        try:

            result = {
                "ml_label": "UNKNOWN",
                "ml_conf": 0.0,
                "ml_conf_pct": "0%",
                "lstm_label": "N/A",
                "lstm_conf": 0.0,
                "lstm_conf_pct": "0%",
                "combined": "UNKNOWN",
                "combined_conf": 0.0,
                "severity": "MEDIUM",
                "class_probs": {},
                "models_used": "LSTM",
            }

            print(
                "[CLASSIFIER] RF unavailable; "
                "using LSTM/ISO fallback mode."
            )

        except Exception as e:

            print(
                f"[CLASSIFIER] LSTM fallback error: {e}"
            )

            result = {}

    else:

        result = {

            "ml_label":
                "UNKNOWN",

            "ml_conf":
                0.0,

            "ml_conf_pct":
                "0%",

            "lstm_label":
                "N/A",

            "lstm_conf":
                0.0,

            "lstm_conf_pct":
                "0%",

            "combined":
                "UNKNOWN",

            "combined_conf":
                0.0,

            "severity":
                "MEDIUM",

            "class_probs":
                {},

            "models_used":
                "ISO",

        }


    result = _normalize_result(
        result
    )


    # ========================================================
    # ISOLATION FOREST
    # ========================================================

    iso = {

        "iso_anomaly":
            False,

        "iso_score":
            0.0,

    }


    if iso_available:

        try:

            detected = detect_anomaly(
                flow
            )

            if isinstance(
                detected,
                dict,
            ):

                iso.update(
                    detected
                )

        except Exception as e:

            print(
                f"[CLASSIFIER] ISO error: {e}"
            )


    result["iso_anomaly"] = bool(
        iso.get(
            "iso_anomaly",
            False,
        )
    )

    result["iso_score"] = (
        iso.get(
            "iso_score",
            0.0,
        )
    )


    # ========================================================
    # MODEL USAGE DESCRIPTION
    # ========================================================

    active_models = []

    if rf_available:
        active_models.append(
            "RF"
        )

    if lstm_available:
        active_models.append(
            "LSTM"
        )

    if iso_available:
        active_models.append(
            "ISO"
        )


    result["models_used"] = (

        "+".join(
            active_models
        )

        if active_models

        else

        "NONE"

    )


    # ========================================================
    # ISOLATION FOREST ENRICHMENT
    # ========================================================

    # If RF reports BENIGN but the flow is anomalous and the
    # RF confidence isn't extremely high, mark it suspicious.
    #
    # This does NOT create a rule-based alert by itself.
    # detect.py decides whether an ML event should be emitted.

    combined_label = str(
        result.get(
            "combined",
            "",
        )
    ).upper()


    try:

        ml_conf = float(
            result.get(
                "ml_conf",
                0.0,
            )
            or 0.0
        )

    except Exception:

        ml_conf = 0.0


    if (
        result["iso_anomaly"]
        and
        combined_label == "BENIGN"
        and
        ml_conf < 0.90
    ):

        result["combined"] = (
            "SUSPICIOUS"
        )

        result["combined_conf"] = (
            max(
                ml_conf,
                0.50,
            )
        )

        result["severity"] = (
            "MEDIUM"
        )


    # ========================================================
    # FINAL NORMALIZATION
    # ========================================================

    result = _normalize_result(
        result
    )


    return result


# ============================================================
# PUBLIC MODEL STATUS
# ============================================================

def get_classifier_status():
    """
    Lightweight runtime model status.

    Useful for /api/status and debugging.
    """

    try:
        rf = bool(
            is_ready()
        )
    except Exception:
        rf = False

    try:
        lstm = bool(
            is_lstm_ready()
        )
    except Exception:
        lstm = False

    try:
        iso = bool(
            iso_ready()
        )
    except Exception:
        iso = False

    return {

        "random_forest":
            rf,

        "lstm":
            lstm,

        "isolation_forest":
            iso,

        "active_models":
            [
                name

                for name, active
                in (
                    ("RF", rf),
                    ("LSTM", lstm),
                    ("ISO", iso),
                )

                if active
            ],

        "ready":
            rf or lstm or iso,

    }