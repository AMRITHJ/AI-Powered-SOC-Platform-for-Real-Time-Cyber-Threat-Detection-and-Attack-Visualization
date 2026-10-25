/* ============================================================
   SOC PLATFORM — SOCKET.IO CLIENT
   frontend/socket.js

   RESPONSIBILITIES
   ------------------------------------------------------------
   - Real-time Socket.IO connection
   - Live detections
   - Security alerts
   - Packet statistics
   - Traffic updates
   - Device updates
   - Topology updates
   - Honeypot / Canary updates
   - Detection history

   LIVE OWNERSHIP
   ------------------------------------------------------------
   new_detection
       -> authoritative LIVE detection
       -> charts.js owns live threat count/distribution/timeline/risk

   enriched new_detection
       -> same event
       -> risk / CTI update only

   packet_stats / packet
       -> packet counter
       -> traffic chart

   history
       -> stored only
       -> NEVER injected into live alerts/charts/map automatically

   alert / threat
       -> display only
       -> NEVER increments live threat counter

   SESSION RULE
   ------------------------------------------------------------
   - Browser refresh does NOT reset backend packet count.
   - Socket reconnect does NOT reset backend packet count.
   - Current-session filtering is based on charts.js backend
     monitoring session (capture_started_at).
   ============================================================ */

"use strict";


/* ============================================================
   SOCKET CONNECTION / STATE
   ============================================================ */

let socSocket = null;

const SOCKET_SERVER =
    "http://127.0.0.1:5000";

const processedDetectionIds =
    new Set();

const enrichedDetectionIds =
    new Set();

const renderedAlertIds =
    new Set();

const MAX_PROCESSED_IDS =
    500;

const MAX_ALERT_IDS =
    500;

let historicalDetections =
    [];


/* ============================================================
   GENERIC HELPERS
   ============================================================ */

function normalizeAttackType(
    value
) {

    return String(
        value ?? ""
    )
        .trim()
        .toLowerCase()
        .replace(
            /[\s_-]+/g,
            ""
        );
}


function isBenignDetection(
    data
) {

    if (!data) {

        return false;
    }


    const attack =
        normalizeAttackType(
            data.attack_type ??
            data.attack ??
            data.label ??
            data.threat ??
            data.ml_label ??
            ""
        );


    return (
        attack === "benign" ||
        attack === "normal"
    );
}


function isEnrichedDetection(
    data
) {

    if (!data) {

        return false;
    }


    const stage =
        String(
            data.processing_stage ??
            data.stage ??
            ""
        )
            .trim()
            .toLowerCase();


    return (
        stage === "enriched"
    );
}


function getDetectionId(
    data
) {

    if (!data) {

        return null;
    }


    const explicitId =
        data.id ??
        data.detection_id ??
        data.event_id;


    if (
        explicitId !== undefined &&
        explicitId !== null &&
        String(explicitId).trim() !== ""
    ) {

        return String(
            explicitId
        );
    }


    const timestamp =
        data.timestamp ??
        data.time ??
        data.created_at ??
        "";


    const source =
        data.src_ip ??
        data.source_ip ??
        data.src ??
        "";


    const destination =
        data.dst_ip ??
        data.destination_ip ??
        data.dst ??
        "";


    const attack =
        data.attack_type ??
        data.attack ??
        data.label ??
        data.threat ??
        data.ml_label ??
        "";


    const fallback =
        [
            timestamp,
            source,
            destination,
            attack
        ]
            .map(
                value =>
                    String(
                        value ?? ""
                    )
            )
            .join("|");


    return fallback !== "|||"
        ? fallback
        : null;
}


function trimSet(
    set,
    maximum
) {

    while (
        set.size >
        maximum
    ) {

        const first =
            set
                .values()
                .next()
                .value;


        if (
            first === undefined
        ) {

            break;
        }


        set.delete(
            first
        );
    }
}


function trimDetectionCache() {

    trimSet(
        processedDetectionIds,
        MAX_PROCESSED_IDS
    );


    trimSet(
        enrichedDetectionIds,
        MAX_PROCESSED_IDS
    );
}


function trimAlertCache() {

    trimSet(
        renderedAlertIds,
        MAX_ALERT_IDS
    );
}


function isCurrentMonitoringEvent(
    data
) {

    if (!data) {

        return false;
    }


    if (
        window.socCharts &&
        typeof window.socCharts
            .isEventInCurrentMonitoringSession ===
        "function"
    ) {

        try {

            return !!window.socCharts
                .isEventInCurrentMonitoringSession(
                    data
                );

        } catch (error) {

            console.warn(
                "[SOCKET] Session filter failed:",
                error.message
            );
        }
    }


    /*
     * If charts.js has not established the backend session yet,
     * real-time socket events are treated as live.
     */
    return true;
}


function formatSocketTime(
    value = null
) {

    if (
        typeof window.formatSOCLiveTime ===
        "function"
    ) {

        try {

            return window.formatSOCLiveTime(
                value
            );

        } catch (error) {

            console.warn(
                "[SOCKET] Shared time formatter failed:",
                error.message
            );
        }
    }


    if (
        window.socCharts &&
        typeof window.socCharts
            .getTimeLabel ===
        "function"
    ) {

        try {

            return window.socCharts
                .getTimeLabel(
                    value
                );

        } catch (error) {

            console.warn(
                "[SOCKET] Charts time formatter failed:",
                error.message
            );
        }
    }


    if (!value) {

        return new Date()
            .toLocaleTimeString(
                [],
                {
                    hour: "2-digit",
                    minute: "2-digit",
                    second: "2-digit"
                }
            );
    }


    let timestamp =
        value;


    if (
        typeof value ===
        "number"
    ) {

        timestamp =
            value < 1000000000000
                ? value * 1000
                : value;

    } else {

        timestamp =
            String(
                value
            )
                .trim();


        if (
            /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/
                .test(
                    timestamp
                )
            &&
            !/[zZ]$/
                .test(
                    timestamp
                )
            &&
            !/[+-]\d{2}:?\d{2}$/
                .test(
                    timestamp
                )
        ) {

            timestamp +=
                "Z";
        }
    }


    const date =
        new Date(
            timestamp
        );


    if (
        Number.isNaN(
            date.getTime()
        )
    ) {

        return new Date()
            .toLocaleTimeString(
                [],
                {
                    hour: "2-digit",
                    minute: "2-digit",
                    second: "2-digit"
                }
            );
    }


    return date
        .toLocaleTimeString(
            [],
            {
                hour: "2-digit",
                minute: "2-digit",
                second: "2-digit"
            }
        );
}


function escapeSocketHTML(
    value
) {

    return String(
        value ?? ""
    )
        .replace(
            /&/g,
            "&amp;"
        )
        .replace(
            /</g,
            "&lt;"
        )
        .replace(
            />/g,
            "&gt;"
        )
        .replace(
            /"/g,
            "&quot;"
        )
        .replace(
            /'/g,
            "&#039;"
        );
}


function setSocketElement(
    id,
    value
) {

    const element =
        document.getElementById(
            id
        );


    if (element) {

        element.textContent =
            value;
    }
}


/* ============================================================
   SOCKET INITIALIZATION
   ============================================================ */

function initializeSocket() {

    if (
        typeof io ===
        "undefined"
    ) {

        console.error(
            "[SOCKET] Socket.IO library not loaded."
        );


        updateSocketStatus(
            false
        );


        return;
    }


    if (
        socSocket &&
        (
            socSocket.connected ||
            socSocket.active
        )
    ) {

        console.log(
            "[SOCKET] Socket already initialized."
        );


        return;
    }


    console.log(
        "[SOCKET] Connecting to:",
        SOCKET_SERVER
    );


    socSocket =
        io(
            SOCKET_SERVER,
            {

                transports: [
                    "websocket",
                    "polling"
                ],

                reconnection:
                    true,

                reconnectionAttempts:
                    Infinity,

                reconnectionDelay:
                    2000,

                reconnectionDelayMax:
                    10000,

                timeout:
                    5000
            }
        );


    /* ========================================================
       CONNECTED
       ======================================================== */

    socSocket.on(
        "connect",
        () => {

            console.log(
                "[SOCKET] Connected:",
                socSocket.id
            );


            updateSocketStatus(
                true
            );


            /*
             * DO NOT automatically request SQLite history.
             *
             * A socket reconnect continues the current backend
             * monitoring session.
             */
        }
    );


    /* ========================================================
       SERVER READY
       ======================================================== */

    socSocket.on(
        "server_ready",
        data => {

            console.log(
                "[SOCKET] Server ready:",
                data
            );


            updateSocketStatus(
                true
            );


            if (
                data &&
                data.model
            ) {

                console.log(
                    "[SOCKET] AI model:",
                    data.model
                );
            }
        }
    );


    /* ========================================================
       DISCONNECT / RECONNECT
       ======================================================== */

    socSocket.on(
        "disconnect",
        reason => {

            console.warn(
                "[SOCKET] Disconnected:",
                reason
            );


            updateSocketStatus(
                false
            );
        }
    );


    socSocket.on(
        "connect_error",
        error => {

            console.error(
                "[SOCKET] Connection error:",
                error.message
            );


            updateSocketStatus(
                false
            );
        }
    );


    socSocket.io.on(
        "reconnect_attempt",
        attempt => {

            console.log(
                "[SOCKET] Reconnection attempt:",
                attempt
            );
        }
    );


    socSocket.io.on(
        "reconnect",
        attempt => {

            console.log(
                "[SOCKET] Reconnected after attempt:",
                attempt
            );


            updateSocketStatus(
                true
            );


            /*
             * Reconnection is NOT a new monitoring session.
             * Do not clear packet counts or request old history.
             */
        }
    );


    socSocket.io.on(
        "reconnect_error",
        error => {

            console.warn(
                "[SOCKET] Reconnection error:",
                error.message
            );


            updateSocketStatus(
                false
            );
        }
    );


    /* ========================================================
       LIVE EVENTS
       ======================================================== */

    socSocket.on(
        "new_detection",
        data => {

            console.log(
                "[SOCKET] New detection:",
                data
            );


            handleDetectionEvent(
                data
            );
        }
    );


    socSocket.on(
        "alert",
        data => {

            console.log(
                "[SOCKET] Alert:",
                data
            );


            handleAlertEvent(
                data
            );
        }
    );


    socSocket.on(
        "threat",
        data => {

            console.log(
                "[SOCKET] Threat:",
                data
            );


            handleThreatEvent(
                data
            );
        }
    );


    socSocket.on(
        "packet",
        data => {

            handlePacketEvent(
                data
            );
        }
    );


    socSocket.on(
        "packet_stats",
        data => {

            handlePacketStatsEvent(
                data
            );
        }
    );


    socSocket.on(
        "traffic",
        data => {

            handleTrafficEvent(
                data
            );
        }
    );


    socSocket.on(
        "device",
        data => {

            handleDeviceEvent(
                data
            );
        }
    );


    socSocket.on(
        "topology",
        data => {

            handleTopologyEvent(
                data
            );
        }
    );


    socSocket.on(
        "honeypot_session",
        data => {

            handleHoneypotEvent(
                data
            );
        }
    );


    socSocket.on(
        "canary_trigger",
        data => {

            handleCanaryEvent(
                data
            );
        }
    );


    socSocket.on(
        "history",
        data => {

            handleHistoryEvent(
                data
            );
        }
    );
}


/* ============================================================
   HISTORY REQUEST
   ============================================================ */

function requestHistory() {

    if (
        !socSocket ||
        !socSocket.connected
    ) {

        return;
    }


    try {

        socSocket.emit(
            "request_history",
            {
                limit: 20
            }
        );


        console.log(
            "[SOCKET] Detection history requested."
        );

    } catch (error) {

        console.warn(
            "[SOCKET] History request failed:",
            error.message
        );
    }
}


/* ============================================================
   AUTHORITATIVE LIVE DETECTION
   ============================================================ */

function handleDetectionEvent(
    data
) {

    if (!data) {

        return;
    }


    /*
     * Reject previous-backend-session events before they touch
     * the alert panel, charts, map, CTI, or de-duplication state.
     */
    if (
        !isCurrentMonitoringEvent(
            data
        )
    ) {

        console.log(
            "[SOCKET] Previous-session detection ignored:",
            getDetectionId(
                data
            )
        );


        return;
    }


    const detectionId =
        getDetectionId(
            data
        );


    const enriched =
        isEnrichedDetection(
            data
        );


    /* ========================================================
       ENRICHED STAGE
       ======================================================== */

    if (enriched) {

        if (
            detectionId &&
            enrichedDetectionIds.has(
                detectionId
            )
        ) {

            console.log(
                "[SOCKET] Duplicate enriched detection ignored:",
                detectionId
            );


            return;
        }


        if (
            detectionId
        ) {

            enrichedDetectionIds.add(
                detectionId
            );
        }


        trimDetectionCache();


        if (
            detectionId &&
            !processedDetectionIds.has(
                detectionId
            )
        ) {

            console.warn(
                "[SOCKET] Enriched event received before initial event:",
                detectionId
            );
        }


        /*
         * Enriched stage updates risk + CTI only.
         */
        updateRiskFromDetection(
            data
        );


        updateThreatIntelligence(
            data
        );


        return;
    }


    /* ========================================================
       DUPLICATE INITIAL
       ======================================================== */

    if (
        detectionId &&
        processedDetectionIds.has(
            detectionId
        )
    ) {

        console.log(
            "[SOCKET] Duplicate initial detection ignored:",
            detectionId
        );


        return;
    }


    if (
        detectionId
    ) {

        processedDetectionIds.add(
            detectionId
        );
    }


    trimDetectionCache();


    if (
        isBenignDetection(
            data
        )
    ) {

        console.log(
            "[SOCKET] Benign event ignored for threats."
        );


        return;
    }


    /*
     * Register with api.js if it is available.
     * This stores current-session detections only and does not
     * own charts/counters.
     */
    if (
        window.API &&
        typeof window.API
            .registerLiveDetection ===
        "function"
    ) {

        try {

            window.API
                .registerLiveDetection(
                    data
                );

        } catch (error) {

            console.warn(
                "[SOCKET] API live registration failed:",
                error.message
            );
        }
    }


    /* ========================================================
       MAP
       ======================================================== */

    if (
        typeof window.addAttackLocation ===
        "function"
    ) {

        try {

            window.addAttackLocation(
                data
            );

        } catch (error) {

            console.warn(
                "[SOCKET] Map update failed:",
                error.message
            );
        }
    }


    /* ========================================================
       ALERT
       ======================================================== */

    addLiveAlert(
        data
    );


    /* ========================================================
       LIVE CHARTS
       ======================================================== */

    processDetectionForCharts(
        data
    );


    /* ========================================================
       CTI
       ======================================================== */

    updateThreatIntelligence(
        data
    );
}


/* ============================================================
   CHART DETECTION BRIDGE
   ============================================================ */

function processDetectionForCharts(
    data
) {

    if (!data) {

        return;
    }


    if (
        window.socCharts &&
        typeof window.socCharts
            .processDetectionEvent ===
        "function"
    ) {

        try {

            window.socCharts
                .processDetectionEvent(
                    data
                );


            return;

        } catch (error) {

            console.warn(
                "[SOCKET] Charts detection update failed:",
                error.message
            );
        }
    }


    /*
     * Compatibility fallback.
     */
    const score =
        getThreatScore(
            data
        );


    const timestamp =
        data.timestamp ??
        data.time ??
        data.created_at ??
        null;


    if (
        typeof window.updateThreatTimeline ===
        "function"
    ) {

        try {

            window.updateThreatTimeline(
                score,
                timestamp
            );

        } catch (error) {

            console.warn(
                "[SOCKET] Timeline fallback failed:",
                error.message
            );
        }
    }


    if (
        typeof window.updateAttackCharts ===
        "function"
    ) {

        try {

            window.updateAttackCharts(
                data
            );

        } catch (error) {

            console.warn(
                "[SOCKET] Attack chart fallback failed:",
                error.message
            );
        }
    }
}


/* ============================================================
   THREAT SCORE / RISK
   ============================================================ */

function getThreatScore(
    data
) {

    if (!data) {

        return 0;
    }


    let score =
        data.risk_score ??
        data.threat_score ??
        data.cti_score ??
        data.combined_conf ??
        data.ml_conf ??
        data.lstm_conf;


    if (
        score === undefined ||
        score === null
    ) {

        const severity =
            String(
                data.severity ??
                ""
            )
                .trim()
                .toUpperCase();


        switch (severity) {

            case "CRITICAL":
                score = 100;
                break;

            case "HIGH":
                score = 80;
                break;

            case "MEDIUM":
                score = 60;
                break;

            case "LOW":
                score = 30;
                break;

            case "INFO":
                score = 10;
                break;

            default:
                score = 0;
        }
    }


    score =
        Number(
            score
        );


    if (
        !Number.isFinite(
            score
        )
    ) {

        score = 0;
    }


    if (
        score > 0 &&
        score <= 1
    ) {

        score *=
            100;
    }


    return Math.max(
        0,
        Math.min(
            100,
            score
        )
    );
}


function updateRiskFromDetection(
    data
) {

    if (!data) {

        return;
    }


    if (
        !isCurrentMonitoringEvent(
            data
        )
    ) {

        return;
    }


    const score =
        getThreatScore(
            data
        );


    const riskElement =
        document.getElementById(
            "riskScore"
        );


    if (riskElement) {

        riskElement.textContent =
            Math.round(
                score
            );
    }


    if (
        window.socCharts &&
        typeof window.socCharts
            .updateThreatLevel ===
        "function"
    ) {

        try {

            window.socCharts
                .updateThreatLevel(
                    score,
                    data.severity
                );


            return;

        } catch (error) {

            console.warn(
                "[SOCKET] Threat level update failed:",
                error.message
            );
        }
    }


    if (
        typeof window.updateThreatLevel ===
        "function"
    ) {

        try {

            window.updateThreatLevel(
                score,
                data.severity
            );

        } catch (error) {

            console.warn(
                "[SOCKET] Legacy threat level update failed:",
                error.message
            );
        }
    }
}


/* ============================================================
   THREAT INTELLIGENCE BRIDGE
   ============================================================ */

function updateThreatIntelligence(
    data
) {

    if (!data) {

        return;
    }


    if (
        !isCurrentMonitoringEvent(
            data
        )
    ) {

        return;
    }


    if (
        window.socCharts &&
        typeof window.socCharts
            .updateThreatIntelligence ===
        "function"
    ) {

        try {

            window.socCharts
                .updateThreatIntelligence(
                    data
                );


            return;

        } catch (error) {

            console.warn(
                "[SOCKET] CTI dashboard update failed:",
                error.message
            );
        }
    }


    if (
        typeof window.updateThreatIntelligence ===
        "function" &&
        window.updateThreatIntelligence !==
            updateThreatIntelligence
    ) {

        try {

            window.updateThreatIntelligence(
                data
            );

        } catch (error) {

            console.warn(
                "[SOCKET] Legacy CTI update failed:",
                error.message
            );
        }
    }
}


/* ============================================================
   AUXILIARY ALERT / THREAT EVENTS
   ============================================================ */

function handleAlertEvent(
    data
) {

    if (
        !data ||
        !isCurrentMonitoringEvent(
            data
        )
    ) {

        return;
    }


    /*
     * Display only.
     * This event must never increment charts.js live threat count.
     */
    addLiveAlert(
        data
    );
}


function handleThreatEvent(
    data
) {

    if (
        !data ||
        !isCurrentMonitoringEvent(
            data
        )
    ) {

        return;
    }


    console.log(
        "[SOCKET] Auxiliary threat event:",
        data
    );


    /*
     * Display / CTI only.
     * No live counter increment.
     */
    addLiveAlert(
        data
    );


    updateThreatIntelligence(
        data
    );
}


/* ============================================================
   PACKET EVENTS
   ============================================================ */

function handlePacketEvent(
    data
) {

    if (!data) {

        return;
    }


    const total =
        data.total ??
        data.total_packets ??
        data.packet_count ??
        data.count;


    if (
        total !== undefined &&
        Number.isFinite(
            Number(
                total
            )
        )
    ) {

        updatePacketCounter(
            Number(
                total
            )
        );
    }


    processTrafficForCharts(
        data
    );
}


function handlePacketStatsEvent(
    data
) {

    if (!data) {

        return;
    }


    const total =
        data.total ??
        data.total_packets ??
        data.packet_count;


    if (
        total !== undefined &&
        Number.isFinite(
            Number(
                total
            )
        )
    ) {

        updatePacketCounter(
            Number(
                total
            )
        );
    }


    processTrafficForCharts(
        data
    );
}


function updatePacketCounter(
    total
) {

    const value =
        Number(
            total
        );


    if (
        !Number.isFinite(
            value
        )
    ) {

        return;
    }


    const formatted =
        value.toLocaleString();


    setSocketElement(
        "packetCount",
        formatted
    );


    setSocketElement(
        "packets",
        formatted
    );
}


/* ============================================================
   TRAFFIC
   ============================================================ */

function handleTrafficEvent(
    data
) {

    if (!data) {

        return;
    }


    processTrafficForCharts(
        data
    );
}


function processTrafficForCharts(
    data
) {

    if (!data) {

        return;
    }


    if (
        window.socCharts &&
        typeof window.socCharts
            .processTrafficEvent ===
        "function"
    ) {

        try {

            window.socCharts
                .processTrafficEvent(
                    data
                );


            return;

        } catch (error) {

            console.warn(
                "[SOCKET] Traffic chart update failed:",
                error.message
            );
        }
    }


    /*
     * Compatibility fallback.
     */
    if (
        typeof window.updateTrafficChart ===
        "function"
    ) {

        const incoming =
            Number(
                data.incoming ??
                data.incoming_pps ??
                data.in_bytes ??
                data.incoming_bytes ??
                data.rx ??
                data.received ??
                0
            );


        const outgoing =
            Number(
                data.outgoing ??
                data.outgoing_pps ??
                data.out_bytes ??
                data.outgoing_bytes ??
                data.tx ??
                data.sent ??
                0
            );


        const timestamp =
            data.timestamp ??
            data.time ??
            null;


        try {

            window.updateTrafficChart(
                Number.isFinite(
                    incoming
                )
                    ? incoming
                    : 0,

                Number.isFinite(
                    outgoing
                )
                    ? outgoing
                    : 0,

                timestamp
            );

        } catch (error) {

            console.warn(
                "[SOCKET] Traffic fallback failed:",
                error.message
            );
        }
    }
}


/* ============================================================
   DEVICE EVENT
   ============================================================ */

function handleDeviceEvent(
    data
) {

    if (!data) {

        return;
    }


    console.log(
        "[SOCKET] Device update:",
        data
    );


    let deviceList =
        [];


    if (
        Array.isArray(
            data
        )
    ) {

        deviceList =
            data;

    } else if (
        Array.isArray(
            data.devices
        )
    ) {

        deviceList =
            data.devices;

    } else if (
        Array.isArray(
            data.data
        )
    ) {

        deviceList =
            data.data;
    }


    if (
        typeof window.updateDevices ===
        "function"
    ) {

        try {

            window.updateDevices(
                deviceList
            );

        } catch (error) {

            console.warn(
                "[SOCKET] Device UI update failed:",
                error.message
            );
        }
    }


    let count =
        data.count ??
        data.device_count ??
        data.connected_devices;


    if (
        count === undefined ||
        count === null
    ) {

        count =
            deviceList.length;
    }


    const numericCount =
        Number(
            count
        );


    if (
        Number.isFinite(
            numericCount
        )
    ) {

        const formatted =
            numericCount
                .toLocaleString();


        setSocketElement(
            "deviceCount",
            formatted
        );


        setSocketElement(
            "devices",
            formatted
        );
    }
}


/* ============================================================
   TOPOLOGY EVENT
   ============================================================ */

function handleTopologyEvent(
    data
) {

    if (!data) {

        return;
    }


    console.log(
        "[SOCKET] Network topology update:",
        data
    );


    if (
        window.Topology &&
        typeof window.Topology.update ===
        "function"
    ) {

        try {

            window.Topology.update(
                data
            );


            return;

        } catch (error) {

            console.warn(
                "[SOCKET] Topology.update failed:",
                error.message
            );
        }
    }


    if (
        typeof window.renderTopology ===
        "function"
    ) {

        try {

            window.renderTopology(
                data
            );

        } catch (error) {

            console.warn(
                "[SOCKET] Legacy topology update failed:",
                error.message
            );
        }
    }
}


/* ============================================================
   HONEYPOT / CANARY
   ============================================================ */

function handleHoneypotEvent(
    data
) {

    if (
        !data ||
        !isCurrentMonitoringEvent(
            data
        )
    ) {

        return;
    }


    console.log(
        "[SOCKET] Honeypot activity:",
        data
    );


    addLiveAlert({

        id:
            data.id ??
            data.event_id ??
            data.session_id,

        attack:
            data.attack ??
            data.attack_type ??
            "HONEYPOT ACTIVITY",

        severity:
            data.severity ??
            "HIGH",

        src_ip:
            data.src_ip ??
            data.source_ip ??
            "Unknown",

        dst_ip:
            data.dst_ip ??
            data.destination_ip ??
            "Honeypot",

        timestamp:
            data.timestamp ??
            data.time ??
            null
    });
}


function handleCanaryEvent(
    data
) {

    if (
        !data ||
        !isCurrentMonitoringEvent(
            data
        )
    ) {

        return;
    }


    console.log(
        "[SOCKET] Canary triggered:",
        data
    );


    addLiveAlert({

        id:
            data.id ??
            data.event_id,

        attack:
            data.attack ??
            data.attack_type ??
            "CANARY TRIGGERED",

        severity:
            data.severity ??
            "CRITICAL",

        src_ip:
            data.src_ip ??
            data.source_ip ??
            "Unknown",

        dst_ip:
            data.dst_ip ??
            data.destination_ip ??
            "Canary Sensor",

        timestamp:
            data.timestamp ??
            data.time ??
            null
    });
}


/* ============================================================
   HISTORY
   ============================================================ */

function handleHistoryEvent(
    data
) {

    if (
        !Array.isArray(
            data
        )
    ) {

        console.warn(
            "[SOCKET] Invalid history payload."
        );


        return;
    }


    /*
     * HISTORY IS STORED ONLY.
     *
     * It is never automatically rendered inside #alerts and never
     * enters live charts/counter/map.
     */
    historicalDetections =
        data.slice();


    console.log(
        "[SOCKET] Historical detections stored:",
        historicalDetections.length
    );
}


function displayHistoricalAlerts(
    detections
) {

    /*
     * Compatibility only.
     * Old database alerts are intentionally not rendered.
     */
    if (
        Array.isArray(
            detections
        )
    ) {

        historicalDetections =
            detections.slice();
    }


    console.log(
        "[SOCKET] Historical alert rendering suppressed for live dashboard."
    );
}


function createHistoricalAlertHTML(
    data
) {

    const attack =
        data?.attack ??
        data?.attack_type ??
        data?.label ??
        data?.threat ??
        "Unknown Threat";


    const severity =
        data?.severity ??
        "INFO";


    const source =
        data?.src_ip ??
        data?.source_ip ??
        "Unknown";


    const destination =
        data?.dst_ip ??
        data?.destination_ip ??
        "Unknown";


    const timestamp =
        data?.timestamp ??
        data?.time ??
        "Unknown";


    return `

        <div class="alert historical-alert">

            <strong>
                ${escapeSocketHTML(
                    attack
                )}
            </strong>

            <br>

            <span>
                ${escapeSocketHTML(
                    source
                )}
                →
                ${escapeSocketHTML(
                    destination
                )}
            </span>

            <br>

            <small>
                HISTORICAL |
                ${escapeSocketHTML(
                    severity
                )}
                |
                ${escapeSocketHTML(
                    timestamp
                )}
            </small>

        </div>
    `;
}


/* ============================================================
   LIVE SECURITY ALERT
   ============================================================ */

function addLiveAlert(
    data
) {

    if (!data) {

        return;
    }


    if (
        !isCurrentMonitoringEvent(
            data
        )
    ) {

        console.log(
            "[SOCKET] Previous-session alert ignored:",
            getDetectionId(
                data
            )
        );


        return;
    }


    const container =
        document.getElementById(
            "alerts"
        );


    if (!container) {

        return;
    }


    const alertId =
        getDetectionId(
            data
        );


    /*
     * new_detection + auxiliary alert/threat events can describe
     * the same backend event. Render it only once.
     */
    if (
        alertId &&
        renderedAlertIds.has(
            alertId
        )
    ) {

        return;
    }


    if (alertId) {

        renderedAlertIds.add(
            alertId
        );


        trimAlertCache();
    }


    const placeholder =
        container.querySelector(
            "p"
        );


    if (placeholder) {

        placeholder.remove();
    }


    const attack =
        data.attack ??
        data.attack_type ??
        data.label ??
        data.threat ??
        "Unknown Threat";


    const severity =
        data.severity ??
        "HIGH";


    const source =
        data.src_ip ??
        data.source_ip ??
        data.src ??
        "Unknown";


    const destination =
        data.dst_ip ??
        data.destination_ip ??
        data.dst ??
        "Unknown";


    /*
     * Always format through the same formatter used by charts.js.
     */
    const timestamp =
        formatSocketTime(
            data.timestamp ??
            data.time ??
            data.created_at ??
            null
        );


    const alert =
        document.createElement(
            "div"
        );


    alert.className =
        "alert live-alert";


    const severityClass =
        String(
            severity
        )
            .toLowerCase()
            .replace(
                /[^a-z]/g,
                ""
            );


    if (severityClass) {

        alert.classList.add(
            "severity-" +
            severityClass
        );
    }


    alert.innerHTML = `

        <strong>
            ${escapeSocketHTML(
                attack
            )}
        </strong>

        <br>

        <span>
            ${escapeSocketHTML(
                source
            )}
            →
            ${escapeSocketHTML(
                destination
            )}
        </span>

        <br>

        <small>
            ${escapeSocketHTML(
                severity
            )}
            |
            ${escapeSocketHTML(
                timestamp
            )}
        </small>

    `;


    container.prepend(
        alert
    );


    /*
     * Keep the latest 20 rendered live alerts.
     */
    while (
        container.querySelectorAll(
            ".live-alert"
        ).length >
        20
    ) {

        const alerts =
            container.querySelectorAll(
                ".live-alert"
            );


        const last =
            alerts[
                alerts.length -
                1
            ];


        if (!last) {

            break;
        }


        last.remove();
    }
}


/* ============================================================
   SOCKET STATUS
   ============================================================ */

function updateSocketStatus(
    connected
) {

    /*
     * charts.js is the primary backend-status owner.
     */
    if (
        window.socCharts &&
        typeof window.socCharts
            .setBackendStatus ===
        "function"
    ) {

        try {

            window.socCharts
                .setBackendStatus(
                    connected
                        ? "live"
                        : "offline"
                );

        } catch (error) {

            console.warn(
                "[SOCKET] charts.js status update failed:",
                error.message
            );
        }
    }


    const status =
        document.getElementById(
            "backendStatus"
        );


    const indicator =
        document.getElementById(
            "statusIndicator"
        );


    const text =
        document.getElementById(
            "statusText"
        );


    if (
        status &&
        indicator &&
        text
    ) {

        status.classList.remove(
            "online",
            "offline",
            "live",
            "connecting",
            "last-known"
        );


        indicator.classList.remove(
            "online",
            "offline",
            "live",
            "connecting",
            "last-known"
        );


        if (connected) {

            status.classList.add(
                "online"
            );


            indicator.classList.add(
                "online"
            );


            text.textContent =
                "🟢 LIVE — Real-time data";

        } else {

            status.classList.add(
                "offline"
            );


            indicator.classList.add(
                "offline"
            );


            text.textContent =
                "🔴 OFFLINE — Backend Disconnected";
        }


        return;
    }


    const oldStatus =
        document.querySelector(
            ".status"
        );


    if (!oldStatus) {

        return;
    }


    if (connected) {

        oldStatus.innerHTML = `
            <span class="online"></span>
            SOC Online
        `;

    } else {

        oldStatus.innerHTML = `
            <span class="offline"></span>
            Backend Disconnected
        `;
    }
}


/* ============================================================
   BROWSER UI INITIALIZATION
   ============================================================ */

function resetSocketSessionUI() {

    /*
     * Reset browser-only Socket.IO state.
     *
     * IMPORTANT:
     * - Does NOT reset backend packet count.
     * - Does NOT reset capture_started_at.
     * - Does NOT delete SQLite.
     * - Does NOT delete PDF reports.
     *
     * A browser reload naturally reconstructs the DOM. Clearing the
     * alert panel here prevents stale DOM content from surviving any
     * frontend re-initialization logic.
     */
    processedDetectionIds.clear();

    enrichedDetectionIds.clear();

    renderedAlertIds.clear();

    historicalDetections =
        [];


    const alertContainer =
        document.getElementById(
            "alerts"
        );


    if (alertContainer) {

        alertContainer.innerHTML =
            "<p>No alerts detected.</p>";
    }


    console.log(
        "[SOCKET] Browser Socket.IO UI initialized."
    );
}


/* ============================================================
   START
   ============================================================ */

document.addEventListener(
    "DOMContentLoaded",
    () => {

        console.log(
            "[SOCKET] Starting SOC real-time connection..."
        );


        resetSocketSessionUI();


        if (
            window.socCharts &&
            typeof window.socCharts
                .setBackendStatus ===
            "function"
        ) {

            window.socCharts
                .setBackendStatus(
                    "connecting"
                );

        } else {

            updateSocketStatus(
                false
            );
        }


        initializeSocket();
    }
);


/* ============================================================
   PUBLIC SOCKET API
   ============================================================ */

window.SOCSocket = {

    getSocket:
        function () {

            return socSocket;
        },


    isConnected:
        function () {

            return !!(
                socSocket &&
                socSocket.connected
            );
        },


    reconnect:
        function () {

            if (socSocket) {

                socSocket.connect();

            } else {

                initializeSocket();
            }
        },


    disconnect:
        function () {

            if (socSocket) {

                socSocket.disconnect();
            }
        },


    requestHistory:
        function () {

            requestHistory();
        },


    clearDetectionCache:
        function () {

            processedDetectionIds.clear();

            enrichedDetectionIds.clear();

            renderedAlertIds.clear();


            console.log(
                "[SOCKET] Detection/alert caches cleared."
            );
        },


    getProcessedDetectionCount:
        function () {

            return processedDetectionIds.size;
        },


    getHistoricalDetections:
        function () {

            return historicalDetections.slice();
        },


    resetLiveSession:
        function () {

            resetSocketSessionUI();
        },


    isCurrentMonitoringEvent:
        function (
            data
        ) {

            return isCurrentMonitoringEvent(
                data
            );
        },


    formatTime:
        function (
            value
        ) {

            return formatSocketTime(
                value
            );
        }
};


/* ============================================================
   COMPATIBILITY GLOBALS
   ============================================================ */

window.displayHistoricalAlerts =
    displayHistoricalAlerts;

window.createHistoricalAlertHTML =
    createHistoricalAlertHTML;