/* ============================================================
   SOC PLATFORM — API CLIENT
   frontend/api.js

   Responsibilities:
   - REST API communication
   - Backend health/status
   - Backend monitoring-session tracking
   - Packet statistics fallback
   - Device inventory
   - Network topology
   - Model information
   - Historical detections (manual only)
   - Threat intelligence
   - Current-session security reports
   - Live device/topology refresh

   IMPORTANT LIVE OWNERSHIP:
   ------------------------------------------------------------
   - Socket.IO -> new_detection -> charts.js
   - charts.js owns live threat visualization
   - api.js must NEVER overwrite live threat counters/charts

   SESSION RULE:
   ------------------------------------------------------------
   - Backend capture_started_at defines monitoring session
   - Browser F5 does NOT create a new monitoring session
   - Socket reconnect does NOT create a new monitoring session
   - Backend restart creates a new monitoring session
   - SQLite history remains stored
   - Old PDF reports remain stored
   - Dashboard reports show current backend session only
   ============================================================ */

"use strict";


/* ============================================================
   CONFIGURATION
   ============================================================ */

const API_BASE = "http://127.0.0.1:5000";

const NETWORK_REFRESH_INTERVAL_MS = 5000;

const REPORT_REFRESH_INTERVAL_MS = 10000;


/* ============================================================
   STATE
   ============================================================ */

let backendAvailable = false;

let apiInitialized = false;

let reportRefreshTimer = null;

let networkRefreshTimer = null;

let networkRefreshInProgress = false;

let currentSessionDetections = [];


/*
 * Backend monitoring session start.
 *
 * Stored as Unix milliseconds.
 *
 * IMPORTANT:
 * This is never initialized with Date.now().
 */
let monitoringSessionStart = null;


/* ============================================================
   GENERIC API REQUEST
   ============================================================ */

async function apiRequest(
    endpoint,
    options = {}
) {

    const controller =
        new AbortController();


    const timeout =
        setTimeout(
            () => controller.abort(),
            options.timeout || 5000
        );


    try {

        const requestOptions = {

            method:
                options.method || "GET",

            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json",
                ...(options.headers || {})
            },

            signal:
                controller.signal,

            cache:
                "no-store"
        };


        if (
            options.body !== undefined
        ) {

            requestOptions.body =
                JSON.stringify(
                    options.body
                );
        }


        const response =
            await fetch(
                `${API_BASE}${endpoint}`,
                requestOptions
            );


        if (
            !response.ok
        ) {

            throw new Error(
                `HTTP ${response.status}: ${response.statusText}`
            );
        }


        return await response.json();


    } catch (error) {

        if (
            error &&
            error.name === "AbortError"
        ) {

            console.warn(
                `[API TIMEOUT] ${endpoint}`
            );

        } else {

            console.error(
                `[API ERROR] ${endpoint}`,
                error
            );
        }


        return null;


    } finally {

        clearTimeout(
            timeout
        );
    }
}


/* ============================================================
   TIMESTAMP PARSER
   ============================================================ */

function parseAPITimestamp(
    value
) {

    /*
     * Prefer charts.js shared parser.
     */
    if (
        window.socCharts &&
        typeof window.socCharts.parseSOCTimestamp ===
        "function"
    ) {

        try {

            return window.socCharts
                .parseSOCTimestamp(
                    value
                );

        } catch (error) {

            console.warn(
                "[API] Shared timestamp parser failed:",
                error.message
            );
        }
    }


    if (
        value instanceof Date
    ) {

        return Number.isNaN(
            value.getTime()
        )
            ? null
            : value;
    }


    if (
        typeof value === "number" &&
        Number.isFinite(value)
    ) {

        const milliseconds =
            value < 1000000000000
                ? value * 1000
                : value;


        const date =
            new Date(
                milliseconds
            );


        return Number.isNaN(
            date.getTime()
        )
            ? null
            : date;
    }


    if (
        typeof value !== "string"
    ) {

        return null;
    }


    const trimmed =
        value.trim();


    if (
        !trimmed
    ) {

        return null;
    }


    /*
     * Numeric string timestamp.
     */
    if (
        /^\d+(?:\.\d+)?$/
            .test(
                trimmed
            )
    ) {

        const numeric =
            Number(
                trimmed
            );


        if (
            Number.isFinite(
                numeric
            )
        ) {

            const milliseconds =
                numeric < 1000000000000
                    ? numeric * 1000
                    : numeric;


            const numericDate =
                new Date(
                    milliseconds
                );


            if (
                !Number.isNaN(
                    numericDate.getTime()
                )
            ) {

                return numericDate;
            }
        }
    }


    let normalized =
        trimmed;


    /*
     * Backend naive ISO timestamps are UTC.
     */
    if (
        /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/
            .test(
                normalized
            ) &&
        !/[zZ]$/
            .test(
                normalized
            ) &&
        !/[+-]\d{2}:?\d{2}$/
            .test(
                normalized
            )
    ) {

        normalized += "Z";
    }


    const date =
        new Date(
            normalized
        );


    return Number.isNaN(
        date.getTime()
    )
        ? null
        : date;
}


/* ============================================================
   DATE FORMATTER
   ============================================================ */

function formatAPIDateTime(
    value
) {

    const date =
        parseAPITimestamp(
            value
        );


    if (
        !date
    ) {

        return "Unknown time";
    }


    return date
        .toLocaleString();
}


/* ============================================================
   MONITORING SESSION EXTRACTION
   ============================================================ */

function extractMonitoringSessionStart(
    data
) {

    if (
        !data
    ) {

        return null;
    }


    return (
        data.capture_started_at ??
        data.session_started_at ??
        data.monitoring_started_at ??
        data.capture?.capture_started_at ??
        data.capture?.started_at ??
        null
    );
}


/* ============================================================
   NORMALIZE MONITORING SESSION
   ============================================================ */

function normalizeMonitoringSessionStart(
    value
) {

    const date =
        parseAPITimestamp(
            value
        );


    return date
        ? date.getTime()
        : null;
}


/* ============================================================
   CLEAR FRONTEND SESSION STATE
   ============================================================ */

function clearCurrentSessionFrontendState() {

    currentSessionDetections =
        [];


    /*
     * Reset Socket.IO live alert/dedupe state only.
     */
    if (
        window.SOCSocket &&
        typeof window.SOCSocket.resetLiveSession ===
        "function"
    ) {

        try {

            window.SOCSocket
                .resetLiveSession();

        } catch (error) {

            console.warn(
                "[API] Socket live-session reset failed:",
                error.message
            );
        }
    }


    /*
     * Reset live threat charts.
     */
    if (
        window.socCharts &&
        typeof window.socCharts.clearLiveThreatCharts ===
        "function"
    ) {

        try {

            window.socCharts
                .clearLiveThreatCharts();

        } catch (error) {

            console.warn(
                "[API] Live threat chart reset failed:",
                error.message
            );
        }
    }


    /*
     * Reset traffic graph only.
     *
     * Does NOT reset backend packet count.
     */
    if (
        window.socCharts &&
        typeof window.socCharts.clearLiveTrafficChart ===
        "function"
    ) {

        try {

            window.socCharts
                .clearLiveTrafficChart();

        } catch (error) {

            console.warn(
                "[API] Live traffic chart reset failed:",
                error.message
            );
        }
    }


    /*
     * Clear currently displayed report cards only.
     *
     * PDF files remain on disk.
     */
    const reportContainer =
        document.getElementById(
            "reportContainer"
        );


    if (
        reportContainer
    ) {

        reportContainer.innerHTML = `
            <p class="report-empty-message">
                No security reports generated yet.
            </p>
        `;
    }
}


/* ============================================================
   SET MONITORING SESSION
   ============================================================ */

function setMonitoringSessionStart(
    value
) {

    const normalized =
        normalizeMonitoringSessionStart(
            value
        );


    if (
        normalized === null
    ) {

        return false;
    }


    const previous =
        monitoringSessionStart;


    /*
     * First API status response.
     *
     * Establish session only.
     *
     * Browser F5 must NOT look like a backend restart.
     */
    if (
        previous === null
    ) {

        monitoringSessionStart =
            normalized;


        if (
            window.socCharts &&
            typeof window.socCharts.setMonitoringSessionStart ===
            "function"
        ) {

            try {

                window.socCharts
                    .setMonitoringSessionStart(
                        value
                    );

            } catch (error) {

                console.warn(
                    "[API] charts.js monitoring-session sync failed:",
                    error.message
                );
            }
        }


        console.log(
            "[API] Backend monitoring session established:",
            new Date(
                normalized
            ).toISOString()
        );


        return false;
    }


    /*
     * Same backend capture session.
     */
    if (
        Math.abs(
            previous -
            normalized
        ) < 1000
    ) {

        return false;
    }


    /*
     * Backend capture_started_at changed.
     *
     * Real backend/capture restart.
     */
    monitoringSessionStart =
        normalized;


    if (
        window.socCharts &&
        typeof window.socCharts.setMonitoringSessionStart ===
        "function"
    ) {

        try {

            window.socCharts
                .setMonitoringSessionStart(
                    value
                );

        } catch (error) {

            console.warn(
                "[API] charts.js monitoring-session restart sync failed:",
                error.message
            );
        }
    }


    clearCurrentSessionFrontendState();


    console.log(
        "[API] New backend monitoring session detected:",
        new Date(
            normalized
        ).toISOString()
    );


    return true;
}


/* ============================================================
   SESSION TIMESTAMP CHECK
   ============================================================ */

function isTimestampInCurrentMonitoringSession(
    value
) {

    if (
        monitoringSessionStart === null
    ) {

        return true;
    }


    const date =
        parseAPITimestamp(
            value
        );


    if (
        !date
    ) {

        return false;
    }


    return (
        date.getTime() >=
        monitoringSessionStart -
        3000
    );
}


/* ============================================================
   EVENT SESSION CHECK
   ============================================================ */

function isEventInCurrentMonitoringSession(
    event
) {

    if (
        !event
    ) {

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
                    event
                );

        } catch (error) {

            console.warn(
                "[API] charts.js event-session check failed:",
                error.message
            );
        }
    }


    const timestamp =
        event.timestamp ??
        event.time ??
        event.created_at ??
        event.generated_at ??
        null;


    if (
        !timestamp
    ) {

        return (
            monitoringSessionStart ===
            null
        );
    }


    return isTimestampInCurrentMonitoringSession(
        timestamp
    );
}


/* ============================================================
   BACKEND HEALTH
   ============================================================ */

async function checkBackendHealth() {

    const data =
        await apiRequest(
            "/api/health",
            {
                timeout: 3000
            }
        );


    const healthy =
        !!(
            data &&
            (
                data.status === "ok" ||
                data.status === "online" ||
                data.status === "running" ||
                data.status === "active"
            )
        );


    backendAvailable =
        healthy;


    if (
        window.socCharts &&
        typeof window.socCharts.setBackendStatus ===
        "function"
    ) {

        try {

            window.socCharts
                .setBackendStatus(
                    healthy
                        ? "live"
                        : "offline"
                );

        } catch (error) {

            console.warn(
                "[API] Status UI update failed:",
                error.message
            );
        }
    }


    return healthy;
}


/* ============================================================
   SYSTEM STATUS
   ============================================================ */

async function getSystemStatus() {

    const data =
        await apiRequest(
            "/api/status"
        );


    if (
        !data
    ) {

        return null;
    }


    updateSystemStatus(
        data
    );


    return data;
}


/* ============================================================
   UPDATE SYSTEM STATUS
   ============================================================ */

function updateSystemStatus(
    data
) {

    if (
        !data
    ) {

        return;
    }


    const status =
        String(
            data.status ??
            data.system_status ??
            data.state ??
            ""
        )
            .trim()
            .toLowerCase();


    if (
        status === "ok" ||
        status === "online" ||
        status === "running" ||
        status === "active"
    ) {

        backendAvailable =
            true;
    }


    /*
     * Synchronize backend monitoring session.
     */
    const sessionStart =
        extractMonitoringSessionStart(
            data
        );


    if (
        sessionStart !== null &&
        sessionStart !== undefined
    ) {

        setMonitoringSessionStart(
            sessionStart
        );
    }


    /*
     * TOTAL PACKETS
     *
     * Backend is authoritative.
     */
    const packetCount =
        data.capture?.total_packets ??
        data.capture?.packet_count ??
        data.total_packets ??
        data.packet_count ??
        data.packets ??
        data.total;


    if (
        packetCount !== undefined &&
        packetCount !== null &&
        Number.isFinite(
            Number(
                packetCount
            )
        )
    ) {

        updatePacketElements(
            Number(
                packetCount
            )
        );
    }


    /*
     * IMPORTANT:
     *
     * Do NOT update devices here.
     * /api/devices owns Connected Devices.
     *
     * Do NOT update live threat totals here.
     */
}


/* ============================================================
   LIVE STATS
   ============================================================ */

async function getLiveStats() {

    const data =
        await apiRequest(
            "/api/live-stats"
        );


    if (
        !data
    ) {

        console.warn(
            "[API] /api/live-stats unavailable"
        );

        return null;
    }


    const packets =
        data.capture?.total_packets ??
        data.capture?.packet_count ??
        data.total_packets ??
        data.packet_count ??
        data.packets ??
        data.total;


    if (
        packets !== undefined &&
        packets !== null &&
        Number.isFinite(
            Number(
                packets
            )
        )
    ) {

        updatePacketElements(
            Number(
                packets
            )
        );
    }


    /*
     * /api/devices owns Connected Devices.
     *
     * Socket.IO/charts.js own threat count.
     */


    return data;
}


/* ============================================================
   MODEL INFORMATION
   ============================================================ */

async function getModelInfo() {

    const data =
        await apiRequest(
            "/api/model"
        );


    if (
        !data
    ) {

        return null;
    }


    updateModelInfo(
        data
    );


    return data;
}


/* ============================================================
   UPDATE MODEL INFO
   ============================================================ */

function updateModelInfo(
    data
) {

    if (
        !data
    ) {

        return;
    }


    const rfAccuracy =
        data.rf_accuracy ??
        data.random_forest_accuracy ??
        data.accuracy;


    if (
        rfAccuracy !== undefined &&
        rfAccuracy !== null
    ) {

        const formatted =
            normalizePercentage(
                rfAccuracy
            );


        setElementText(
            "aiAccuracy",
            formatted
        );


        updateAccuracyCard(
            "AI Accuracy",
            formatted
        );
    }


    const lstmAccuracy =
        data.lstm_accuracy ??
        data.lstmAccuracy;


    if (
        lstmAccuracy !== undefined &&
        lstmAccuracy !== null
    ) {

        const formatted =
            normalizePercentage(
                lstmAccuracy
            );


        setElementText(
            "lstmAccuracy",
            formatted
        );


        updateAccuracyCard(
            "LSTM Accuracy",
            formatted
        );
    }
}


/* ============================================================
   HISTORICAL DETECTIONS
   MANUAL ONLY
   ============================================================ */

async function getDetections(
    limit = 50
) {

    const safeLimit =
        Math.max(
            1,
            Math.min(
                Number(
                    limit
                ) || 50,
                500
            )
        );


    const data =
        await apiRequest(
            `/api/detections?limit=${safeLimit}`
        );


    if (
        !data
    ) {

        return null;
    }


    let detections =
        data;


    if (
        !Array.isArray(
            detections
        )
    ) {

        detections =
            data.detections ??
            data.results ??
            data.data ??
            [];
    }


    return Array.isArray(
        detections
    )
        ? detections
        : [];
}


/* ============================================================
   CURRENT SESSION DETECTION FILTER
   ============================================================ */

function filterCurrentSessionDetections(
    detections
) {

    if (
        !Array.isArray(
            detections
        )
    ) {

        return [];
    }


    return detections.filter(
        detection =>
            isEventInCurrentMonitoringSession(
                detection
            )
    );
}


/* ============================================================
   REGISTER LIVE DETECTION
   ============================================================ */

function registerLiveDetection(
    detection
) {

    if (
        !detection
    ) {

        return;
    }


    if (
        !isEventInCurrentMonitoringSession(
            detection
        )
    ) {

        return;
    }


    const attack =
        String(
            detection.attack_type ??
            detection.attack ??
            detection.label ??
            ""
        )
            .trim()
            .toUpperCase();


    if (
        attack === "BENIGN" ||
        attack === "NORMAL"
    ) {

        return;
    }


    const id =
        detection.id ??
        detection.event_id ??
        detection.detection_id ??
        [
            detection.timestamp || "",
            detection.src_ip || "",
            detection.dst_ip || "",
            detection.attack_type ||
            detection.attack ||
            ""
        ].join("|");


    const exists =
        currentSessionDetections
            .some(
                item => {

                    const currentId =
                        item.id ??
                        item.event_id ??
                        item.detection_id ??
                        [
                            item.timestamp || "",
                            item.src_ip || "",
                            item.dst_ip || "",
                            item.attack_type ||
                            item.attack ||
                            ""
                        ].join("|");


                    return (
                        String(
                            currentId
                        ) ===
                        String(
                            id
                        )
                    );
                }
            );


    if (
        exists
    ) {

        return;
    }


    currentSessionDetections
        .push(
            detection
        );


    if (
        currentSessionDetections.length >
        100
    ) {

        currentSessionDetections =
            currentSessionDetections
                .slice(
                    -100
                );
    }
}


/* ============================================================
   CONNECTED DEVICES
   /api/devices IS AUTHORITATIVE
   ============================================================ */

async function getDevices() {

    const data =
        await apiRequest(
            "/api/devices"
        );


    if (
        !data
    ) {

        return null;
    }


    /*
     * IMPORTANT:
     *
     * This has a unique name deliberately.
     *
     * topology.js also defines a global updateDevices()
     * function for topology nodes. Calling updateDevices()
     * here would therefore call the topology function instead
     * of the Connected Devices table renderer.
     */
    updateDeviceInventory(
        data
    );


    return data;
}


/* ============================================================
   EXTRACT DEVICE ARRAY
   ============================================================ */

function extractDevices(
    data
) {

    if (
        !data
    ) {

        return [];
    }


    if (
        Array.isArray(
            data
        )
    ) {

        return data;
    }


    if (
        Array.isArray(
            data.devices
        )
    ) {

        return data.devices;
    }


    if (
        Array.isArray(
            data.results
        )
    ) {

        return data.results;
    }


    if (
        Array.isArray(
            data.data
        )
    ) {

        return data.data;
    }


    return [];
}


/* ============================================================
   UPDATE CONNECTED DEVICE INVENTORY
   ============================================================ */

function updateDeviceInventory(
    data
) {

    const deviceList =
        extractDevices(
            data
        );


    /*
     * Prefer explicit backend count.
     *
     * Fall back to actual returned array size.
     */
    let count =
        data &&
        !Array.isArray(
            data
        )
            ? (
                data.count ??
                data.device_count ??
                data.connected_devices
            )
            : undefined;


    if (
        count === undefined ||
        count === null ||
        !Number.isFinite(
            Number(
                count
            )
        )
    ) {

        count =
            deviceList.length;
    }


    /*
     * Update Connected Devices summary card.
     */
    updateDeviceElements(
        Number(
            count
        )
    );


    /*
     * ========================================================
     * DEVICE TABLE
     * ========================================================
     *
     * Preferred HTML:
     *
     * <tbody id="deviceTableBody">
     *
     * Legacy forms are also supported.
     */

    let table =
        document.getElementById(
            "deviceTableBody"
        );


    if (
        !table
    ) {

        const tableElement =
            document.getElementById(
                "deviceTable"
            );


        if (
            tableElement
        ) {

            const tagName =
                String(
                    tableElement.tagName ??
                    ""
                )
                    .trim()
                    .toLowerCase();


            /*
             * Legacy:
             * <tbody id="deviceTable">
             */
            if (
                tagName === "tbody"
            ) {

                table =
                    tableElement;

            } else {

                /*
                 * Legacy:
                 * <table id="deviceTable">
                 *     <tbody>...</tbody>
                 * </table>
                 */
                table =
                    tableElement.tBodies?.[0] ??
                    tableElement.querySelector?.(
                        "tbody"
                    ) ??
                    null;
            }
        }
    }


    if (
        !table
    ) {

        console.warn(
            "[API] Connected Devices table body not found."
        );

        return;
    }


    /*
     * ========================================================
     * EMPTY DEVICE INVENTORY
     * ========================================================
     */

    if (
        deviceList.length === 0
    ) {

        table.innerHTML = `
            <tr>
                <td>No devices detected</td>
                <td>—</td>
                <td>—</td>
                <td>—</td>
            </tr>
        `;


        console.log(
            "[API] Connected device inventory rendered: 0"
        );


        return;
    }


    /*
     * ========================================================
     * RENDER DEVICE ROWS
     * ========================================================
     */

    table.innerHTML =
        deviceList
            .map(
                createDeviceRow
            )
            .join("");


    console.log(
        `[API] Connected device inventory rendered: ${deviceList.length}`
    );
}


/* ============================================================
   CREATE DEVICE ROW
   ============================================================ */

function createDeviceRow(
    device
) {

    const hostname =
        device.hostname ??
        device.name ??
        device.device_name ??
        "Unknown";


    const ip =
        device.ip ??
        device.ip_address ??
        device.src_ip ??
        "Unknown";


    const os =
        device.os ??
        device.operating_system ??
        "Unknown";


    const status =
        device.status ??
        (
            device.online === false
                ? "Offline"
                : "Online"
        );


    return `
        <tr>

            <td>
                ${escapeHTML(
                    hostname
                )}
            </td>

            <td>
                ${escapeHTML(
                    ip
                )}
            </td>

            <td>
                ${escapeHTML(
                    os
                )}
            </td>

            <td>
                <span class="${escapeHTML(
                    getStatusClass(
                        status
                    )
                )}">
                    ${escapeHTML(
                        status
                    )}
                </span>
            </td>

        </tr>
    `;
}


/* ============================================================
   TOPOLOGY API
   ============================================================ */

async function getTopology(
    updateUI = true
) {

    const data =
        await apiRequest(
            "/api/topology"
        );


    if (
        !data
    ) {

        return null;
    }


    if (
        updateUI
    ) {

        updateTopology(
            data
        );
    }


    return data;
}


/* ============================================================
   UPDATE TOPOLOGY
   ============================================================ */

function updateTopology(
    data
) {

    if (
        !data
    ) {

        return;
    }


    /*
     * Preferred topology.js interface.
     */
    if (
        window.Topology &&
        typeof window.Topology.update ===
        "function"
    ) {

        try {

            window.Topology
                .update(
                    data
                );


            return;

        } catch (error) {

            console.warn(
                "[API] Topology.update failed:",
                error.message
            );
        }
    }


    /*
     * Legacy compatibility.
     */
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
                "[API] Legacy topology failed:",
                error.message
            );
        }
    }
}


/* ============================================================
   TRAFFIC
   charts.js owns recurring polling
   ============================================================ */

async function getTraffic() {

    const data =
        await apiRequest(
            "/api/traffic"
        );


    if (
        !data
    ) {

        return null;
    }


    if (
        window.socCharts &&
        typeof window.socCharts.updateTrafficFromAPI ===
        "function"
    ) {

        try {

            window.socCharts
                .updateTrafficFromAPI(
                    data
                );

        } catch (error) {

            console.warn(
                "[API] Traffic chart update failed:",
                error.message
            );
        }
    }


    return data;
}


/* ============================================================
   PROTOCOLS
   charts.js owns recurring polling
   ============================================================ */

async function getProtocols() {

    const data =
        await apiRequest(
            "/api/protocols"
        );


    if (
        !data
    ) {

        return null;
    }


    const protocols =
        data.protocols ??
        data.by_protocol ??
        data.data ??
        data;


    if (
        window.socCharts &&
        typeof window.socCharts.updateProtocolUsage ===
        "function"
    ) {

        try {

            window.socCharts
                .updateProtocolUsage(
                    protocols
                );

        } catch (error) {

            console.warn(
                "[API] Protocol chart update failed:",
                error.message
            );
        }
    }


    return data;
}


/* ============================================================
   HISTORICAL ATTACK STATS
   MANUAL ONLY
   ============================================================ */

async function getAttackStats() {

    return await apiRequest(
        "/api/attack-stats"
    );
}


/* ============================================================
   HISTORICAL TIMELINE
   MANUAL ONLY
   ============================================================ */

async function getTimeline() {

    return await apiRequest(
        "/api/timeline"
    );
}


/* ============================================================
   THREAT INTELLIGENCE
   ============================================================ */

async function getThreatIntelligence() {

    return await apiRequest(
        "/api/threat-intelligence"
    );
}


/* ============================================================
   REPORT TIMESTAMP
   ============================================================ */

function extractReportTimestamp(
    report
) {

    if (
        !report
    ) {

        return null;
    }


    /*
     * Prefer backend metadata.
     */
    const directTimestamp =
        report.timestamp ??
        report.created_at ??
        report.generated_at ??
        report.modified_at ??
        report.mtime ??
        report.file_time ??
        null;


    if (
        directTimestamp !== null &&
        directTimestamp !== undefined
    ) {

        const parsed =
            parseAPITimestamp(
                directTimestamp
            );


        if (
            parsed
        ) {

            return parsed;
        }
    }


    /*
     * Fallback to EVT timestamp.
     *
     * Example:
     * EVT-1788774889651.pdf
     */
    const eventId =
        String(
            report.event_id ??
            report.id ??
            ""
        );


    const filename =
        String(
            report.filename ??
            report.file ??
            ""
        );


    const candidates =
        [
            eventId,
            filename
        ];


    for (
        const candidate
        of candidates
    ) {

        const match =
            String(
                candidate
            )
                .match(
                    /(?:EVT[-_])?(\d{10,13})(?!\d)/i
                );


        if (
            !match
        ) {

            continue;
        }


        const numeric =
            Number(
                match[1]
            );


        if (
            !Number.isFinite(
                numeric
            )
        ) {

            continue;
        }


        const milliseconds =
            match[1].length <= 10
                ? numeric * 1000
                : numeric;


        const date =
            new Date(
                milliseconds
            );


        if (
            !Number.isNaN(
                date.getTime()
            )
        ) {

            return date;
        }
    }


    return null;
}


/* ============================================================
   CURRENT SESSION REPORT FILTER
   ============================================================ */

function filterReportsForCurrentMonitoringSession(
    reports
) {

    if (
        !Array.isArray(
            reports
        )
    ) {

        return [];
    }


    /*
     * Do not show historical PDFs until backend session start
     * is known.
     */
    if (
        monitoringSessionStart === null
    ) {

        return [];
    }


    return reports.filter(
        report => {

            const timestamp =
                extractReportTimestamp(
                    report
                );


            if (
                !timestamp
            ) {

                return false;
            }


            return (
                timestamp.getTime() >=
                monitoringSessionStart -
                3000
            );
        }
    );
}


/* ============================================================
   SECURITY REPORTS
   ============================================================ */

async function getReports() {

    /*
     * Establish monitoring session before filtering reports.
     */
    if (
        monitoringSessionStart === null
    ) {

        await getSystemStatus();
    }


    const data =
        await apiRequest(
            "/api/reports",
            {
                timeout: 5000
            }
        );


    if (
        !data
    ) {

        console.warn(
            "[API] Reports unavailable."
        );


        renderReports(
            []
        );


        return [];
    }


    let reports =
        data;


    if (
        !Array.isArray(
            reports
        )
    ) {

        reports =
            data.reports ??
            data.data ??
            data.results ??
            [];
    }


    if (
        !Array.isArray(
            reports
        )
    ) {

        reports =
            [];
    }


    const currentReports =
        filterReportsForCurrentMonitoringSession(
            reports
        );


    /*
     * Newest first.
     */
    currentReports.sort(
        (
            a,
            b
        ) => {

            const aTime =
                extractReportTimestamp(
                    a
                )?.getTime() ??
                0;


            const bTime =
                extractReportTimestamp(
                    b
                )?.getTime() ??
                0;


            return (
                bTime -
                aTime
            );
        }
    );


    renderReports(
        currentReports
    );


    return currentReports;
}


/* ============================================================
   REPORT RENDERER
   ============================================================ */

function renderReports(
    reports
) {

    const container =
        document.getElementById(
            "reportContainer"
        );


    if (
        !container
    ) {

        return;
    }


    ensureReportStyles();


    if (
        !Array.isArray(
            reports
        ) ||
        reports.length === 0
    ) {

        container.innerHTML = `
            <p class="report-empty-message">
                No security reports generated in this monitoring session.
            </p>
        `;


        return;
    }


    container.innerHTML =
        reports
            .map(
                createReportCard
            )
            .join("");
}


/* ============================================================
   CREATE REPORT CARD
   ============================================================ */

function createReportCard(
    report
) {

    if (
        !report
    ) {

        return "";
    }


    const filename =
        report.filename ??
        report.file ??
        "Unknown report";


    const eventId =
        report.event_id ??
        report.id ??
        String(
            filename
        )
            .replace(
                /\.pdf$/i,
                ""
            );


    const attackType =
        report.attack_type ??
        report.attack ??
        "UNKNOWN";


    const severity =
        String(
            report.severity ??
            "UNKNOWN"
        )
            .trim()
            .toUpperCase();


    const srcIP =
        report.src_ip ??
        report.source_ip ??
        "Unknown";


    const dstIP =
        report.dst_ip ??
        report.destination_ip ??
        "Unknown";


    const reportDate =
        extractReportTimestamp(
            report
        );


    const displayTime =
        reportDate
            ? reportDate.toLocaleString()
            : "Unknown time";


    let viewURL =
        report.view_url ??
        (
            "/api/reports/" +
            encodeURIComponent(
                filename
            )
        );


    let downloadURL =
        report.download_url ??
        (
            "/api/reports/" +
            encodeURIComponent(
                filename
            ) +
            "?download=1"
        );


    /*
     * Backend may return relative URLs.
     */
    if (
        viewURL.startsWith(
            "/"
        )
    ) {

        viewURL =
            API_BASE +
            viewURL;
    }


    if (
        downloadURL.startsWith(
            "/"
        )
    ) {

        downloadURL =
            API_BASE +
            downloadURL;
    }


    let sizeText =
        "";


    const size =
        Number(
            report.size_bytes
        );


    if (
        Number.isFinite(
            size
        ) &&
        size > 0
    ) {

        if (
            size >=
            1024 * 1024
        ) {

            sizeText =
                (
                    size /
                    (
                        1024 *
                        1024
                    )
                )
                    .toFixed(
                        2
                    ) +
                " MB";

        } else {

            sizeText =
                (
                    size /
                    1024
                )
                    .toFixed(
                        1
                    ) +
                " KB";
        }
    }


    const severityClass =
        getReportSeverityClass(
            severity
        );


    return `
        <article class="security-report-card">

            <div class="security-report-main">

                <div class="security-report-heading">

                    <span
                        class="
                            security-report-severity
                            ${escapeHTML(
                                severityClass
                            )}
                        "
                    >
                        ${escapeHTML(
                            severity
                        )}
                    </span>

                    <strong class="security-report-attack">
                        ${escapeHTML(
                            attackType
                        )}
                    </strong>

                </div>

                <div class="security-report-route">

                    ${escapeHTML(
                        srcIP
                    )}

                    <span>→</span>

                    ${escapeHTML(
                        dstIP
                    )}

                </div>

                <div class="security-report-meta">

                    <span>
                        ${escapeHTML(
                            eventId
                        )}
                    </span>

                    <span>
                        ${escapeHTML(
                            displayTime
                        )}
                    </span>

                    ${
                        sizeText
                            ? `
                                <span>
                                    ${escapeHTML(
                                        sizeText
                                    )}
                                </span>
                              `
                            : ""
                    }

                </div>

            </div>

            <div class="security-report-actions">

                <a
                    class="
                        security-report-button
                        report-view-button
                    "
                    href="${escapeHTML(
                        viewURL
                    )}"
                    target="_blank"
                    rel="noopener noreferrer"
                >
                    View Report
                </a>

                <a
                    class="
                        security-report-button
                        report-download-button
                    "
                    href="${escapeHTML(
                        downloadURL
                    )}"
                >
                    Download PDF
                </a>

            </div>

        </article>
    `;
}


/* ============================================================
   REPORT SEVERITY CLASS
   ============================================================ */

function getReportSeverityClass(
    severity
) {

    const value =
        String(
            severity ??
            ""
        )
            .trim()
            .toUpperCase();


    if (
        value === "CRITICAL"
    ) {

        return "report-critical";
    }


    if (
        value === "HIGH"
    ) {

        return "report-high";
    }


    if (
        value === "MEDIUM"
    ) {

        return "report-medium";
    }


    return "report-low";
}


/* ============================================================
   REPORT STYLES
   ============================================================ */

function ensureReportStyles() {

    if (
        document.getElementById(
            "soc-report-styles"
        )
    ) {

        return;
    }


    const style =
        document.createElement(
            "style"
        );


    style.id =
        "soc-report-styles";


    style.textContent = `

        #reportContainer {

            display: flex;

            flex-direction: column;

            gap: 12px;

            width: 100%;

            box-sizing: border-box;
        }


        .report-empty-message {

            color: #94a3b8;

            margin: 0;
        }


        .security-report-card {

            display: flex;

            justify-content: space-between;

            align-items: center;

            gap: 20px;

            width: 100%;

            box-sizing: border-box;

            padding: 18px;

            border:
                1px solid
                rgba(148, 163, 184, 0.16);

            border-radius: 12px;

            background:
                rgba(15, 23, 42, 0.62);
        }


        .security-report-main {

            min-width: 0;

            flex: 1;
        }


        .security-report-heading {

            display: flex;

            align-items: center;

            flex-wrap: wrap;

            gap: 10px;

            margin-bottom: 8px;
        }


        .security-report-attack {

            color: #ffffff;

            font-size: 16px;

            overflow-wrap: anywhere;
        }


        .security-report-severity {

            display: inline-flex;

            padding: 4px 9px;

            border-radius: 999px;

            font-size: 11px;

            font-weight: 700;

            white-space: nowrap;
        }


        .report-critical {

            color: #fecaca;

            background:
                rgba(220, 38, 38, .18);

            border:
                1px solid
                rgba(248, 113, 113, .28);
        }


        .report-high {

            color: #fdba74;

            background:
                rgba(234, 88, 12, .16);

            border:
                1px solid
                rgba(251, 146, 60, .26);
        }


        .report-medium {

            color: #fde68a;

            background:
                rgba(202, 138, 4, .14);

            border:
                1px solid
                rgba(250, 204, 21, .22);
        }


        .report-low {

            color: #93c5fd;

            background:
                rgba(37, 99, 235, .13);

            border:
                1px solid
                rgba(96, 165, 250, .24);
        }


        .security-report-route {

            color: #93b4df;

            margin-bottom: 7px;

            overflow-wrap: anywhere;
        }


        .security-report-route span {

            margin: 0 5px;
        }


        .security-report-meta {

            display: flex;

            flex-wrap: wrap;

            gap: 8px 14px;

            color: #64748b;

            font-size: 12px;

            overflow-wrap: anywhere;
        }


        .security-report-actions {

            display: flex;

            flex-wrap: wrap;

            justify-content: flex-end;

            gap: 8px;

            flex: 0 0 auto;
        }


        .security-report-button {

            display: inline-flex;

            align-items: center;

            justify-content: center;

            min-height: 38px;

            padding: 0 14px;

            border-radius: 8px;

            text-decoration: none;

            font-size: 12px;

            font-weight: 600;

            transition:
                opacity .15s ease,
                transform .15s ease;
        }


        .security-report-button:hover {

            opacity: .9;

            transform:
                translateY(-1px);
        }


        .report-view-button {

            color: #bfdbfe;

            background:
                rgba(37, 99, 235, .16);

            border:
                1px solid
                rgba(96, 165, 250, .24);
        }


        .report-download-button {

            color: #bbf7d0;

            background:
                rgba(22, 163, 74, .14);

            border:
                1px solid
                rgba(74, 222, 128, .22);
        }


        @media (max-width: 760px) {

            .security-report-card {

                align-items: flex-start;

                flex-direction: column;
            }


            .security-report-actions {

                width: 100%;

                justify-content: flex-start;
            }
        }

    `;


    document.head.appendChild(
        style
    );
}


/* ============================================================
   LIVE NETWORK INVENTORY REFRESH

   /api/devices and /api/topology continue refreshing while
   the browser remains open.
   ============================================================ */

async function refreshNetworkState() {

    if (
        networkRefreshInProgress
    ) {

        return null;
    }


    networkRefreshInProgress =
        true;


    try {

        const results =
            await Promise.allSettled(
                [
                    getDevices(),
                    getTopology()
                ]
            );


        return results;


    } finally {

        networkRefreshInProgress =
            false;
    }
}


/* ============================================================
   REFRESH DASHBOARD SNAPSHOT
   ============================================================ */

async function refreshDashboard() {

    const healthy =
        await checkBackendHealth();


    if (
        !healthy
    ) {

        console.warn(
            "[API] Backend unavailable."
        );


        return null;
    }


    /*
     * Status first because capture_started_at defines the
     * monitoring session.
     */
    const status =
        await getSystemStatus();


    if (
        !status
    ) {

        console.warn(
            "[API] Backend status unavailable."
        );
    }


    /*
     * charts.js owns recurring:
     *
     * /api/status
     * /api/live-stats
     * /api/traffic
     * /api/protocols
     *
     * api.js owns:
     *
     * /api/devices
     * /api/topology
     * /api/reports
     */
    const results =
        await Promise.allSettled(
            [
                getModelInfo(),
                getDevices(),
                getTopology(),
                getReports()
            ]
        );


    return results;
}


/* ============================================================
   EXPLICIT LIVE DASHBOARD RESET
   ============================================================ */

function resetLiveDashboard() {

    currentSessionDetections =
        [];


    if (
        window.SOCSocket &&
        typeof window.SOCSocket.resetLiveSession ===
        "function"
    ) {

        try {

            window.SOCSocket
                .resetLiveSession();

        } catch (error) {

            console.warn(
                "[API] Socket UI reset failed:",
                error.message
            );
        }
    }


    if (
        window.socCharts &&
        typeof window.socCharts.clearLiveThreatCharts ===
        "function"
    ) {

        try {

            window.socCharts
                .clearLiveThreatCharts();

        } catch (error) {

            console.warn(
                "[API] Threat chart reset failed:",
                error.message
            );
        }
    }


    /*
     * IMPORTANT:
     *
     * Do NOT reset Total Packets here.
     *
     * Browser/UI reset != backend capture restart.
     */
}


/* ============================================================
   UPDATE PACKET ELEMENTS
   ============================================================ */

function updatePacketElements(
    value
) {

    const number =
        Number(
            value
        );


    if (
        !Number.isFinite(
            number
        )
    ) {

        return;
    }


    const formatted =
        number
            .toLocaleString();


    setElementText(
        "packetCount",
        formatted
    );


    setElementText(
        "packets",
        formatted
    );
}


/* ============================================================
   UPDATE DEVICE ELEMENTS
   ============================================================ */

function updateDeviceElements(
    value
) {

    const number =
        Number(
            value
        );


    if (
        !Number.isFinite(
            number
        )
    ) {

        return;
    }


    const formatted =
        number
            .toLocaleString();


    /*
     * Compatibility with both possible dashboard IDs.
     */
    setElementText(
        "deviceCount",
        formatted
    );


    setElementText(
        "devices",
        formatted
    );
}


/* ============================================================
   SET ELEMENT TEXT
   ============================================================ */

function setElementText(
    id,
    value
) {

    const element =
        document.getElementById(
            id
        );


    if (
        element
    ) {

        element.textContent =
            value;
    }
}


/* ============================================================
   NORMALIZE ACCURACY
   ============================================================ */

function normalizePercentage(
    value
) {

    let number =
        Number(
            value
        );


    if (
        !Number.isFinite(
            number
        )
    ) {

        return "N/A";
    }


    if (
        number >= 0 &&
        number <= 1
    ) {

        number *=
            100;
    }


    return (
        number.toFixed(
            2
        ) +
        "%"
    );
}


/* ============================================================
   ACCURACY CARD FALLBACK
   ============================================================ */

function updateAccuracyCard(
    title,
    value
) {

    const cards =
        document.querySelectorAll(
            ".card"
        );


    cards.forEach(
        card => {

            const heading =
                card.querySelector(
                    "h3"
                );


            const number =
                card.querySelector(
                    "h2"
                );


            if (
                heading &&
                number &&
                heading.textContent
                    .trim()
                    .toLowerCase() ===
                title.toLowerCase()
            ) {

                number.textContent =
                    value;
            }
        }
    );
}


/* ============================================================
   STATUS CLASS
   ============================================================ */

function getStatusClass(
    status
) {

    const value =
        String(
            status ??
            ""
        )
            .toLowerCase();


    if (
        value.includes(
            "online"
        ) ||
        value.includes(
            "active"
        ) ||
        value.includes(
            "protected"
        ) ||
        value.includes(
            "running"
        )
    ) {

        return "green";
    }


    if (
        value.includes(
            "attack"
        ) ||
        value.includes(
            "offline"
        ) ||
        value.includes(
            "critical"
        ) ||
        value.includes(
            "down"
        )
    ) {

        return "red";
    }


    return "yellow";
}


/* ============================================================
   HTML ESCAPE
   ============================================================ */

function escapeHTML(
    value
) {

    return String(
        value ??
        ""
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


/* ============================================================
   PUBLIC API
   ============================================================ */

window.API = {

    request:
        apiRequest,

    health:
        checkBackendHealth,

    getStatus:
        getSystemStatus,

    getLiveStats:
        getLiveStats,

    getModel:
        getModelInfo,

    getDetections:
        getDetections,

    filterCurrentSessionDetections:
        filterCurrentSessionDetections,

    getDevices:
        getDevices,

    getTopology:
        getTopology,

    getTraffic:
        getTraffic,

    getProtocols:
        getProtocols,

    getAttackStats:
        getAttackStats,

    getTimeline:
        getTimeline,

    getThreatIntelligence:
        getThreatIntelligence,

    getReports:
        getReports,

    renderReports:
        renderReports,

    filterReportsForCurrentMonitoringSession:
        filterReportsForCurrentMonitoringSession,

    refresh:
        refreshDashboard,

    refreshNetworkState:
        refreshNetworkState,

    registerLiveDetection:
        registerLiveDetection,

    resetLiveDashboard:
        resetLiveDashboard,

    setMonitoringSessionStart:
        setMonitoringSessionStart,

    getMonitoringSessionStart:
        function () {

            return monitoringSessionStart;
        },

    getSessionDetections:
        function () {

            return currentSessionDetections
                .slice();
        },

    getSessionStart:
        function () {

            return monitoringSessionStart !== null
                ? new Date(
                    monitoringSessionStart
                )
                : null;
        },

    isBackendAvailable:
        function () {

            return backendAvailable;
        },

    parseTimestamp:
        parseAPITimestamp,

    formatDateTime:
        formatAPIDateTime
};


/* ============================================================
   START
   ============================================================ */

function initializeAPIClient() {

    if (
        apiInitialized
    ) {

        return;
    }


    apiInitialized =
        true;


    console.log(
        "[API] SOC API client started."
    );


    /*
     * Initial full dashboard snapshot.
     */
    refreshDashboard();


    /*
     * Refresh device inventory and topology immediately.
     *
     * This prevents the Connected Devices table from waiting
     * for the first scheduled interval.
     */
    refreshNetworkState();


    /*
     * LIVE DEVICE / TOPOLOGY REFRESH
     */
    if (
        networkRefreshTimer
    ) {

        clearInterval(
            networkRefreshTimer
        );
    }


    networkRefreshTimer =
        setInterval(
            refreshNetworkState,
            NETWORK_REFRESH_INTERVAL_MS
        );


    /*
     * Security reports refresh independently.
     */
    if (
        reportRefreshTimer
    ) {

        clearInterval(
            reportRefreshTimer
        );
    }


    reportRefreshTimer =
        setInterval(
            getReports,
            REPORT_REFRESH_INTERVAL_MS
        );


    console.log(
        `[API] Network refresh active every ${
            NETWORK_REFRESH_INTERVAL_MS / 1000
        } seconds.`
    );
}


/*
 * api.js may execute before or after DOMContentLoaded.
 */
if (
    document.readyState === "loading"
) {

    document.addEventListener(
        "DOMContentLoaded",
        initializeAPIClient,
        {
            once: true
        }
    );

} else {

    initializeAPIClient();
}