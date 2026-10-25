/* ============================================================
   SOC PLATFORM — CHARTS
   frontend/static/js/charts.js

   RESPONSIBILITIES:
   - Network Traffic
   - Attack Distribution
   - Protocol Usage
   - Threat Timeline
   - Backend status
   - Dashboard counters
   - Threat Level
   - Threat Intelligence

   LIVE OWNERSHIP
   ------------------------------------------------------------
   charts.js owns:
       - liveSessionThreatCount
       - live attack distribution
       - live threat timeline
       - threat level
       - risk display

   Historical database detections DO NOT enter live charts.
   ============================================================ */

(function () {

    "use strict";


    /* ========================================================
       CHART.JS CHECK
       ======================================================== */

    if (typeof Chart === "undefined") {

        console.error(
            "[Charts] Chart.js not loaded."
        );

        return;
    }


    Chart.defaults.color =
        "#ffffff";

    Chart.defaults.borderColor =
        "#334155";

    Chart.defaults.font.family =
        "Poppins, Arial, sans-serif";


    /* ========================================================
       STATE
       ======================================================== */

    let trafficChart = null;

    let attackChart = null;

    let protocolChart = null;

    let timelineChart = null;


    let backendConnected = false;

    let lastKnownDataAvailable = false;


    let liveSessionThreatCount = 0;


    /*
     * IMPORTANT:
     *
     * This is the BACKEND monitoring-session start.
     *
     * A browser refresh does NOT create a new SOC monitoring
     * session.
     *
     * It changes only when the backend capture session changes.
     */
    let monitoringSessionStart = null;


    const MAX_POINTS = 20;

    const MAX_CTI_ITEMS = 10;


    let initialized = false;

    let healthTimer = null;

    let statsTimer = null;


    /* ========================================================
       GENERAL HELPERS
       ======================================================== */

    function getElement(
        ...ids
    ) {

        for (const id of ids) {

            const element =
                document.getElementById(
                    id
                );

            if (element) {

                return element;
            }
        }

        return null;
    }


    function safeNumber(
        value,
        fallback = 0
    ) {

        const number =
            Number(
                value
            );

        return Number.isFinite(number)
            ? number
            : fallback;
    }


    function escapeHTML(
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


    /* ========================================================
       SOC TIMESTAMP PARSER
       ======================================================== */

    function parseSOCTimestamp(
        value = null
    ) {

        /*
         * Already a Date.
         */
        if (
            value instanceof Date
        ) {

            return value;
        }


        /*
         * UNIX timestamp.
         *
         * Backend capture_started_at uses seconds.
         * JavaScript Date uses milliseconds.
         */
        if (
            typeof value === "number"
        ) {

            return new Date(
                value < 1000000000000
                    ? value * 1000
                    : value
            );
        }


        if (value) {

            let timestamp =
                String(
                    value
                )
                    .trim();


            /*
             * Backend UTC datetime values may be emitted without
             * a timezone suffix:
             *
             *     2026-09-07T12:06:21.035644
             *
             * JavaScript otherwise interprets this as browser-local
             * time.
             *
             * Treat timezone-less ISO backend timestamps as UTC.
             */
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


            const parsed =
                new Date(
                    timestamp
                );


            if (
                !Number.isNaN(
                    parsed.getTime()
                )
            ) {

                return parsed;
            }
        }


        /*
         * Missing/invalid timestamps fall back to the browser's
         * current local time.
         */
        return new Date();
    }


    /* ========================================================
       UNIFIED LIVE TIME LABEL
       ======================================================== */

    function getTimeLabel(
        value = null
    ) {

        return parseSOCTimestamp(
            value
        )
            .toLocaleTimeString(
                [],
                {
                    hour:
                        "2-digit",

                    minute:
                        "2-digit",

                    second:
                        "2-digit"
                }
            );
    }


    function limitChartPoints(
        chart
    ) {

        if (!chart) {

            return;
        }


        while (
            chart.data.labels.length >
            MAX_POINTS
        ) {

            chart.data.labels.shift();

            chart.data.datasets.forEach(
                dataset => {

                    dataset.data.shift();
                }
            );
        }
    }


    function updateChart(
        chart
    ) {

        if (!chart) {

            return;
        }

        chart.update(
            "none"
        );
    }


    function normalizeAttackKey(
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


    function isBenignEvent(
        event
    ) {

        if (!event) {

            return false;
        }


        const type =
            normalizeAttackKey(
                event.attack_type ??
                event.attack ??
                event.label ??
                event.threat ??
                event.ml_label ??
                ""
            );


        return (
            type === "benign" ||
            type === "normal"
        );
    }


    /* ========================================================
       TRAFFIC CHART
       ======================================================== */

    function createTrafficChart() {

        const canvas =
            getElement(
                "trafficChart"
            );


        if (!canvas) {

            console.warn(
                "[Charts] trafficChart missing."
            );

            return;
        }


        trafficChart =
            new Chart(
                canvas.getContext(
                    "2d"
                ),
                {

                    type:
                        "line",

                    data: {

                        labels:
                            [],

                        datasets: [

                            {

                                label:
                                    "Incoming",

                                data:
                                    [],

                                borderColor:
                                    "#00ff88",

                                backgroundColor:
                                    "rgba(0,255,136,.08)",

                                fill:
                                    true,

                                tension:
                                    0.4,

                                borderWidth:
                                    2,

                                pointRadius:
                                    2
                            },

                            {

                                label:
                                    "Outgoing",

                                data:
                                    [],

                                borderColor:
                                    "#2196F3",

                                backgroundColor:
                                    "rgba(33,150,243,.08)",

                                fill:
                                    true,

                                tension:
                                    0.4,

                                borderWidth:
                                    2,

                                pointRadius:
                                    2
                            }

                        ]
                    },

                    options: {

                        responsive:
                            true,

                        maintainAspectRatio:
                            false,

                        animation:
                            false,

                        interaction: {

                            intersect:
                                false,

                            mode:
                                "index"
                        },

                        scales: {

                            y: {

                                beginAtZero:
                                    true
                            }
                        }
                    }
                }
            );
    }


    function updateTrafficChart(
        incoming = 0,
        outgoing = 0,
        label = null
    ) {

        if (!trafficChart) {

            return;
        }


        trafficChart
            .data
            .labels
            .push(
                getTimeLabel(
                    label
                )
            );


        trafficChart
            .data
            .datasets[0]
            .data
            .push(
                safeNumber(
                    incoming
                )
            );


        trafficChart
            .data
            .datasets[1]
            .data
            .push(
                safeNumber(
                    outgoing
                )
            );


        limitChartPoints(
            trafficChart
        );


        updateChart(
            trafficChart
        );


        lastKnownDataAvailable =
            true;
    }


    function processTrafficEvent(
        data
    ) {

        if (!data) {

            return;
        }


        const incoming =
            data.incoming ??
            data.incoming_pps ??
            data.in_bytes ??
            data.incoming_bytes ??
            data.rx ??
            data.received ??
            0;


        const outgoing =
            data.outgoing ??
            data.outgoing_pps ??
            data.out_bytes ??
            data.outgoing_bytes ??
            data.tx ??
            data.sent ??
            0;


        updateTrafficChart(
            incoming,
            outgoing,
            data.timestamp ??
            data.time ??
            null
        );


        /*
         * Packet counter is authoritative from backend.
         *
         * Browser refresh does NOT reset this value.
         */
        const total =
            data.total ??
            data.total_packets ??
            data.packet_count;


        if (
            total !== undefined &&
            total !== null
        ) {

            const packetElement =
                getElement(
                    "packetCount",
                    "packets"
                );


            if (packetElement) {

                packetElement.textContent =
                    safeNumber(
                        total
                    )
                        .toLocaleString();
            }
        }
    }


    function updateTrafficFromAPI(
        data
    ) {

        if (!data) {

            return;
        }

        processTrafficEvent(
            data
        );
    }


    /*
     * Reset only the graph data.
     *
     * This does NOT reset the authoritative backend packet count.
     */
    function clearLiveTrafficChart() {

        if (!trafficChart) {

            return;
        }


        trafficChart.data.labels =
            [];


        trafficChart
            .data
            .datasets
            .forEach(
                dataset => {

                    dataset.data =
                        [];
                }
            );


        updateChart(
            trafficChart
        );
    }


    /* ========================================================
       ATTACK DISTRIBUTION
       ======================================================== */

    function createAttackChart() {

        const canvas =
            getElement(
                "attackChart"
            );


        if (!canvas) {

            console.warn(
                "[Charts] attackChart missing."
            );

            return;
        }


        attackChart =
            new Chart(
                canvas.getContext(
                    "2d"
                ),
                {

                    type:
                        "doughnut",

                    data: {

                        labels: [

                            "DDoS",

                            "Port Scan",

                            "Brute Force",

                            "Botnet",

                            "Malware",

                            "Benign"
                        ],

                        datasets: [

                            {

                                data: [
                                    0,
                                    0,
                                    0,
                                    0,
                                    0,
                                    0
                                ],

                                backgroundColor: [

                                    "#ff5252",

                                    "#ff9800",

                                    "#ffeb3b",

                                    "#9c27b0",

                                    "#03a9f4",

                                    "#4caf50"
                                ],

                                borderWidth:
                                    0
                            }

                        ]
                    },

                    options: {

                        responsive:
                            true,

                        maintainAspectRatio:
                            false,

                        animation:
                            false,

                        cutout:
                            "62%",

                        plugins: {

                            legend: {

                                display:
                                    true,

                                position:
                                    "bottom"
                            }
                        }
                    }
                }
            );
    }


    function getAttackIndex(
        type
    ) {

        const normalized =
            normalizeAttackKey(
                type
            );


        if (
            normalized.includes(
                "ddos"
            ) ||
            normalized === "dos" ||
            normalized.includes(
                "denial"
            )
        ) {

            return 0;
        }


        if (
            normalized.includes(
                "portscan"
            ) ||
            normalized.includes(
                "scan"
            ) ||
            normalized.includes(
                "recon"
            )
        ) {

            return 1;
        }


        if (
            normalized.includes(
                "bruteforce"
            ) ||
            normalized.includes(
                "brute"
            ) ||
            normalized.includes(
                "password"
            ) ||
            normalized.includes(
                "credential"
            ) ||
            normalized.includes(
                "ssh"
            )
        ) {

            return 2;
        }


        if (
            normalized.includes(
                "bot"
            ) ||
            normalized.includes(
                "commandcontrol"
            ) ||
            normalized.includes(
                "c2"
            )
        ) {

            return 3;
        }


        if (
            normalized ===
            "benign"
            ||
            normalized ===
            "normal"
        ) {

            return 5;
        }


        return 4;
    }


    function updateAttackFromEvent(
        event
    ) {

        if (
            !attackChart ||
            !event ||
            isBenignEvent(
                event
            )
        ) {

            return;
        }


        const attackType =
            event.attack_type ??
            event.attack ??
            event.label ??
            event.threat ??
            event.ml_label ??
            "";


        const index =
            getAttackIndex(
                attackType
            );


        const current =
            safeNumber(
                attackChart
                    .data
                    .datasets[0]
                    .data[index]
            );


        attackChart
            .data
            .datasets[0]
            .data[index] =
                current + 1;


        updateChart(
            attackChart
        );
    }


    function updateAttackChart(
        values
    ) {

        if (
            !attackChart ||
            !Array.isArray(
                values
            )
        ) {

            return;
        }


        const result =
            values
                .slice(
                    0,
                    6
                )
                .map(
                    value =>
                        safeNumber(
                            value
                        )
                );


        while (
            result.length <
            6
        ) {

            result.push(
                0
            );
        }


        attackChart
            .data
            .datasets[0]
            .data =
                result;


        updateChart(
            attackChart
        );
    }


    function updateAttackDistribution(
        data
    ) {

        if (
            !data ||
            typeof data !==
            "object"
        ) {

            return;
        }


        const values = [
            0,
            0,
            0,
            0,
            0,
            0
        ];


        Object.entries(
            data
        )
            .forEach(
                (
                    [
                        key,
                        rawValue
                    ]
                ) => {

                    const index =
                        getAttackIndex(
                            key
                        );

                    values[index] +=
                        safeNumber(
                            rawValue
                        );
                }
            );


        updateAttackChart(
            values
        );
    }


    /* ========================================================
       PROTOCOL USAGE
       ======================================================== */

    function createProtocolChart() {

        const canvas =
            getElement(
                "protocolChart"
            );


        if (!canvas) {

            console.warn(
                "[Charts] protocolChart missing."
            );

            return;
        }


        protocolChart =
            new Chart(
                canvas.getContext(
                    "2d"
                ),
                {

                    type:
                        "bar",

                    data: {

                        labels: [

                            "TCP",

                            "UDP",

                            "ICMP",

                            "HTTP",

                            "HTTPS",

                            "DNS"
                        ],

                        datasets: [

                            {

                                label:
                                    "Packets",

                                data: [
                                    0,
                                    0,
                                    0,
                                    0,
                                    0,
                                    0
                                ],

                                backgroundColor: [

                                    "#4caf50",

                                    "#2196F3",

                                    "#FFC107",

                                    "#9C27B0",

                                    "#FF5722",

                                    "#00BCD4"
                                ]
                            }

                        ]
                    },

                    options: {

                        responsive:
                            true,

                        maintainAspectRatio:
                            false,

                        animation:
                            false,

                        scales: {

                            y: {

                                beginAtZero:
                                    true
                            }
                        }
                    }
                }
            );
    }


    function updateProtocolUsage(
        data
    ) {

        if (
            !protocolChart ||
            !data ||
            typeof data !==
            "object"
        ) {

            return;
        }


        protocolChart
            .data
            .datasets[0]
            .data = [

                safeNumber(
                    data.TCP ??
                    data.tcp
                ),

                safeNumber(
                    data.UDP ??
                    data.udp
                ),

                safeNumber(
                    data.ICMP ??
                    data.icmp
                ),

                safeNumber(
                    data.HTTP ??
                    data.http
                ),

                safeNumber(
                    data.HTTPS ??
                    data.https
                ),

                safeNumber(
                    data.DNS ??
                    data.dns
                )
            ];


        updateChart(
            protocolChart
        );
    }


    /* ========================================================
       THREAT TIMELINE
       ======================================================== */

    function createTimelineChart() {

        const canvas =
            getElement(
                "timelineChart"
            );


        if (!canvas) {

            console.warn(
                "[Charts] timelineChart missing."
            );

            return;
        }


        timelineChart =
            new Chart(
                canvas.getContext(
                    "2d"
                ),
                {

                    type:
                        "line",

                    data: {

                        labels:
                            [],

                        datasets: [

                            {

                                label:
                                    "Threat Score",

                                data:
                                    [],

                                borderColor:
                                    "#ff5252",

                                backgroundColor:
                                    "rgba(255,82,82,.08)",

                                fill:
                                    true,

                                tension:
                                    0.4,

                                borderWidth:
                                    2
                            }

                        ]
                    },

                    options: {

                        responsive:
                            true,

                        maintainAspectRatio:
                            false,

                        animation:
                            false,

                        scales: {

                            y: {

                                beginAtZero:
                                    true,

                                min:
                                    0,

                                max:
                                    100
                            }
                        }
                    }
                }
            );
    }


    function getEventThreatScore(
        event
    ) {

        if (!event) {

            return 0;
        }


        const candidates = [

            event.risk_score,

            event.threat_score,

            event.cti_score,

            event.combined_conf,

            event.ml_conf,

            event.lstm_conf
        ];


        for (
            const candidate of
            candidates
        ) {

            if (
                candidate === null ||
                candidate === undefined
            ) {

                continue;
            }


            let value =
                Number(
                    candidate
                );


            if (
                !Number.isFinite(
                    value
                )
            ) {

                continue;
            }


            if (
                value > 0 &&
                value <= 1
            ) {

                value *=
                    100;
            }


            return Math.max(
                0,
                Math.min(
                    100,
                    value
                )
            );
        }


        const severity =
            String(
                event.severity ??
                ""
            )
                .trim()
                .toUpperCase();


        switch (severity) {

            case "CRITICAL":
                return 100;

            case "HIGH":
                return 80;

            case "MEDIUM":
                return 60;

            case "LOW":
                return 30;

            case "INFO":
                return 10;

            default:
                return 0;
        }
    }


    function updateThreatTimeline(
        score = 0,
        label = null
    ) {

        if (!timelineChart) {

            return;
        }


        timelineChart
            .data
            .labels
            .push(
                getTimeLabel(
                    label
                )
            );


        timelineChart
            .data
            .datasets[0]
            .data
            .push(
                Math.max(
                    0,
                    Math.min(
                        100,
                        safeNumber(
                            score
                        )
                    )
                )
            );


        limitChartPoints(
            timelineChart
        );


        updateChart(
            timelineChart
        );
    }


    function updateTimelineFromDetection(
        event
    ) {

        if (
            !event ||
            isBenignEvent(
                event
            )
        ) {

            return;
        }


        updateThreatTimeline(

            getEventThreatScore(
                event
            ),

            event.timestamp ??
            event.time ??
            event.created_at ??
            null
        );
    }


    /* ========================================================
       LIVE THREAT COUNTER
       ======================================================== */

    function renderLiveThreatCount() {

        const element =
            getElement(
                "threatCount",
                "threats"
            );


        if (!element) {

            return;
        }


        element.textContent =
            liveSessionThreatCount
                .toLocaleString();
    }


    function clearLiveThreatCharts() {

        liveSessionThreatCount =
            0;


        renderLiveThreatCount();


        if (attackChart) {

            attackChart
                .data
                .datasets[0]
                .data = [
                    0,
                    0,
                    0,
                    0,
                    0,
                    0
                ];


            updateChart(
                attackChart
            );
        }


        if (timelineChart) {

            timelineChart
                .data
                .labels =
                    [];


            timelineChart
                .data
                .datasets[0]
                .data =
                    [];


            updateChart(
                timelineChart
            );
        }


        updateThreatLevel(
            0,
            "LOW"
        );
    }


    /* ========================================================
       THREAT LEVEL
       ======================================================== */

    function updateThreatLevel(
        score = 0,
        severity = null
    ) {

        const element =
            getElement(
                "threatLevel"
            );


        if (!element) {

            return;
        }


        let numericScore =
            safeNumber(
                score
            );


        if (
            numericScore > 0 &&
            numericScore <= 1
        ) {

            numericScore *=
                100;
        }


        const explicitSeverity =
            String(
                severity ??
                ""
            )
                .trim()
                .toUpperCase();


        let level;


        if (
            [
                "LOW",
                "MEDIUM",
                "HIGH",
                "CRITICAL"
            ]
                .includes(
                    explicitSeverity
                )
        ) {

            level =
                explicitSeverity;

        } else if (
            numericScore >= 80
        ) {

            level =
                "CRITICAL";

        } else if (
            numericScore >= 60
        ) {

            level =
                "HIGH";

        } else if (
            numericScore >= 30
        ) {

            level =
                "MEDIUM";

        } else {

            level =
                "LOW";
        }


        element.textContent =
            level;


        element
            .classList
            .remove(
                "safe",
                "warning",
                "danger",
                "critical"
            );


        if (
            level ===
            "CRITICAL"
        ) {

            element
                .classList
                .add(
                    "critical"
                );

        } else if (
            level ===
            "HIGH"
        ) {

            element
                .classList
                .add(
                    "danger"
                );

        } else if (
            level ===
            "MEDIUM"
        ) {

            element
                .classList
                .add(
                    "warning"
                );

        } else {

            element
                .classList
                .add(
                    "safe"
                );
        }
    }


    /* ========================================================
       THREAT INTELLIGENCE STYLING
       ======================================================== */

    function ensureCTIStyles() {

        if (
            document.getElementById(
                "soc-cti-styles"
            )
        ) {

            return;
        }


        const style =
            document.createElement(
                "style"
            );


        style.id =
            "soc-cti-styles";


        style.textContent = `

            #threatFeed,
            #threatIntelligence,
            #ctiFeed {
                display: block;
                width: 100%;
                box-sizing: border-box;
                overflow-x: hidden;
            }

            .threat-intel-item {
                display: block;
                width: 100%;
                box-sizing: border-box;

                margin: 0 0 14px 0;
                padding: 16px;

                border: 1px solid rgba(148, 163, 184, 0.16);
                border-radius: 12px;

                background:
                    rgba(15, 23, 42, 0.65);

                overflow: hidden;
            }

            .cti-header {
                display: flex;
                justify-content: space-between;
                align-items: flex-start;

                gap: 15px;

                flex-wrap: wrap;

                margin-bottom: 14px;
            }

            .cti-identity {
                min-width: 0;
                flex: 1 1 240px;
            }

            .cti-ip {
                color: #ffffff;

                font-size: 16px;
                font-weight: 700;

                overflow-wrap: anywhere;
            }

            .cti-event-meta {
                margin-top: 4px;

                color: #94a3b8;

                font-size: 13px;

                overflow-wrap: anywhere;
            }

            .cti-badges {
                display: flex;
                flex-wrap: wrap;

                gap: 7px;
            }

            .cti-badge {
                display: inline-flex;

                padding: 5px 9px;

                border-radius: 999px;

                font-size: 12px;
                font-weight: 600;

                white-space: nowrap;
            }

            .cti-risk-label {
                color: #93c5fd;

                border:
                    1px solid
                    rgba(96, 165, 250, 0.25);

                background:
                    rgba(59, 130, 246, 0.12);
            }

            .cti-risk-score {
                color: #fca5a5;

                border:
                    1px solid
                    rgba(248, 113, 113, 0.24);

                background:
                    rgba(239, 68, 68, 0.10);
            }

            .cti-grid {
                display: grid;

                grid-template-columns:
                    repeat(
                        auto-fit,
                        minmax(190px, 1fr)
                    );

                gap: 10px;

                width: 100%;
            }

            .cti-source-card {
                min-width: 0;

                padding: 11px 12px;

                border-radius: 9px;

                background:
                    rgba(2, 6, 23, 0.42);

                border:
                    1px solid
                    rgba(148, 163, 184, 0.08);
            }

            .cti-source-name {
                margin-bottom: 5px;

                color: #64748b;

                font-size: 11px;
                font-weight: 700;

                text-transform: uppercase;

                letter-spacing: 0.06em;
            }

            .cti-source-value {
                color: #cbd5e1;

                font-size: 13px;

                line-height: 1.55;

                overflow-wrap: anywhere;
                word-break: break-word;
            }

            .cti-empty {
                color: #64748b;
            }

        `;


        document.head.appendChild(
            style
        );
    }


    /* ========================================================
       THREAT INTELLIGENCE HELPERS
       ======================================================== */

    function formatCTIValue(
        value,
        fallback = "N/A"
    ) {

        if (
            value === null ||
            value === undefined ||
            value === ""
        ) {

            return fallback;
        }


        if (
            typeof value ===
            "boolean"
        ) {

            return value
                ? "Yes"
                : "No";
        }


        if (
            typeof value ===
            "number"
        ) {

            return Number.isFinite(
                value
            )
                ? String(
                    value
                )
                : fallback;
        }


        if (
            Array.isArray(
                value
            )
        ) {

            if (
                value.length ===
                0
            ) {

                return fallback;
            }


            return value
                .slice(
                    0,
                    5
                )
                .map(
                    item => {

                        if (
                            item &&
                            typeof item ===
                            "object"
                        ) {

                            return (

                                item.id ??

                                item.cve ??

                                item.name ??

                                item.indicator ??

                                "Item"
                            );
                        }


                        return String(
                            item
                        );
                    }
                )
                .join(
                    ", "
                );
        }


        if (
            typeof value ===
            "object"
        ) {

            const preferredKeys = [

                "score",

                "confidence",

                "abuseConfidenceScore",

                "malicious",

                "reputation",

                "pulse_count",

                "count",

                "status"
            ];


            for (
                const key of
                preferredKeys
            ) {

                if (
                    value[key] !==
                    undefined
                    &&
                    value[key] !==
                    null
                    &&
                    value[key] !==
                    ""
                ) {

                    return formatCTIValue(
                        value[key],
                        fallback
                    );
                }
            }


            const keys =
                Object.keys(
                    value
                );


            if (
                keys.length ===
                0
            ) {

                return fallback;
            }


            return keys
                .slice(
                    0,
                    4
                )
                .join(
                    ", "
                );
        }


        return String(
            value
        );
    }


    function getCTISourceSummary(
        details,
        sourceName
    ) {

        if (
            !details ||
            typeof details !==
            "object"
        ) {

            return "No data";
        }


        const value =
            details[
                sourceName
            ];


        if (
            value === null ||
            value === undefined
        ) {

            return "No data";
        }


        if (
            typeof value !==
            "object"
        ) {

            return formatCTIValue(
                value
            );
        }


        if (
            Object.keys(
                value
            ).length ===
            0
        ) {

            return "No result";
        }


        switch (
            sourceName
        ) {

            case "abuseipdb":

                if (
                    value.abuseConfidenceScore !==
                    undefined
                ) {

                    return (
                        "Abuse score: " +
                        formatCTIValue(
                            value.abuseConfidenceScore
                        )
                    );
                }


                if (
                    value.score !==
                    undefined
                ) {

                    return (
                        "Score: " +
                        formatCTIValue(
                            value.score
                        )
                    );
                }


                if (
                    value.countryCode
                ) {

                    return (
                        "Country: " +
                        formatCTIValue(
                            value.countryCode
                        )
                    );
                }


                return formatCTIValue(
                    value
                );


            case "virustotal":

                if (
                    value.malicious !==
                    undefined
                ) {

                    return (
                        "Malicious: " +
                        formatCTIValue(
                            value.malicious
                        )
                    );
                }


                if (
                    value.reputation !==
                    undefined
                ) {

                    return (
                        "Reputation: " +
                        formatCTIValue(
                            value.reputation
                        )
                    );
                }


                return formatCTIValue(
                    value
                );


            case "otx":

                if (
                    value.pulse_count !==
                    undefined
                ) {

                    return (
                        "Pulses: " +
                        formatCTIValue(
                            value.pulse_count
                        )
                    );
                }


                if (
                    value.count !==
                    undefined
                ) {

                    return (
                        "Count: " +
                        formatCTIValue(
                            value.count
                        )
                    );
                }


                return formatCTIValue(
                    value
                );


            default:

                return formatCTIValue(
                    value
                );
        }
    }


    function formatCVEs(
        cves
    ) {

        if (
            !Array.isArray(
                cves
            ) ||
            cves.length ===
            0
        ) {

            return "None";
        }


        return cves
            .slice(
                0,
                5
            )
            .map(
                cve => {

                    if (
                        cve &&
                        typeof cve ===
                        "object"
                    ) {

                        return (

                            cve.id ??

                            cve.cve ??

                            cve.name ??

                            "CVE"
                        );
                    }


                    return String(
                        cve
                    );
                }
            )
            .join(
                ", "
            );
    }


    /* ========================================================
       THREAT INTELLIGENCE
       ======================================================== */

    function updateThreatIntelligence(
        data
    ) {

        const container =
            getElement(
                "threatFeed",
                "threatIntelligence",
                "ctiFeed"
            );


        if (
            !container ||
            !data
        ) {

            return;
        }


        ensureCTIStyles();


        const details =
            data.cti_details ??
            {};


        /*
         * socket.js can call CTI during both initial and enriched
         * stages.
         *
         * The initial event normally contains an empty CTI object.
         * Do not create a useless empty card for that stage.
         */

        const hasCTIData =
            details &&
            typeof details ===
            "object" &&
            Object.keys(
                details
            ).length >
            0;


        const hasRiskData =
            data.cti_score !==
            undefined
            &&
            data.cti_score !==
            null;


        if (
            !hasCTIData &&
            !hasRiskData
        ) {

            return;
        }


        const sourceIP =
            data.src_ip ??
            data.source_ip ??
            "Unknown";


        const attackType =
            data.attack_type ??
            data.attack ??
            data.label ??
            "Threat";


        const score =
            data.cti_score ??
            data.risk_score ??
            null;


        const label =
            data.cti_label ??
            data.risk_label ??
            data.severity ??
            "UNKNOWN";


        const eventId =
            data.id ??
            data.event_id ??
            (
                String(
                    sourceIP
                ) +
                "-" +
                String(
                    data.timestamp ??
                    data.time ??
                    attackType
                )
            );


        const timestamp =
            data.timestamp ??
            data.time ??
            data.created_at ??
            null;


        const abuseSummary =
            getCTISourceSummary(
                details,
                "abuseipdb"
            );


        const vtSummary =
            getCTISourceSummary(
                details,
                "virustotal"
            );


        const otxSummary =
            getCTISourceSummary(
                details,
                "otx"
            );


        const kevCount =
            safeNumber(
                details.kev_count ??
                details.kev_hits ??
                0
            );


        const maxEpss =
            safeNumber(
                details.max_epss ??
                0
            );


        const cves =
            Array.isArray(
                details.cves
            )
                ? details.cves
                : [];


        let numericScore =
            safeNumber(
                score,
                0
            );


        if (
            numericScore > 0 &&
            numericScore <= 1
        ) {

            numericScore *=
                100;
        }


        const riskScoreText =
            (
                score === null ||
                score === undefined ||
                score === ""
            )
                ? "N/A"
                : Math.round(
                    numericScore
                );


        /*
         * Remove placeholder.
         */

        const placeholder =
            container.querySelector(
                "p"
            );


        if (placeholder) {

            placeholder.remove();
        }


        /*
         * Remove an existing card for this same event.
         *
         * This prevents:
         *
         * initial event
         * enriched event
         *
         * from becoming two CTI cards.
         */

        const existing =
            Array
                .from(
                    container
                        .querySelectorAll(
                            ".threat-intel-item"
                        )
                )
                .find(
                    element =>
                        element.dataset.eventId ===
                        String(
                            eventId
                        )
                );


        if (existing) {

            existing.remove();
        }


        const item =
            document.createElement(
                "article"
            );


        item.className =
            "threat-intel-item";


        item.dataset.eventId =
            String(
                eventId
            );


        const timeText =
            timestamp
                ? getTimeLabel(
                    timestamp
                )
                : "";


        item.innerHTML = `

            <div class="cti-header">

                <div class="cti-identity">

                    <div class="cti-ip">

                        ${escapeHTML(sourceIP)}

                    </div>

                    <div class="cti-event-meta">

                        ${escapeHTML(attackType)}

                        ${
                            timeText
                                ? " • " +
                                  escapeHTML(
                                      timeText
                                  )
                                : ""
                        }

                    </div>

                </div>


                <div class="cti-badges">

                    <span
                        class="
                            cti-badge
                            cti-risk-label
                        "
                    >

                        ${escapeHTML(label)}

                    </span>


                    <span
                        class="
                            cti-badge
                            cti-risk-score
                        "
                    >

                        Risk
                        ${escapeHTML(riskScoreText)}

                    </span>

                </div>

            </div>


            <div class="cti-grid">


                <div class="cti-source-card">

                    <div class="cti-source-name">

                        AbuseIPDB

                    </div>

                    <div class="cti-source-value">

                        ${escapeHTML(abuseSummary)}

                    </div>

                </div>


                <div class="cti-source-card">

                    <div class="cti-source-name">

                        VirusTotal

                    </div>

                    <div class="cti-source-value">

                        ${escapeHTML(vtSummary)}

                    </div>

                </div>


                <div class="cti-source-card">

                    <div class="cti-source-name">

                        AlienVault OTX

                    </div>

                    <div class="cti-source-value">

                        ${escapeHTML(otxSummary)}

                    </div>

                </div>


                <div class="cti-source-card">

                    <div class="cti-source-name">

                        Vulnerability Intelligence

                    </div>

                    <div class="cti-source-value">

                        KEV:
                        ${escapeHTML(kevCount)}

                        <br>

                        Max EPSS:
                        ${escapeHTML(maxEpss)}

                        <br>

                        CVEs:
                        ${escapeHTML(
                            formatCVEs(
                                cves
                            )
                        )}

                    </div>

                </div>


            </div>
        `;


        container.prepend(
            item
        );


        /*
         * Keep only newest CTI cards.
         */

        const items =
            container
                .querySelectorAll(
                    ".threat-intel-item"
                );


        for (
            let index =
                MAX_CTI_ITEMS;

            index <
            items.length;

            index++
        ) {

            items[index]
                .remove();
        }


        console.log(
            "[Charts] CTI updated:",
            sourceIP,
            attackType
        );
    }


    /* ========================================================
       MONITORING SESSION
       ======================================================== */

    function extractMonitoringSessionStart(
        data
    ) {

        if (
            !data ||
            typeof data !==
            "object"
        ) {

            return null;
        }


        return (
            data.capture_started_at ??
            data.session_started_at ??
            data.capture?.capture_started_at ??
            data.capture?.started_at ??
            null
        );
    }


    function normalizeMonitoringSessionStart(
        value
    ) {

        if (
            value === null ||
            value === undefined ||
            value === ""
        ) {

            return null;
        }


        /*
         * Backend capture_started_at is normally UNIX seconds.
         */
        if (
            typeof value ===
            "number"
        ) {

            const milliseconds =
                value < 1000000000000
                    ? value * 1000
                    : value;


            return Number.isFinite(
                milliseconds
            )
                ? milliseconds
                : null;
        }


        const parsed =
            parseSOCTimestamp(
                value
            );


        const milliseconds =
            parsed.getTime();


        return Number.isFinite(
            milliseconds
        )
            ? milliseconds
            : null;
    }


    function setMonitoringSessionStart(
        value
    ) {

        const next =
            normalizeMonitoringSessionStart(
                value
            );


        if (
            next === null
        ) {

            return false;
        }


        /*
         * First API response after page load.
         *
         * This establishes the existing backend session.
         *
         * DO NOT clear the packet counter because F5 is not
         * a new backend monitoring session.
         */
        if (
            monitoringSessionStart ===
            null
        ) {

            monitoringSessionStart =
                next;


            console.log(
                "[Charts] Backend monitoring session:",
                new Date(
                    monitoringSessionStart
                )
                    .toLocaleString()
            );


            return false;
        }


        /*
         * Same backend session.
         */
        if (
            monitoringSessionStart ===
            next
        ) {

            return false;
        }


        /*
         * capture_started_at changed.
         *
         * This means the backend monitoring/capture session
         * restarted.
         */
        monitoringSessionStart =
            next;


        console.log(
            "[Charts] New backend monitoring session detected:",
            new Date(
                monitoringSessionStart
            )
                .toLocaleString()
        );


        /*
         * Reset only LIVE session presentation.
         *
         * Backend packet counter will shortly overwrite the packet
         * card with the new capture count.
         */
        clearLiveThreatCharts();

        clearLiveTrafficChart();


        /*
         * Reset protocol visualization until the new backend
         * session stats arrive.
         */
        if (protocolChart) {

            protocolChart
                .data
                .datasets[0]
                .data = [
                    0,
                    0,
                    0,
                    0,
                    0,
                    0
                ];


            updateChart(
                protocolChart
            );
        }


        /*
         * Clear current live CTI only.
         */
        const feed =
            getElement(
                "threatFeed",
                "threatIntelligence",
                "ctiFeed"
            );


        if (feed) {

            feed.innerHTML = `
                <p class="cti-empty">
                    No live threat intelligence.
                </p>
            `;
        }


        return true;
    }


    function getMonitoringSessionStart() {

        return monitoringSessionStart;
    }


    function isEventInCurrentMonitoringSession(
        event
    ) {

        if (!event) {

            return false;
        }


        /*
         * If the backend session is not known yet, do not reject
         * real-time events.
         */
        if (
            monitoringSessionStart ===
            null
        ) {

            return true;
        }


        const timestamp =
            event.timestamp ??
            event.time ??
            event.created_at ??
            null;


        /*
         * Socket events without a timestamp are assumed live.
         */
        if (!timestamp) {

            return true;
        }


        const eventTime =
            parseSOCTimestamp(
                timestamp
            )
                .getTime();


        if (
            !Number.isFinite(
                eventTime
            )
        ) {

            return true;
        }


        /*
         * Allow a small clock/timing tolerance around startup.
         */
        return (
            eventTime >=
            monitoringSessionStart -
            3000
        );
    }


    /* ========================================================
       DASHBOARD STATS
       ======================================================== */

    function updateDashboardStats(
        data
    ) {

        if (
            !data ||
            typeof data !==
            "object"
        ) {

            return;
        }


        /*
         * Establish/check the backend capture session first.
         */
        setMonitoringSessionStart(
            extractMonitoringSessionStart(
                data
            )
        );


        /* ====================================================
           PACKET COUNT
           ==================================================== */

        const packetElement =
            getElement(
                "packetCount",
                "packets"
            );


        /*
         * Support both top-level and /api/status nested capture
         * structures.
         */
        const packets =
            data.capture?.total_packets ??
            data.capture?.packet_count ??
            data.capture?.packets ??
            data.total_packets ??
            data.packet_count ??
            data.packets ??
            data.total;


        if (
            packetElement &&
            packets !== undefined &&
            packets !== null
        ) {

            packetElement.textContent =
                safeNumber(
                    packets
                )
                    .toLocaleString();
        }


        /*
         * IMPORTANT:
         *
         * Backend API threat totals must NOT replace the locally
         * owned live-session threat counter.
         */
        renderLiveThreatCount();


        /* ====================================================
           DEVICE COUNT
           ==================================================== */

        const deviceElement =
            getElement(
                "deviceCount",
                "devices"
            );


        let devices =
            data.connected_devices ??
            data.device_count ??
            data.total_devices;


        if (
            devices === undefined &&
            Array.isArray(
                data.devices
            )
        ) {

            devices =
                data.devices.length;
        }


        if (
            deviceElement &&
            devices !== undefined &&
            devices !== null &&
            typeof devices !==
            "object"
        ) {

            deviceElement.textContent =
                safeNumber(
                    devices
                )
                    .toLocaleString();
        }


        /* ====================================================
           RISK
           ==================================================== */

        const risk =
            data.risk_score ??
            data.threat_score ??
            data.cti_score;


        if (
            risk !== undefined &&
            risk !== null
        ) {

            const riskElement =
                getElement(
                    "riskScore"
                );


            let score =
                safeNumber(
                    risk
                );


            if (
                score > 0 &&
                score <= 1
            ) {

                score *=
                    100;
            }


            if (riskElement) {

                riskElement.textContent =
                    Math.round(
                        score
                    );
            }


            updateThreatLevel(

                risk,

                data.severity ??
                data.threat_level ??
                data.risk_level
            );
        }
    }


    /* ========================================================
       LIVE DETECTION
       ======================================================== */

    function processDetectionEvent(
        event
    ) {

        if (!event) {

            return;
        }


        if (
            isBenignEvent(
                event
            )
        ) {

            return;
        }


        /*
         * Historical/previous-session events must never enter
         * the current live charts.
         */
        if (
            !isEventInCurrentMonitoringSession(
                event
            )
        ) {

            console.log(
                "[Charts] Previous-session detection ignored:",
                event.id ??
                event.event_id ??
                event.detection_id ??
                "unknown"
            );


            return;
        }


        /*
         * socket.js performs event-ID de-duplication.
         *
         * Therefore every accepted call here represents one
         * authoritative NEW live detection.
         */
        liveSessionThreatCount++;


        renderLiveThreatCount();


        updateAttackFromEvent(
            event
        );


        updateTimelineFromDetection(
            event
        );


        const score =
            getEventThreatScore(
                event
            );


        const riskElement =
            getElement(
                "riskScore"
            );


        if (riskElement) {

            riskElement.textContent =
                Math.round(
                    score
                );
        }


        updateThreatLevel(
            score,
            event.severity
        );


        lastKnownDataAvailable =
            true;


        console.log(
            "[Charts] Live detection processed:",
            event.attack_type ??
            event.attack ??
            event.label
        );
    }


    /* ========================================================
       BACKEND STATUS
       ======================================================== */

    function setBackendStatus(
        status
    ) {

        const indicator =
            getElement(
                "statusIndicator"
            );


        const text =
            getElement(
                "statusText"
            );


        const container =
            getElement(
                "backendStatus"
            );


        if (
            !indicator ||
            !text
        ) {

            return;
        }


        const classes = [

            "connecting",

            "live",

            "offline",

            "last-known",

            "online"
        ];


        indicator
            .classList
            .remove(
                ...classes
            );


        if (container) {

            container
                .classList
                .remove(
                    ...classes
                );
        }


        if (
            status ===
            "connecting"
        ) {

            indicator
                .classList
                .add(
                    "connecting"
                );


            if (container) {

                container
                    .classList
                    .add(
                        "connecting"
                    );
            }


            text.textContent =
                "🟡 CONNECTING...";


            backendConnected =
                false;


            return;
        }


        if (
            status ===
            "live"
        ) {

            indicator
                .classList
                .add(
                    "live"
                );


            if (container) {

                container
                    .classList
                    .add(
                        "live"
                    );
            }


            text.textContent =
                "🟢 LIVE — Real-time data";


            backendConnected =
                true;


            lastKnownDataAvailable =
                true;


            return;
        }


        if (
            status ===
            "last-known"
        ) {

            indicator
                .classList
                .add(
                    "last-known"
                );


            if (container) {

                container
                    .classList
                    .add(
                        "last-known"
                    );
            }


            text.textContent =
                "🟠 OFFLINE — Showing last known data";


            backendConnected =
                false;


            return;
        }


        indicator
            .classList
            .add(
                "offline"
            );


        if (container) {

            container
                .classList
                .add(
                    "offline"
                );
        }


        text.textContent =
            "🔴 OFFLINE — Backend Disconnected";


        backendConnected =
            false;
    }


    async function checkBackendConnection() {

        try {

            const response =
                await fetch(
                    "/api/health",
                    {
                        cache:
                            "no-store"
                    }
                );


            if (!response.ok) {

                throw new Error(
                    `HTTP ${response.status}`
                );
            }


            const data =
                await response.json();


            if (
                data &&
                (
                    data.status ===
                    "ok"
                    ||
                    data.status ===
                    "running"
                    ||
                    data.status ===
                    "online"
                )
            ) {

                setBackendStatus(
                    "live"
                );

            } else {

                setBackendStatus(
                    lastKnownDataAvailable
                        ? "last-known"
                        : "offline"
                );
            }

        } catch (error) {

            setBackendStatus(
                lastKnownDataAvailable
                    ? "last-known"
                    : "offline"
            );
        }
    }


    /* ========================================================
       API LOADERS
       ======================================================== */

    async function loadLiveStats() {

        try {

            const response =
                await fetch(
                    "/api/live-stats",
                    {
                        cache:
                            "no-store"
                    }
                );


            if (!response.ok) {

                throw new Error(
                    `HTTP ${response.status}`
                );
            }


            const data =
                await response.json();


            updateDashboardStats(
                data
            );


            lastKnownDataAvailable =
                true;

        } catch (error) {

            console.warn(
                "[Charts] live-stats failed:",
                error.message
            );
        }
    }


    async function loadTrafficData() {

        try {

            const response =
                await fetch(
                    "/api/traffic",
                    {
                        cache:
                            "no-store"
                    }
                );


            if (!response.ok) {

                throw new Error(
                    `HTTP ${response.status}`
                );
            }


            const data =
                await response.json();


            updateTrafficFromAPI(
                data
            );


            if (
                data.by_protocol
            ) {

                updateProtocolUsage(
                    data.by_protocol
                );
            }

        } catch (error) {

            console.warn(
                "[Charts] traffic API failed:",
                error.message
            );
        }
    }


    async function loadProtocolData() {

        try {

            const response =
                await fetch(
                    "/api/protocols",
                    {
                        cache:
                            "no-store"
                    }
                );


            if (!response.ok) {

                throw new Error(
                    `HTTP ${response.status}`
                );
            }


            const data =
                await response.json();


            updateProtocolUsage(

                data.protocols ??

                data.by_protocol ??

                data.data ??

                data
            );

        } catch (error) {

            console.warn(
                "[Charts] protocols API failed:",
                error.message
            );
        }
    }


    async function loadBackendStatusData() {

        try {

            const response =
                await fetch(
                    "/api/status",
                    {
                        cache:
                            "no-store"
                    }
                );


            if (!response.ok) {

                throw new Error(
                    `HTTP ${response.status}`
                );
            }


            const data =
                await response.json();


            updateDashboardStats(
                data
            );

        } catch (error) {

            console.warn(
                "[Charts] status API failed:",
                error.message
            );
        }
    }


    /*
     * Historical functions preserved for compatibility.
     *
     * They intentionally do not inject old database detections
     * into live-session charts.
     */

    async function loadAttackData() {

        return null;
    }


    async function loadTimelineData() {

        return null;
    }


    async function loadRecentDetections() {

        return null;
    }


    /* ========================================================
       PERIODIC DATA
       ======================================================== */

    async function loadAllDashboardData() {

        await Promise.allSettled(
            [

                /*
                 * /api/status establishes capture_started_at
                 * and the authoritative packet counter.
                 */
                loadBackendStatusData(),

                loadLiveStats(),

                loadTrafficData(),

                loadProtocolData()
            ]
        );


        /*
         * API polling must never replace the locally-owned
         * live detection counter.
         */
        renderLiveThreatCount();
    }


    /* ========================================================
       INITIALIZATION
       ======================================================== */

    function initializeCharts() {

        if (initialized) {

            return;
        }


        initialized =
            true;


        console.log(
            "[Charts] Initializing SOC charts..."
        );


        ensureCTIStyles();


        createTrafficChart();

        createAttackChart();

        createProtocolChart();

        createTimelineChart();


        /*
         * A new browser document starts with empty live threat
         * visualization.
         *
         * socket.js/api.js will be responsible for preserving
         * same-backend-session live alert state where required.
         *
         * Packet count is NOT forced to zero here.
         */
        clearLiveThreatCharts();


        setBackendStatus(
            "connecting"
        );


        checkBackendConnection();


        loadAllDashboardData();


        healthTimer =
            setInterval(
                checkBackendConnection,
                5000
            );


        statsTimer =
            setInterval(
                loadAllDashboardData,
                5000
            );


        console.log(
            "[Charts] SOC charts initialized."
        );
    }


    /* ========================================================
       PUBLIC API
       ======================================================== */

    window.socCharts = {

        get trafficChart() {

            return trafficChart;
        },

        get attackChart() {

            return attackChart;
        },

        get protocolChart() {

            return protocolChart;
        },

        get timelineChart() {

            return timelineChart;
        },


        setBackendStatus:
            setBackendStatus,

        checkBackendConnection:
            checkBackendConnection,


        updateTrafficChart:
            updateTrafficChart,

        updateTrafficFromAPI:
            updateTrafficFromAPI,

        processTrafficEvent:
            processTrafficEvent,


        parseSOCTimestamp:
            parseSOCTimestamp,

        getTimeLabel:
            getTimeLabel,


        setMonitoringSessionStart:
            setMonitoringSessionStart,

        getMonitoringSessionStart:
            getMonitoringSessionStart,

        isEventInCurrentMonitoringSession:
            isEventInCurrentMonitoringSession,


        clearLiveTrafficChart:
            clearLiveTrafficChart,


        updateAttackChart:
            updateAttackChart,

        updateAttackDistribution:
            updateAttackDistribution,

        updateAttackFromEvent:
            updateAttackFromEvent,


        updateProtocolUsage:
            updateProtocolUsage,


        updateThreatTimeline:
            updateThreatTimeline,

        updateTimelineFromDetection:
            updateTimelineFromDetection,


        getEventThreatScore:
            getEventThreatScore,

        updateThreatLevel:
            updateThreatLevel,

        updateThreatIntelligence:
            updateThreatIntelligence,


        updateDashboardStats:
            updateDashboardStats,


        processDetectionEvent:
            processDetectionEvent,


        loadBackendStatusData:
            loadBackendStatusData,

        loadLiveStats:
            loadLiveStats,

        loadTrafficData:
            loadTrafficData,

        loadProtocolData:
            loadProtocolData,

        loadAttackData:
            loadAttackData,

        loadTimelineData:
            loadTimelineData,

        loadRecentDetections:
            loadRecentDetections,


        clearLiveThreatCharts:
            clearLiveThreatCharts
    };


    /* ========================================================
       COMPATIBILITY GLOBALS
       ======================================================== */

    window.updateTrafficChart =
        updateTrafficChart;


    window.updateAttackChart =
        updateAttackChart;


    window.updateAttackCharts =
        function (
            event
        ) {

            updateAttackFromEvent(
                event
            );
        };


    window.updateProtocolUsage =
        updateProtocolUsage;


    window.updateThreatTimeline =
        updateThreatTimeline;


    window.updateThreatLevel =
        updateThreatLevel;


    window.updateThreatIntelligence =
        updateThreatIntelligence;


    window.updateDashboardStats =
        updateDashboardStats;


    window.processTrafficEvent =
        processTrafficEvent;


    /*
     * socket.js/api.js can use the exact same timestamp formatter.
     */
    window.formatSOCLiveTime =
        getTimeLabel;


    window.parseSOCTimestamp =
        parseSOCTimestamp;


    window.processDetectionEvent =
        processDetectionEvent;


    /* ========================================================
       START
       ======================================================== */

    if (
        document.readyState ===
        "loading"
    ) {

        document.addEventListener(
            "DOMContentLoaded",
            initializeCharts
        );

    } else {

        initializeCharts();
    }

})();