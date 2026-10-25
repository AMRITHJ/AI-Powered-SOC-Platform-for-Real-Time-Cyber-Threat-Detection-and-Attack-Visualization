/* ============================================================
   SOC PLATFORM — NETWORK TOPOLOGY
   frontend/topology.js

   Purpose:
   - Render backend /api/topology data
   - Support VMNET1 switch
   - Support SOC / Kali / Ubuntu / Cowrie
   - Support PC01-PC20
   - Preserve backend node IDs
   - Support API + Socket.IO updates
   - Responsive canvas
   - Live connection animation
   ============================================================ */

(function () {

    "use strict";

    let topologyCanvas = null;
    let topologyCtx = null;

    let devices = [];
    let connections = [];

    let initialized = false;
    let animationFrame = null;


    /* ============================================================
       CONFIGURATION
       ============================================================ */

    const CONFIG = {

        maxDevices: 40,

        nodeRadius: 24,
        coreRadius: 28,
        switchRadius: 30,

        animationSpeed: 0.00035,

        colors: {

            soc: "#8b5cf6",

            attacker: "#ff3b5c",

            server: "#00ff88",

            honeypot: "#a259ff",

            switch: "#4da3ff",

            router: "#ffaa00",

            firewall: "#ff8800",

            workstation: "#00e5ff",

            device: "#00e5ff",

            offline: "#666666",

            connection: "#00d9ff",

            text: "#ffffff",

            subText: "#8fa5b5"
        }
    };


    /* ============================================================
       INITIALIZE
       ============================================================ */

    function initTopology() {

        topologyCanvas =
            document.getElementById(
                "topologyCanvas"
            );

        if (!topologyCanvas) {

            console.warn(
                "[Topology] #topologyCanvas not found."
            );

            return;
        }

        topologyCtx =
            topologyCanvas.getContext(
                "2d"
            );

        if (!topologyCtx) {

            console.error(
                "[Topology] Canvas context unavailable."
            );

            return;
        }

        initialized = true;

        resizeCanvas();

        window.addEventListener(
            "resize",
            resizeCanvas
        );

        topologyCanvas.addEventListener(
            "click",
            handleCanvasClick
        );

        topologyCanvas.addEventListener(
            "mousemove",
            handleMouseMove
        );

        loadTopology();

        animate();

        console.log(
            "[Topology] Initialized successfully."
        );
    }


    /* ============================================================
       RESPONSIVE CANVAS
       ============================================================ */

    function resizeCanvas() {

        if (
            !topologyCanvas ||
            !topologyCtx
        ) {
            return;
        }

        const rect =
            topologyCanvas.getBoundingClientRect();

        const width =
            Math.max(
                rect.width,
                300
            );

        const height =
            Math.max(
                rect.height,
                450
            );

        const dpr =
            window.devicePixelRatio || 1;

        topologyCanvas.width =
            Math.floor(
                width * dpr
            );

        topologyCanvas.height =
            Math.floor(
                height * dpr
            );

        topologyCanvas.style.width =
            `${width}px`;

        topologyCanvas.style.height =
            `${height}px`;

        topologyCtx.setTransform(
            dpr,
            0,
            0,
            dpr,
            0,
            0
        );

        arrangeDevices();

        drawTopology();
    }


    /* ============================================================
       LOAD TOPOLOGY
       ============================================================ */

    async function loadTopology() {

        try {

            if (
                window.API &&
                typeof window.API.getTopology ===
                    "function"
            ) {

                /*
                 * false prevents api.js from rendering
                 * topology separately.
                 */

                const data =
                    await window.API.getTopology(
                        false
                    );

                if (
                    data &&
                    (
                        Array.isArray(data.nodes) ||
                        Array.isArray(data.devices)
                    )
                ) {

                    updateTopology(data);

                    console.log(
                        `[Topology] Loaded ${devices.length} nodes and ${connections.length} links from backend.`
                    );

                    return;
                }
            }

        } catch (error) {

            console.warn(
                "[Topology] Backend unavailable:",
                error
            );
        }

        createFallbackTopology();
    }


    /* ============================================================
       UPDATE COMPLETE TOPOLOGY
       ============================================================ */

    function updateTopology(data) {

        if (!data) {
            return;
        }

        /*
         * Prefer nodes because the backend nodes array
         * contains the topology-only VMnet1 switch.
         */

        let incomingDevices =
            Array.isArray(data.nodes)

                ? data.nodes

                : Array.isArray(data.devices)

                    ? data.devices

                    : [];


        let incomingConnections =
            Array.isArray(data.links)

                ? data.links

                : Array.isArray(data.connections)

                    ? data.connections

                    : Array.isArray(data.edges)

                        ? data.edges

                        : [];


        if (incomingDevices.length > 0) {

            devices =
                incomingDevices
                    .slice(
                        0,
                        CONFIG.maxDevices
                    )
                    .map(
                        normalizeDevice
                    );
        }


        if (incomingConnections.length > 0) {

            connections =
                incomingConnections
                    .map(
                        normalizeConnection
                    )
                    .filter(Boolean);

        } else {

            connections = [];
        }


        if (
            devices.length > 0 &&
            connections.length === 0
        ) {

            generateConnections();
        }


        ensureSOCDevice();

        updateConnectedDeviceCard(
            data
        );

        arrangeDevices();

        drawTopology();
    }


    /* ============================================================
       NORMALIZE DEVICE
       ============================================================ */

    function normalizeDevice(
        device,
        index
    ) {

        const input =
            device || {};

        const ip =
            input.ip ??
            input.ip_address ??
            input.address ??
            null;

        const hostname =
            input.hostname ??
            input.host ??
            input.name ??
            ip ??
            `Device-${index + 1}`;

        const name =
            input.name ??
            input.hostname ??
            input.host ??
            ip ??
            `Device ${index + 1}`;

        const os =
            input.os ??
            input.operating_system ??
            input.platform ??
            "Unknown";

        const type =
            String(
                input.type ??
                input.role ??
                detectDeviceType({
                    name,
                    hostname,
                    os,
                    ip
                })
            )
                .toLowerCase();

        /*
         * Preserve backend IDs.
         */

        const id =
            String(
                input.id ??
                ip ??
                hostname ??
                `device-${index}`
            );

        return {

            ...input,

            id,

            name,

            hostname,

            ip:
                ip ?? "",

            os,

            status:
                normalizeStatus(
                    input.status ??
                    input.online
                ),

            type,

            x: 0,

            y: 0,

            radius:

                type === "switch"

                    ? CONFIG.switchRadius

                    : [
                        "soc",
                        "attacker",
                        "server",
                        "honeypot",
                        "router",
                        "firewall"
                    ].includes(type)

                        ? CONFIG.coreRadius

                        : CONFIG.nodeRadius,

            selected: false
        };
    }


    /* ============================================================
       STATUS
       ============================================================ */

    function normalizeStatus(status) {

        if (
            typeof status ===
            "boolean"
        ) {

            return status
                ? "online"
                : "offline";
        }

        const value =
            String(
                status ?? "online"
            )
                .toLowerCase();

        if (
            value.includes("offline") ||
            value.includes("down") ||
            value.includes("inactive") ||
            value === "false"
        ) {

            return "offline";
        }

        return "online";
    }


    /* ============================================================
       NORMALIZE CONNECTION
       ============================================================ */

    function normalizeConnection(
        connection
    ) {

        if (!connection) {
            return null;
        }

        const source =
            connection.source ??
            connection.src ??
            connection.from;

        const target =
            connection.target ??
            connection.dst ??
            connection.to;

        if (
            source === undefined ||
            source === null ||
            target === undefined ||
            target === null
        ) {

            return null;
        }

        return {

            ...connection,

            source:
                String(source),

            target:
                String(target)
        };
    }


    /* ============================================================
       DETECT DEVICE TYPE
       ============================================================ */

    function detectDeviceType(
        device
    ) {

        const text =
            `
                ${device.name || ""}
                ${device.hostname || ""}
                ${device.os || ""}
                ${device.ip || ""}
            `
                .toLowerCase();


        if (
            text.includes("switch") ||
            text.includes("vmnet")
        ) {

            return "switch";
        }


        if (
            text.includes("cowrie") ||
            text.includes("honeypot")
        ) {

            return "honeypot";
        }


        if (
            text.includes("soc") ||
            text.includes(
                "security operation"
            )
        ) {

            return "soc";
        }


        if (
            text.includes("kali") ||
            text.includes("attacker") ||
            text.includes("parrot")
        ) {

            return "attacker";
        }


        if (
            text.includes("ubuntu") ||
            text.includes("server")
        ) {

            return "server";
        }


        if (
            text.includes("router") ||
            text.includes("gateway")
        ) {

            return "router";
        }


        if (
            text.includes("firewall")
        ) {

            return "firewall";
        }


        if (
            text.includes("windows") ||
            text.includes("desktop") ||
            /\bpc\d+/i.test(text)
        ) {

            return "workstation";
        }


        return "device";
    }


    /* ============================================================
       ENSURE SOC DEVICE
       ============================================================ */

    function ensureSOCDevice() {

        const existingSOC =
            devices.find(
                device =>

                    device.type === "soc" ||

                    device.id === "host" ||

                    device.hostname ===
                        "SOC-HOST"
            );

        if (existingSOC) {

            /*
             * Do not change the ID.
             *
             * Backend links use:
             *
             * enterprise-switch -> host
             */

            existingSOC.type =
                "soc";

            existingSOC.status =
                "online";

            existingSOC.radius =
                CONFIG.coreRadius;

            return;
        }


        /*
         * Compatibility fallback only.
         */

        devices.unshift({

            id: "soc",

            name: "SOC Server",

            hostname:
                "SOC-SERVER",

            ip:
                "127.0.0.1",

            os:
                "SOC Platform",

            status:
                "online",

            type:
                "soc",

            x: 0,

            y: 0,

            radius:
                CONFIG.coreRadius,

            selected:
                false
        });
    }


    /* ============================================================
       FALLBACK TOPOLOGY
       ============================================================ */

    function createFallbackTopology() {

        devices = [

            {
                id:
                    "enterprise-switch",

                name:
                    "VMNET1-SWITCH",

                hostname:
                    "VMNET1-SWITCH",

                ip: "",

                os:
                    "Virtual Network",

                status:
                    "online",

                type:
                    "switch"
            },

            {
                id:
                    "host",

                name:
                    "SOC-HOST",

                hostname:
                    "SOC-HOST",

                ip:
                    "192.168.56.1",

                os:
                    "Windows 11",

                status:
                    "online",

                type:
                    "soc"
            },

            {
                id:
                    "kali",

                name:
                    "KALI-ATTACKER",

                hostname:
                    "KALI-ATTACKER",

                ip:
                    "192.168.56.10",

                os:
                    "Kali Linux",

                status:
                    "online",

                type:
                    "attacker"
            },

            {
                id:
                    "target",

                name:
                    "UBUNTU-TARGET",

                hostname:
                    "UBUNTU-TARGET",

                ip:
                    "192.168.56.30",

                os:
                    "Ubuntu Linux",

                status:
                    "online",

                type:
                    "server"
            },

            {
                id:
                    "honey",

                name:
                    "COWRIE-HONEYPOT",

                hostname:
                    "COWRIE-HONEYPOT",

                ip:
                    "192.168.56.40",

                os:
                    "Linux",

                status:
                    "online",

                type:
                    "honeypot"
            }

        ].map(
            normalizeDevice
        );


        connections = [

            {
                source:
                    "enterprise-switch",

                target:
                    "host"
            },

            {
                source:
                    "enterprise-switch",

                target:
                    "kali"
            },

            {
                source:
                    "enterprise-switch",

                target:
                    "target"
            },

            {
                source:
                    "enterprise-switch",

                target:
                    "honey"
            }
        ];


        arrangeDevices();

        drawTopology();

        console.log(
            "[Topology] Using VM fallback topology."
        );
    }


    /* ============================================================
       GENERATE CONNECTIONS
       ============================================================ */

    function generateConnections() {

        connections = [];

        const switchNode =
            devices.find(
                device =>
                    device.type ===
                    "switch"
            );

        const soc =
            devices.find(
                device =>
                    device.type ===
                    "soc"
            );

        const center =
            switchNode || soc;

        if (!center) {
            return;
        }

        devices
            .filter(
                device =>
                    device.id !==
                    center.id
            )
            .forEach(
                device => {

                    connections.push({

                        source:
                            center.id,

                        target:
                            device.id
                    });
                }
            );
    }


    /* ============================================================
       DEVICE COUNT
       ============================================================ */

    function updateConnectedDeviceCard(
        data
    ) {

        let count = null;


        if (
            data &&
            Number.isFinite(
                Number(
                    data.device_count
                )
            )
        ) {

            count =
                Number(
                    data.device_count
                );

        } else if (
            data &&
            Array.isArray(
                data.devices
            )
        ) {

            count =
                data.devices.length;

        } else {

            /*
             * Never count VMNET1-SWITCH
             * as a connected endpoint.
             */

            count =
                devices.filter(
                    device =>
                        device.type !==
                        "switch"
                ).length;
        }


        const formatted =
            Number(count)
                .toLocaleString();


        const deviceCount =
            document.getElementById(
                "deviceCount"
            );

        const devicesCard =
            document.getElementById(
                "devices"
            );


        if (deviceCount) {

            deviceCount.textContent =
                formatted;
        }


        if (devicesCard) {

            devicesCard.textContent =
                formatted;
        }
    }


    /* ============================================================
       ARRANGE DEVICES
       ============================================================ */

    function arrangeDevices() {

        if (
            !topologyCanvas ||
            devices.length === 0
        ) {

            return;
        }


        const width =
            topologyCanvas.clientWidth ||
            1200;


        const height =
            topologyCanvas.clientHeight ||
            700;


        /*
         * Prevent labels from being clipped
         * against the left/right sides.
         */

        const sidePadding =
            Math.max(
                90,
                width * 0.055
            );


        const assigned =
            new Set();


        /* --------------------------------------------------------
           FIND IMPORTANT NODES
           -------------------------------------------------------- */

        const switchNode =
            devices.find(
                device =>
                    device.type ===
                    "switch"
            );


        const soc =
            devices.find(
                device =>
                    device.type ===
                    "soc"
            );


        const attacker =
            devices.find(
                device =>
                    device.type ===
                    "attacker"
            );


        const server =
            devices.find(
                device =>
                    device.type ===
                    "server"
            );


        const honeypot =
            devices.find(
                device =>

                    device.type ===
                        "honeypot" ||

                    device.id ===
                        "honey" ||

                    String(
                        device.hostname || ""
                    )
                        .toLowerCase()
                        .includes(
                            "cowrie"
                        )
            );


        /*
         * Sort workstations numerically.
         *
         * PC01, PC02 ... PC10
         * PC11 ... PC20
         */

        const workstations =
            devices
                .filter(
                    device =>
                        device.type ===
                        "workstation"
                )
                .sort(
                    (a, b) => {

                        const aName =
                            String(
                                a.hostname ||
                                a.name ||
                                a.id ||
                                ""
                            );

                        const bName =
                            String(
                                b.hostname ||
                                b.name ||
                                b.id ||
                                ""
                            );


                        return aName.localeCompare(
                            bName,
                            undefined,
                            {
                                numeric:
                                    true,

                                sensitivity:
                                    "base"
                            }
                        );
                    }
                );


        /* ========================================================
           LAYER 1 — VMNET1 SWITCH
           ======================================================== */

        if (switchNode) {

            switchNode.x =
                width / 2;

            switchNode.y =
                70;

            assigned.add(
                switchNode.id
            );
        }


        /* ========================================================
           LAYER 2 — CORE SYSTEMS
           ======================================================== */

        const coreNodes =
            [
                attacker,
                soc,
                server
            ]
                .filter(Boolean);


        if (
            coreNodes.length >
            0
        ) {

            const coreY =
                185;


            /*
             * Core systems use only part of the
             * canvas so they remain visually grouped.
             */

            const coreAreaWidth =
                Math.min(
                    width * 0.62,
                    850
                );


            const coreStartX =
                (
                    width -
                    coreAreaWidth
                ) / 2;


            const coreGap =
                coreNodes.length > 1

                    ? coreAreaWidth /
                      (
                          coreNodes.length -
                          1
                      )

                    : 0;


            coreNodes.forEach(
                (
                    device,
                    index
                ) => {

                    device.x =
                        coreNodes.length ===
                        1

                            ? width / 2

                            : coreStartX +
                              index *
                              coreGap;


                    device.y =
                        coreY;


                    assigned.add(
                        device.id
                    );
                }
            );
        }


        /* ========================================================
           LAYER 3 — COWRIE
           ======================================================== */

        if (honeypot) {

            honeypot.x =
                width / 2;

            honeypot.y =
                285;

            assigned.add(
                honeypot.id
            );
        }


        /* ========================================================
           LAYER 4/5 — PC01-PC20
           ======================================================== */

        if (
            workstations.length >
            0
        ) {

            /*
             * Maximum ten PCs per row.
             */

            const columns =
                Math.min(
                    10,
                    workstations.length
                );


            const rows =
                Math.ceil(
                    workstations.length /
                    columns
                );


            const startY =
                405;


            const availableHeight =
                Math.max(
                    80,

                    height -
                    startY -
                    55
                );


            const rowGap =
                rows > 1

                    ? Math.min(
                        150,

                        availableHeight /
                        (
                            rows -
                            1
                        )
                    )

                    : 0;


            const availableWidth =
                Math.max(
                    200,

                    width -
                    sidePadding *
                    2
                );


            workstations.forEach(
                (
                    device,
                    index
                ) => {

                    const row =
                        Math.floor(
                            index /
                            columns
                        );


                    const col =
                        index %
                        columns;


                    const rowStartIndex =
                        row *
                        columns;


                    const countInRow =
                        Math.min(
                            columns,

                            workstations.length -
                            rowStartIndex
                        );


                    let x;


                    if (
                        countInRow ===
                        1
                    ) {

                        x =
                            width / 2;

                    } else {

                        const gap =
                            availableWidth /
                            (
                                countInRow -
                                1
                            );


                        const rowWidth =
                            gap *
                            (
                                countInRow -
                                1
                            );


                        const rowStartX =
                            (
                                width -
                                rowWidth
                            ) / 2;


                        x =
                            rowStartX +
                            col *
                            gap;
                    }


                    device.x =
                        x;


                    device.y =
                        startY +
                        row *
                        rowGap;


                    assigned.add(
                        device.id
                    );
                }
            );
        }


        /* ========================================================
           OTHER DEVICES
           ======================================================== */

        const remaining =
            devices.filter(
                device =>
                    !assigned.has(
                        device.id
                    )
            );


        if (
            remaining.length >
            0
        ) {

            const remainingY =
                honeypot
                    ? 335
                    : 285;


            const remainingWidth =
                Math.min(
                    width * 0.60,
                    800
                );


            const remainingStartX =
                (
                    width -
                    remainingWidth
                ) / 2;


            remaining.forEach(
                (
                    device,
                    index
                ) => {

                    device.x =
                        remainingStartX +
                        remainingWidth *
                        (
                            (
                                index +
                                1
                            ) /
                            (
                                remaining.length +
                                1
                            )
                        );


                    device.y =
                        remainingY;


                    assigned.add(
                        device.id
                    );
                }
            );
        }
    }


    /* ============================================================
       DRAW TOPOLOGY
       ============================================================ */

    function drawTopology() {

        if (
            !initialized ||
            !topologyCtx ||
            !topologyCanvas
        ) {

            return;
        }


        const width =
            topologyCanvas.clientWidth;


        const height =
            topologyCanvas.clientHeight;


        topologyCtx.clearRect(
            0,
            0,
            width,
            height
        );


        drawGrid(
            width,
            height
        );


        drawConnections();


        devices.forEach(
            drawDevice
        );
    }


    /* ============================================================
       GRID
       ============================================================ */

    function drawGrid(
        width,
        height
    ) {

        topologyCtx.save();


        topologyCtx.strokeStyle =
            "rgba(0, 200, 255, 0.045)";


        topologyCtx.lineWidth =
            1;


        const gridSize =
            35;


        for (
            let x = 0;
            x < width;
            x += gridSize
        ) {

            topologyCtx.beginPath();

            topologyCtx.moveTo(
                x,
                0
            );

            topologyCtx.lineTo(
                x,
                height
            );

            topologyCtx.stroke();
        }


        for (
            let y = 0;
            y < height;
            y += gridSize
        ) {

            topologyCtx.beginPath();

            topologyCtx.moveTo(
                0,
                y
            );

            topologyCtx.lineTo(
                width,
                y
            );

            topologyCtx.stroke();
        }


        topologyCtx.restore();
    }


    /* ============================================================
       CONNECTIONS
       ============================================================ */

    function drawConnections() {

        connections.forEach(
            connection => {

                const source =
                    findDevice(
                        connection.source
                    );


                const target =
                    findDevice(
                        connection.target
                    );


                if (
                    !source ||
                    !target
                ) {

                    return;
                }


                const active =
                    source.status ===
                        "online" &&

                    target.status ===
                        "online";


                topologyCtx.save();

                topologyCtx.beginPath();


                topologyCtx.moveTo(
                    source.x,
                    source.y
                );


                topologyCtx.lineTo(
                    target.x,
                    target.y
                );


                topologyCtx.lineWidth =
                    active
                        ? 1.6
                        : 1;


                topologyCtx.strokeStyle =
                    active

                        ? "rgba(0, 220, 255, 0.40)"

                        : "rgba(100, 100, 100, 0.30)";


                topologyCtx.stroke();


                if (active) {

                    drawTrafficParticle(
                        source,
                        target
                    );
                }


                topologyCtx.restore();
            }
        );
    }


    /* ============================================================
       TRAFFIC PARTICLE
       ============================================================ */

    function drawTrafficParticle(
        source,
        target
    ) {

        const progress =
            (
                Date.now() *
                CONFIG.animationSpeed
            ) % 1;


        const x =
            source.x +
            (
                target.x -
                source.x
            ) *
            progress;


        const y =
            source.y +
            (
                target.y -
                source.y
            ) *
            progress;


        topologyCtx.save();

        topologyCtx.beginPath();


        topologyCtx.arc(
            x,
            y,
            2.5,
            0,
            Math.PI * 2
        );


        topologyCtx.fillStyle =
            CONFIG.colors.connection;


        topologyCtx.shadowBlur =
            8;


        topologyCtx.shadowColor =
            CONFIG.colors.connection;


        topologyCtx.fill();

        topologyCtx.restore();
    }


    /* ============================================================
       NODE COLOR
       ============================================================ */

    function getNodeColor(
        type
    ) {

        return (
            CONFIG.colors[type] ||
            CONFIG.colors.device
        );
    }


    /* ============================================================
       DRAW DEVICE
       ============================================================ */

    function drawDevice(
        device
    ) {

        let nodeColor =
            getNodeColor(
                device.type
            );


        if (
            device.status !==
            "online"
        ) {

            nodeColor =
                CONFIG.colors.offline;
        }


        const radius =
            device.radius ||
            CONFIG.nodeRadius;


        topologyCtx.save();


        /* --------------------------------------------------------
           SELECTED NODE
           -------------------------------------------------------- */

        if (device.selected) {

            topologyCtx.beginPath();


            topologyCtx.arc(
                device.x,
                device.y,
                radius + 10,
                0,
                Math.PI * 2
            );


            topologyCtx.strokeStyle =
                "#ffffff";


            topologyCtx.globalAlpha =
                0.45;


            topologyCtx.lineWidth =
                3;


            topologyCtx.stroke();


            topologyCtx.globalAlpha =
                1;
        }


        /* --------------------------------------------------------
           OUTER GLOW
           -------------------------------------------------------- */

        topologyCtx.beginPath();


        topologyCtx.arc(
            device.x,
            device.y,
            radius + 7,
            0,
            Math.PI * 2
        );


        topologyCtx.strokeStyle =
            nodeColor;


        topologyCtx.globalAlpha =
            0.15;


        topologyCtx.lineWidth =
            5;


        topologyCtx.stroke();


        topologyCtx.globalAlpha =
            1;


        /* --------------------------------------------------------
           MAIN NODE
           -------------------------------------------------------- */

        topologyCtx.beginPath();


        topologyCtx.arc(
            device.x,
            device.y,
            radius,
            0,
            Math.PI * 2
        );


        topologyCtx.fillStyle =
            "#101923";


        topologyCtx.fill();


        topologyCtx.strokeStyle =
            nodeColor;


        topologyCtx.lineWidth =
            2;


        topologyCtx.stroke();


        /* --------------------------------------------------------
           ICON
           -------------------------------------------------------- */

        topologyCtx.fillStyle =
            nodeColor;


        topologyCtx.font =
            "bold 17px Arial";


        topologyCtx.textAlign =
            "center";


        topologyCtx.textBaseline =
            "middle";


        topologyCtx.fillText(
            getDeviceIcon(
                device.type
            ),
            device.x,
            device.y
        );


        /* --------------------------------------------------------
           NAME
           -------------------------------------------------------- */

        topologyCtx.font =
            "bold 11px Arial";


        topologyCtx.fillStyle =
            CONFIG.colors.text;


        topologyCtx.textBaseline =
            "top";


        topologyCtx.fillText(
            truncateText(
                device.name,
                18
            ),
            device.x,
            device.y +
            radius +
            7
        );


        /* --------------------------------------------------------
           IP ADDRESS
           -------------------------------------------------------- */

        if (device.ip) {

            topologyCtx.font =
                "9px Arial";


            topologyCtx.fillStyle =
                CONFIG.colors.subText;


            topologyCtx.fillText(
                truncateText(
                    device.ip,
                    20
                ),
                device.x,
                device.y +
                radius +
                21
            );
        }


        /* --------------------------------------------------------
           ONLINE INDICATOR
           -------------------------------------------------------- */

        topologyCtx.beginPath();


        topologyCtx.arc(
            device.x +
            radius -
            3,

            device.y -
            radius +
            3,

            5,

            0,

            Math.PI * 2
        );


        topologyCtx.fillStyle =

            device.status ===
                "online"

                ? "#00ff88"

                : "#777777";


        topologyCtx.fill();


        topologyCtx.restore();
    }


    /* ============================================================
       DEVICE ICON
       ============================================================ */

    function getDeviceIcon(
        type
    ) {

        switch (type) {

            case "soc":

                return "◆";


            case "attacker":

                return "⚠";


            case "server":

                return "▣";


            case "honeypot":

                return "⬡";


            case "switch":

                return "◇";


            case "router":

                return "◇";


            case "firewall":

                return "⬢";


            case "workstation":

                return "▤";


            default:

                return "●";
        }
    }


    /* ============================================================
       FIND DEVICE
       ============================================================ */

    function findDevice(
        id
    ) {

        if (
            id === undefined ||
            id === null
        ) {

            return null;
        }


        const value =
            String(id);


        return (

            devices.find(
                device =>

                    String(
                        device.id
                    ) ===
                        value ||

                    String(
                        device.ip
                    ) ===
                        value ||

                    String(
                        device.hostname
                    ) ===
                        value
            ) ||

            null
        );
    }


    /* ============================================================
       UPDATE DEVICES ONLY
       ============================================================ */

    function updateDevices(
        incoming
    ) {

        if (!incoming) {
            return;
        }


        let list =
            incoming;


        if (
            Array.isArray(
                incoming.devices
            )
        ) {

            list =
                incoming.devices;

        } else if (
            Array.isArray(
                incoming.data
            )
        ) {

            list =
                incoming.data;
        }


        if (
            !Array.isArray(
                list
            )
        ) {

            list =
                [list];
        }


        if (
            list.length ===
            0
        ) {

            return;
        }


        const normalized =
            list
                .slice(
                    0,
                    CONFIG.maxDevices
                )
                .map(
                    normalizeDevice
                );


        normalized.forEach(
            newDevice => {

                const index =
                    devices.findIndex(
                        device =>

                            device.id ===
                                newDevice.id ||

                            (
                                newDevice.ip &&
                                device.ip ===
                                    newDevice.ip
                            )
                    );


                if (index >= 0) {

                    const old =
                        devices[index];


                    devices[index] = {

                        ...old,

                        ...newDevice,

                        x:
                            old.x,

                        y:
                            old.y,

                        selected:
                            old.selected
                    };

                } else {

                    devices.push(
                        newDevice
                    );
                }
            }
        );


        ensureSOCDevice();


        if (
            connections.length ===
            0
        ) {

            generateConnections();
        }


        const endpointCount =
            devices.filter(
                device =>
                    device.type !==
                    "switch"
            ).length;


        updateConnectedDeviceCard({

            device_count:
                endpointCount
        });


        arrangeDevices();

        drawTopology();
    }


    /* ============================================================
       RENDER
       ============================================================ */

    function renderTopology(
        data
    ) {

        if (!data) {
            return;
        }


        if (
            Array.isArray(
                data
            )
        ) {

            updateDevices(
                data
            );

            return;
        }


        if (
            data.nodes ||
            data.devices ||
            data.links ||
            data.connections ||
            data.edges
        ) {

            updateTopology(
                data
            );
        }
    }


    /* ============================================================
       CLICK
       ============================================================ */

    function handleCanvasClick(
        event
    ) {

        if (!topologyCanvas) {
            return;
        }


        const rect =
            topologyCanvas
                .getBoundingClientRect();


        const mouseX =
            event.clientX -
            rect.left;


        const mouseY =
            event.clientY -
            rect.top;


        const device =
            devices.find(
                item => {

                    const dx =
                        mouseX -
                        item.x;


                    const dy =
                        mouseY -
                        item.y;


                    return (
                        Math.sqrt(
                            dx * dx +
                            dy * dy
                        ) <=
                        item.radius
                    );
                }
            );


        if (!device) {
            return;
        }


        devices.forEach(
            item => {

                item.selected =
                    false;
            }
        );


        device.selected =
            true;


        showDeviceDetails(
            device
        );


        drawTopology();
    }


    /* ============================================================
       HOVER
       ============================================================ */

    function handleMouseMove(
        event
    ) {

        if (!topologyCanvas) {
            return;
        }


        const rect =
            topologyCanvas
                .getBoundingClientRect();


        const mouseX =
            event.clientX -
            rect.left;


        const mouseY =
            event.clientY -
            rect.top;


        const hovering =
            devices.some(
                device => {

                    const dx =
                        mouseX -
                        device.x;


                    const dy =
                        mouseY -
                        device.y;


                    return (
                        Math.sqrt(
                            dx * dx +
                            dy * dy
                        ) <=
                        device.radius
                    );
                }
            );


        topologyCanvas.style.cursor =
            hovering
                ? "pointer"
                : "default";
    }


    /* ============================================================
       DEVICE DETAILS
       ============================================================ */

    function showDeviceDetails(
        device
    ) {

        console.log(
            "[Topology] Device selected:",
            device
        );


        const panel =
            document.getElementById(
                "deviceDetails"
            );


        if (!panel) {
            return;
        }


        const department =
            device.department ||
            "—";


        const site =
            device.site ||
            device.location ||
            "—";


        panel.innerHTML = `

            <div class="device-detail-header">

                <strong>
                    ${escapeHtml(
                        device.name
                    )}
                </strong>

            </div>


            <div class="device-detail-row">

                <span>
                    IP Address
                </span>

                <strong>
                    ${escapeHtml(
                        device.ip ||
                        "—"
                    )}
                </strong>

            </div>


            <div class="device-detail-row">

                <span>
                    Hostname
                </span>

                <strong>
                    ${escapeHtml(
                        device.hostname
                    )}
                </strong>

            </div>


            <div class="device-detail-row">

                <span>
                    Operating System
                </span>

                <strong>
                    ${escapeHtml(
                        device.os
                    )}
                </strong>

            </div>


            <div class="device-detail-row">

                <span>
                    Department
                </span>

                <strong>
                    ${escapeHtml(
                        department
                    )}
                </strong>

            </div>


            <div class="device-detail-row">

                <span>
                    Site
                </span>

                <strong>
                    ${escapeHtml(
                        site
                    )}
                </strong>

            </div>


            <div class="device-detail-row">

                <span>
                    Status
                </span>

                <strong>
                    ${escapeHtml(
                        device.status
                    )}
                </strong>

            </div>
        `;
    }


    /* ============================================================
       TEXT UTILITIES
       ============================================================ */

    function truncateText(
        value,
        maxLength
    ) {

        const text =
            String(
                value ?? ""
            );


        if (
            text.length <=
            maxLength
        ) {

            return text;
        }


        return (
            text.substring(
                0,
                maxLength - 3
            ) +
            "..."
        );
    }


    function escapeHtml(
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


    /* ============================================================
       ANIMATION
       ============================================================ */

    function animate() {

        if (initialized) {

            drawTopology();
        }


        animationFrame =
            requestAnimationFrame(
                animate
            );
    }


    /* ============================================================
       PUBLIC API
       ============================================================ */

    window.Topology = {

        init:
            initTopology,

        update:
            updateTopology,

        render:
            renderTopology,

        reload:
            loadTopology,

        updateDevices:
            updateDevices,

        getDevices:
            function () {

                return devices.slice();
            },

        getConnections:
            function () {

                return connections.slice();
            }
    };


    /*
     * Compatibility with existing api.js/socket.js.
     */

    window.renderTopology =
        renderTopology;


    window.updateDevices =
        updateDevices;


    /* ============================================================
       AUTO INITIALIZE
       ============================================================ */

    if (
        document.readyState ===
        "loading"
    ) {

        document.addEventListener(
            "DOMContentLoaded",
            initTopology
        );

    } else {

        initTopology();
    }

})();