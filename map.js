/* ============================================================
   SOC PLATFORM — LIVE ATTACK MAP
   frontend/map.js

   Uses Leaflet to display:
   - World map
   - SOC location
   - Attack locations
   - Attack lines
   - Animated attack markers
   ============================================================ */

"use strict";

let attackMap = null;

let attackMarkers = [];
let attackLines = [];
let movingAttackMarkers = [];

let socMarker = null;

let mapInitialized = false;


/* ============================================================
   DEFAULT SOC LOCATION
   ============================================================ */

const SOC_LOCATION = {
    lat: 25.2048,
    lon: 55.2708,
    name: "SOC Server"
};


/* ============================================================
   MAP CONFIGURATION
   ============================================================ */

const MAP_CONFIG = {

    defaultZoom: 2,

    maxAttacks: 50,

    animationSpeed: 0.025,

    refreshInterval: 10000

};


/* ============================================================
   INITIALISE MAP
   ============================================================ */

function initializeAttackMap() {

    const mapElement =
        document.getElementById("map");


    if (!mapElement) {

        console.warn(
            "[MAP] #map element not found"
        );

        return;

    }


    /*
       Prevent duplicate initialisation.
    */

    if (attackMap) {

        setTimeout(() => {

            attackMap.invalidateSize();

        }, 200);

        return;

    }


    /*
       Make sure Leaflet is available.
    */

    if (typeof L === "undefined") {

        console.error(
            "[MAP] Leaflet is not loaded."
        );

        return;

    }


    /*
       Create Leaflet map.
    */

    attackMap = L.map(
        mapElement,
        {

            worldCopyJump: false,

            zoomControl: true,

            attributionControl: true,

            minZoom: 2,

            maxZoom: 18

        }
    ).setView(
        [
            SOC_LOCATION.lat,
            SOC_LOCATION.lon
        ],
        MAP_CONFIG.defaultZoom
    );


    /*
       OpenStreetMap tiles.
    */

    L.tileLayer(
        "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png",
        {

            maxZoom: 18,

            attribution:
                "&copy; OpenStreetMap contributors"

        }
    ).addTo(attackMap);


    /*
       Create SOC marker.
    */

    createSOCMarker();


    mapInitialized = true;


    /*
       Leaflet sometimes calculates the map size
       incorrectly when the dashboard section is loaded.
    */

    setTimeout(() => {

        if (attackMap) {

            attackMap.invalidateSize();

        }

    }, 300);


    console.log(
        "[MAP] Attack map initialised"
    );

}


/* ============================================================
   SOC MARKER
   ============================================================ */

function createSOCMarker() {

    if (!attackMap) {

        return;

    }


    /*
       Remove old SOC marker if one exists.
    */

    if (socMarker) {

        attackMap.removeLayer(
            socMarker
        );

    }


    const socIcon =
        L.divIcon({

            className:
                "soc-map-marker",

            html: `
                <div class="soc-marker">

                    <div class="soc-marker-pulse"></div>

                    <div class="soc-marker-core">
                        SOC
                    </div>

                </div>
            `,

            iconSize: [
                50,
                50
            ],

            iconAnchor: [
                25,
                25
            ]

        });


    socMarker =
        L.marker(
            [
                SOC_LOCATION.lat,
                SOC_LOCATION.lon
            ],
            {
                icon: socIcon,
                zIndexOffset: 1000
            }
        )
        .addTo(attackMap);


    socMarker.bindPopup(`

        <div class="map-popup">

            <strong>
                ${escapeMapHTML(
                    SOC_LOCATION.name
                )}
            </strong>

            <hr>

            Protected SOC Environment

            <br>

            <b>Status:</b>
            Online

        </div>

    `);

}


/* ============================================================
   NORMALIZE ATTACK DATA
   ============================================================ */

function normalizeAttack(attack) {

    if (!attack || typeof attack !== "object") {

        return null;

    }


    /*
       Support multiple backend coordinate names.
    */

    let latitude =
        attack.latitude ??
        attack.lat ??
        attack.source_lat ??
        attack.src_lat ??
        attack.source?.latitude ??
        attack.source?.lat;


    let longitude =
        attack.longitude ??
        attack.lon ??
        attack.lng ??
        attack.source_lon ??
        attack.src_lon ??
        attack.source?.longitude ??
        attack.source?.lon;


    /*
       Convert coordinates to numbers.
    */

    latitude = Number(latitude);
    longitude = Number(longitude);


    /*
       Validate coordinates.

       Latitude:
       -90 to +90

       Longitude:
       -180 to +180
    */

    if (
        !Number.isFinite(latitude) ||
        !Number.isFinite(longitude) ||
        latitude < -90 ||
        latitude > 90 ||
        longitude < -180 ||
        longitude > 180
    ) {

        return null;

    }


    const attackType =
        attack.attack_type ??
        attack.attack ??
        attack.label ??
        attack.threat ??
        attack.type ??
        "Unknown Attack";


    const sourceIP =
        attack.src_ip ??
        attack.source_ip ??
        attack.src ??
        attack.source?.ip ??
        "Unknown";


    const destinationIP =
        attack.dst_ip ??
        attack.destination_ip ??
        attack.dst ??
        attack.destination?.ip ??
        "Unknown";


    const severity =
        String(
            attack.severity ??
            calculateMapSeverity(
                attackType
            )
        ).toUpperCase();


    const timestamp =
        attack.timestamp ??
        attack.time ??
        attack.created_at ??
        "";


    /*
       Create a stable ID.

       This prevents the same attack from being
       displayed multiple times.
    */

    const id =
        attack.id ??
        attack.detection_id ??
        attack.event_id ??
        `${sourceIP}-${destinationIP}-${attackType}-${timestamp}-${latitude}-${longitude}`;


    return {

        id: String(id),

        latitude,

        longitude,

        attackType:
            String(attackType),

        sourceIP:
            String(sourceIP),

        destinationIP:
            String(destinationIP),

        severity,

        timestamp:
            String(timestamp)

    };

}


/* ============================================================
   ADD ATTACK
   ============================================================ */

function addAttackLocation(attack) {

    if (!attackMap) {

        initializeAttackMap();

    }


    if (!attackMap) {

        return;

    }


    const normalized =
        normalizeAttack(attack);


    /*
       Ignore invalid attack data.
    */

    if (!normalized) {

        console.warn(
            "[MAP] Invalid attack coordinates:",
            attack
        );

        return;

    }


    /*
       Prevent duplicate attacks.
    */

    const duplicate =
        attackMarkers.some(
            item =>
                item.attackId ===
                normalized.id
        );


    if (duplicate) {

        return;

    }


    /*
       Create attack marker.
    */

    const marker =
        createAttackMarker(
            normalized
        );


    /*
       Draw clean attack line.

       Attacker
          |
          |
          ▼
       SOC Server
    */

    const line =
        L.polyline(
            [

                [
                    normalized.latitude,
                    normalized.longitude
                ],

                [
                    SOC_LOCATION.lat,
                    SOC_LOCATION.lon
                ]

            ],
            {

                color:
                    getSeverityColor(
                        normalized.severity
                    ),

                weight: 2,

                opacity: 0.60,

                dashArray: "7, 9",

                className:
                    "attack-line"

            }
        )
        .addTo(attackMap);


    /*
       Store ID on marker so duplicates
       can be detected.
    */

    marker.attackId =
        normalized.id;


    attackMarkers.push(
        marker
    );

    attackLines.push(
        line
    );


    /*
       Keep only the latest attacks.
    */

    while (
        attackMarkers.length >
        MAP_CONFIG.maxAttacks
    ) {

        const oldMarker =
            attackMarkers.shift();

        if (oldMarker) {

            attackMap.removeLayer(
                oldMarker
            );

        }

    }


    while (
        attackLines.length >
        MAP_CONFIG.maxAttacks
    ) {

        const oldLine =
            attackLines.shift();

        if (oldLine) {

            attackMap.removeLayer(
                oldLine
            );

        }

    }


    /*
       Animate attacker → SOC.
    */

    animateAttackLine(
        normalized.latitude,
        normalized.longitude
    );

}


/* ============================================================
   ATTACK MARKER
   ============================================================ */

function createAttackMarker(
    attack
) {

    const color =
        getSeverityColor(
            attack.severity
        );


    const icon =
        L.divIcon({

            className:
                "attack-map-marker",

            html: `

                <div
                    class="attack-marker"
                    style="--marker-color:${color}"
                >

                    <div class="attack-pulse"></div>

                    <div class="attack-core">
                        !
                    </div>

                </div>

            `,

            iconSize: [
                35,
                35
            ],

            iconAnchor: [
                17,
                17
            ]

        });


    const marker =
        L.marker(
            [
                attack.latitude,
                attack.longitude
            ],
            {

                icon: icon,

                zIndexOffset: 500

            }
        )
        .addTo(attackMap);


    marker.bindPopup(`

        <div class="map-popup">

            <strong>
                ${escapeMapHTML(
                    attack.attackType
                )}
            </strong>

            <hr>

            <b>Severity:</b>
            ${escapeMapHTML(
                attack.severity
            )}

            <br>

            <b>Source:</b>
            ${escapeMapHTML(
                attack.sourceIP
            )}

            <br>

            <b>Destination:</b>
            ${escapeMapHTML(
                attack.destinationIP
            )}

            <br>

            <b>Location:</b>
            ${attack.latitude.toFixed(4)},
            ${attack.longitude.toFixed(4)}

            ${
                attack.timestamp
                    ? `
                        <br>
                        <b>Time:</b>
                        ${escapeMapHTML(
                            attack.timestamp
                        )}
                    `
                    : ""
            }

        </div>

    `);


    return marker;

}


/* ============================================================
   ATTACK LINE ANIMATION
   ============================================================ */

function animateAttackLine(
    startLat,
    startLon
) {

    if (!attackMap) {

        return;

    }


    const movingIcon =
        L.divIcon({

            className:
                "moving-attack-marker",

            html:
                `<div class="moving-packet"></div>`,

            iconSize: [
                10,
                10
            ],

            iconAnchor: [
                5,
                5
            ]

        });


    const movingMarker =
        L.marker(
            [
                startLat,
                startLon
            ],
            {

                icon:
                    movingIcon,

                interactive:
                    false,

                zIndexOffset:
                    800

            }
        )
        .addTo(attackMap);


    movingAttackMarkers.push(
        movingMarker
    );


    const startLatitude =
        startLat;

    const startLongitude =
        startLon;


    const endLatitude =
        SOC_LOCATION.lat;

    const endLongitude =
        SOC_LOCATION.lon;


    let progress = 0;


    const interval =
        setInterval(
            () => {

                if (!attackMap) {

                    clearInterval(
                        interval
                    );

                    return;

                }


                progress +=
                    MAP_CONFIG.animationSpeed;


                if (
                    progress >= 1
                ) {

                    clearInterval(
                        interval
                    );


                    attackMap.removeLayer(
                        movingMarker
                    );


                    const index =
                        movingAttackMarkers.indexOf(
                            movingMarker
                        );


                    if (
                        index !== -1
                    ) {

                        movingAttackMarkers.splice(
                            index,
                            1
                        );

                    }


                    return;

                }


                const currentLat =
                    startLatitude +
                    (
                        endLatitude -
                        startLatitude
                    ) *
                    progress;


                const currentLon =
                    startLongitude +
                    (
                        endLongitude -
                        startLongitude
                    ) *
                    progress;


                movingMarker.setLatLng(
                    [
                        currentLat,
                        currentLon
                    ]
                );

            },

            50

        );

}


/* ============================================================
   CLEAR ATTACK MAP
   ============================================================ */

function clearAttackMap() {

    if (!attackMap) {

        return;

    }


    /*
       Remove attack markers.
    */

    attackMarkers.forEach(
        marker => {

            if (
                attackMap.hasLayer(
                    marker
                )
            ) {

                attackMap.removeLayer(
                    marker
                );

            }

        }
    );


    /*
       Remove attack lines.
    */

    attackLines.forEach(
        line => {

            if (
                attackMap.hasLayer(
                    line
                )
            ) {

                attackMap.removeLayer(
                    line
                );

            }

        }
    );


    /*
       Remove moving packets.
    */

    movingAttackMarkers.forEach(
        marker => {

            if (
                attackMap.hasLayer(
                    marker
                )
            ) {

                attackMap.removeLayer(
                    marker
                );

            }

        }
    );


    attackMarkers = [];

    attackLines = [];

    movingAttackMarkers = [];

}


/* ============================================================
   LOAD ATTACKS FROM API
   ============================================================ */

async function loadAttackMapData() {

    try {

        /*
           Make sure map exists.
        */

        if (!attackMap) {

            initializeAttackMap();

        }


        /*
           Keep your existing backend link.
        */

        const response =
            await fetch(
                "http://127.0.0.1:5000/api/detections"
            );


        if (!response.ok) {

            throw new Error(
                `HTTP ${response.status}`
            );

        }


        const data =
            await response.json();


        let detections = [];


        /*
           Support all existing API response formats.
        */

        if (
            Array.isArray(data)
        ) {

            detections =
                data;

        }

        else if (
            Array.isArray(
                data.detections
            )
        ) {

            detections =
                data.detections;

        }

        else if (
            Array.isArray(
                data.results
            )
        ) {

            detections =
                data.results;

        }

        else if (
            Array.isArray(
                data.data
            )
        ) {

            detections =
                data.data;

        }


        if (
            !Array.isArray(
                detections
            )
        ) {

            console.warn(
                "[MAP] Invalid detection response."
            );

            return;

        }


        /*
           Clear old attacks before loading
           the latest backend state.

           This is important because the function
           can be called repeatedly.
        */

        clearAttackMap();


        /*
           Add attacks.

           normalizeAttack() handles coordinate
           validation.
        */

        detections.forEach(
            attack => {

                const normalized =
                    normalizeAttack(
                        attack
                    );


                if (
                    normalized
                ) {

                    addAttackLocation(
                        attack
                    );

                }

            }
        );


        console.log(
            `[MAP] Loaded ${attackMarkers.length} attack locations`
        );


    }

    catch (error) {

        console.warn(
            "[MAP] Unable to load attack data:",
            error.message
        );

    }

}


/* ============================================================
   CALCULATE SEVERITY
   ============================================================ */

function calculateMapSeverity(
    attack
) {

    const text =
        String(attack)
            .toLowerCase();


    if (
        text.includes("ddos") ||
        text.includes("dos") ||
        text.includes("botnet")
    ) {

        return "CRITICAL";

    }


    if (
        text.includes("brute") ||
        text.includes("injection") ||
        text.includes("xss") ||
        text.includes("malware")
    ) {

        return "HIGH";

    }


    if (
        text.includes("scan") ||
        text.includes("recon")
    ) {

        return "MEDIUM";

    }


    return "LOW";

}


/* ============================================================
   SEVERITY COLOUR
   ============================================================ */

function getSeverityColor(
    severity
) {

    switch (
        String(severity)
            .toUpperCase()
    ) {

        case "CRITICAL":

            return "#ff0000";


        case "HIGH":

            return "#ff5500";


        case "MEDIUM":

            return "#ffaa00";


        case "LOW":

            return "#00aaff";


        default:

            return "#00aaff";

    }

}


/* ============================================================
   HTML ESCAPING
   ============================================================ */

function escapeMapHTML(
    value
) {

    return String(value)
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
   MAP RESIZE SUPPORT
   ============================================================ */

function refreshAttackMapSize() {

    if (!attackMap) {

        return;

    }


    setTimeout(
        () => {

            attackMap.invalidateSize();

        },
        100
    );

}


/* ============================================================
   AUTO REFRESH
   ============================================================ */

let attackMapRefreshTimer = null;


function startAttackMapRefresh() {

    if (
        attackMapRefreshTimer
    ) {

        clearInterval(
            attackMapRefreshTimer
        );

    }


    attackMapRefreshTimer =
        setInterval(
            () => {

                loadAttackMapData();

            },
            MAP_CONFIG.refreshInterval
        );

}


/* ============================================================
   WINDOW RESIZE
   ============================================================ */

window.addEventListener(
    "resize",
    () => {

        refreshAttackMapSize();

    }
);


/* ============================================================
   START MAP
   ============================================================ */

document.addEventListener(
    "DOMContentLoaded",
    () => {

        initializeAttackMap();

        /*
           Load existing detections.
        */

        loadAttackMapData();

        /*
           Keep map updated.
        */

        startAttackMapRefresh();

    }
);


/* ============================================================
   PUBLIC MAP API
   ============================================================ */

window.AttackMap = {

    init:
        initializeAttackMap,

    addAttack:
        addAttackLocation,

    clear:
        clearAttackMap,

    reload:
        loadAttackMapData,

    refresh:
        refreshAttackMapSize

};