const scanButton =
    document.getElementById("scan-button");

const scanStatus =
    document.querySelector(".scan-status");

const deviceCount =
    document.getElementById("device-count");

const emptyState =
    document.getElementById("empty-state");

const deviceList =
    document.getElementById("device-list");


let eventSource = null;
let devices = new Map();


function setStatus(
    text,
    statusClass = "status-dot--ready",
) {
    if (!scanStatus) {
        return;
    }

    scanStatus.innerHTML = `
        <span class="status-dot ${statusClass}"></span>
        <span>${text}</span>
    `;
}


function setScanButton(
    disabled,
    text,
) {
    if (!scanButton) {
        return;
    }

    scanButton.disabled = disabled;

    const label =
        scanButton.querySelector("span");

    if (label) {
        label.textContent = text;
    }
}


function updateDeviceCount() {
    if (!deviceCount) {
        return;
    }

    deviceCount.textContent =
        String(devices.size);
}


function clearResults() {
    devices.clear();

    if (deviceList) {
        deviceList.innerHTML = "";
    }

    if (emptyState) {
        emptyState.style.display = "";
    }

    updateDeviceCount();
}


function showResults() {
    if (emptyState) {
        emptyState.style.display = "none";
    }
}


function escapeHtml(value) {
    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}


function getDeviceIp(device) {
    return (
        device.ip ||
        device.host ||
        "Unknown"
    );
}


function getDeviceId(device) {
    return (
        device.id ||
        `network:${getDeviceIp(device)}`
    );
}


function createDeviceCard(device) {
    const card =
        document.createElement("article");

    card.className = "device-card";

    const ip =
        getDeviceIp(device);

    const id =
        getDeviceId(device);

    card.dataset.deviceId = id;


    const sources =
        Array.isArray(
            device.discovery_sources
        )
            ? device.discovery_sources
            : [];


    const sourceBadges =
        sources.length > 0
            ? sources.map(
                (source) => `
                    <span class="badge badge-neutral">
                        ${escapeHtml(source)}
                    </span>
                `
            ).join("")
            : `
                <span class="badge badge-neutral">
                    Network
                </span>
            `;

            const classification = (
    device.classification || "unknown"
    ).toLowerCase();

    const classificationLabel =
        classification.toUpperCase();

    const classificationClass =
        classification === "camera"
            ? "device-classification--camera"
            : "";

    card.innerHTML = `
    <div class="device-card-header">

        <span class="device-classification ${classificationClass}">
            ${escapeHtml(classificationLabel)}
        </span>

    </div>
        <div class="device-card-body">

            <div class="device-card-title">
                <div class="device-address">
                    <span class="address-badge">IP</span>
                    <span>${escapeHtml(ip)}</span>
                </div>

                <div class="device-address">
                    <span class="address-badge">MAC</span>
                    <span>
                        ${
                            device.mac
                                ? escapeHtml(device.mac)
                                : "—"
                        }
                    </span>
                </div>
            </div>

            <div class="device-discovery">

                <span class="device-status">
                    Detected
                </span>

                <div class="device-card-details">
                    ${sourceBadges}
                </div>

            </div>

        </div>
    `;


    return card;
}


function addDevice(device) {
    if (!device) {
        return;
    }


    const id =
        getDeviceId(device);


    if (devices.has(id)) {
        return;
    }


    devices.set(
        id,
        device,
    );


    showResults();

    updateDeviceCount();


    if (!deviceList) {
        return;
    }


    const card =
        createDeviceCard(device);

    deviceList.appendChild(card);
}


async function startScan() {
    if (!scanButton) {
        return;
    }


    if (eventSource) {
        return;
    }


    setScanButton(
        true,
        "Starting scan...",
    );


    clearResults();


    setStatus(
        "Starting scan...",
        "status-dot--scanning",
    );


    try {
        const response =
            await fetch(
                "/api/discovery/scan",
                {
                    method: "POST",
                    headers: {
                        "Accept": "application/json",
                    },
                },
            );


        if (!response.ok) {
            throw new Error(
                `HTTP ${response.status}`
            );
        }


        const result =
            await response.json();

        if (!result.ok) {
            if (result.running) {
                throw new Error(
                    "A scan is already running."
                );
            }

            throw new Error(
                "Unable to start scan."
            );
        }

        connectEvents();

    } catch (error) {
        console.error(
            "Unable to start discovery:",
            error,
        );


        setStatus(
            `Scan failed: ${error.message}`,
            "status-dot--error",
        );


        setScanButton(
            false,
            "Scan network",
        );
    }
}


function connectEvents() {
    if (eventSource) {
        eventSource.close();
    }


    eventSource =
        new EventSource(
            "/api/discovery/events"
        );


    eventSource.onmessage =
            (event) => {

                try {
                    const data =
                        JSON.parse(event.data);

                    handleEvent(data);

                } catch (error) {
                    console.error(
                        "Invalid discovery event:",
                        error,
                    );
                }
            };

        eventSource.onerror =
            (error) => {
                console.error(
                    "DISCOVERY.JS: EventSource ERROR:",
                    error,
                );


            if (eventSource) {
                eventSource.close();
                eventSource = null;
            }


            /*
             * Do not overwrite a completed scan state.
             * The normal completion event closes the stream first.
             */
            setScanButton(
                false,
                "Scan network",
            );


            setStatus(
                "Connection to scanner lost.",
                "status-dot--error",
            );
        };
}


function handleEvent(event) {
    switch (event.type) {

        case "scan_started":
            handleScanStarted();
            break;


        case "device_found":
            handleDeviceFound(
                event.device
            );
            break;


        case "scan_finished":
            handleScanFinished();
            break;


        case "scan_cancelled":
            handleScanCancelled();
            break;


        case "scan_error":
            handleScanError(
                event.error
            );
            break;


        default:
            console.warn(
                "Unknown discovery event:",
                event,
            );
    }
}


function handleScanStarted() {
    setStatus(
        "Scanning local network...",
        "status-dot--scanning",
    );


    setScanButton(
        true,
        "Scanning...",
    );
}


function handleDeviceFound(device) {
    addDevice(device);


    const count =
        devices.size;


    setStatus(
        `Found ${count} device${count === 1 ? "" : "s"}...`,
        "status-dot--scanning",
    );
}


function handleScanFinished() {
    const count =
        devices.size;


    setStatus(
        `Scan finished — ${count} device${count === 1 ? "" : "s"} found`,
        "status-dot--ready",
    );


    setScanButton(
        false,
        "Scan network",
    );


    closeEventSource();
}


function handleScanCancelled() {
    setStatus(
        "Scan cancelled.",
        "status-dot--ready",
    );


    setScanButton(
        false,
        "Scan network",
    );


    closeEventSource();
}


function handleScanError(error) {
    setStatus(
        `Scan error: ${error || "Unknown error"}`,
        "status-dot--error",
    );


    setScanButton(
        false,
        "Scan network",
    );


    closeEventSource();
}


function closeEventSource() {
    if (!eventSource) {
        return;
    }

    eventSource.close();
    eventSource = null;
}


if (scanButton) {
    scanButton.addEventListener(
        "click",
        startScan,
    );
}
