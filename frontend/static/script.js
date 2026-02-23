var socket = io(window.location.origin);

console.log("Socket initialized");

/* ===============================
   GLOBAL STATE
=============================== */

let threatCounts = { Low: 0, Medium: 0, High: 0 };

let threatChart = null;
let trendChart = null;
let heatChart = null;


/* ===============================
   INIT CHARTS
=============================== */

function initCharts() {

    const threatCanvas = document.getElementById('threatChart');
    const trendCanvas = document.getElementById('trendChart');
    const heatCanvas = document.getElementById('heatChart');

    if (threatCanvas) {
        threatChart = new Chart(threatCanvas.getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: ['Low', 'Medium', 'High'],
                datasets: [{
                    data: [0, 0, 0],
                    backgroundColor: ['#1dd1a1', '#feca57', '#ff6b6b']
                }]
            }
        });
    }

    if (trendCanvas) {
        trendChart = new Chart(trendCanvas.getContext('2d'), {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Threat Trend',
                    data: [],
                    borderColor: '#38bdf8',
                    tension: 0.3
                }]
            }
        });
    }

    if (heatCanvas) {
        heatChart = new Chart(heatCanvas.getContext('2d'), {
            type: 'bar',
            data: {
                labels: ['Low', 'Medium', 'High'],
                datasets: [{
                    label: 'Threat Intensity',
                    data: [0, 0, 0],
                    backgroundColor: ['#1dd1a1', '#feca57', '#ff6b6b']
                }]
            }
        });
    }
}

initCharts();


/* ===============================
   LOAD EXISTING LOGS
=============================== */

window.addEventListener("load", function () {

    fetch("/api/logs")
        .then(res => res.json())
        .then(data => {

            data.reverse().forEach(log => {

                let threat = log[2];
                threatCounts[threat]++;

                // Render Overview Feed
                renderLog({
                    message: log[1],
                    threat: threat,
                    geo: log[3]
                });

                updateCharts(threat);

                // Render Honeypot Session Logs (if on honeypot page)
                let hpLogs = document.getElementById("honeypotLogs");

                if (hpLogs && log[1].includes("Honeypot")) {

                    let div = document.createElement("div");
                    div.className = "log-entry High";
                    div.innerHTML = `
                        <div class="log-threat">High</div>
                        <div class="log-message">${log[1]}</div>
                        <div class="log-geo">${log[3]}</div>
                    `;

                    hpLogs.appendChild(div);
                }
            });
        });
});


/* ===============================
   SOCKET EVENTS
=============================== */

socket.on("new_log", function (data) {

    threatCounts[data.threat]++;

    renderLog(data);
    updateCharts(data.threat);

    // Honeypot Live Panel
    if (data.message.includes("Honeypot")) {

        let hpLogs = document.getElementById("honeypotLogs");
        if (!hpLogs) return;

        let div = document.createElement("div");
        div.className = "log-entry High";
        div.innerHTML = `
            <div class="log-threat">High</div>
            <div class="log-message">${data.message}</div>
            <div class="log-geo">${data.geo}</div>
        `;

        hpLogs.prepend(div);
    }
});


socket.on("clear_dashboard", function () {

    threatCounts = { Low: 0, Medium: 0, High: 0 };

    let logs = document.getElementById("logs");
    if (logs) logs.innerHTML = "";

    if (trendChart) {
        trendChart.data.labels = [];
        trendChart.data.datasets[0].data = [];
        trendChart.update();
    }

    updateCharts();
});


/* ===============================
   UPDATE CHARTS
=============================== */

function updateCharts(threat = null) {

    if (threatChart) {
        threatChart.data.datasets[0].data = [
            threatCounts.Low,
            threatCounts.Medium,
            threatCounts.High
        ];
        threatChart.update();
    }

    if (heatChart) {
        heatChart.data.datasets[0].data = [
            threatCounts.Low,
            threatCounts.Medium,
            threatCounts.High
        ];
        heatChart.update();
    }

    if (trendChart && threat) {

        trendChart.data.labels.push(new Date().toLocaleTimeString());

        trendChart.data.datasets[0].data.push(
            threat === "High" ? 3 :
            threat === "Medium" ? 2 : 1
        );

        if (trendChart.data.labels.length > 20) {
            trendChart.data.labels.shift();
            trendChart.data.datasets[0].data.shift();
        }

        trendChart.update();
    }
}


/* ===============================
   RENDER LOG (Overview)
=============================== */

function renderLog(data) {

    let logs = document.getElementById("logs");
    if (!logs) return;

    let div = document.createElement("div");
    div.className = "log-entry " + data.threat;

    div.innerHTML = `
        <div class="log-threat">${data.threat}</div>
        <div class="log-message">${data.message}</div>
        <div class="log-geo">${data.geo}</div>
    `;

    logs.prepend(div);

    if (logs.children.length > 100) {
        logs.removeChild(logs.lastChild);
    }
}


/* ===============================
   CLEAR OVERVIEW LOGS
=============================== */

function clearThreats() {
    fetch("/clear_logs", { method: "POST" });
}


/* ===============================
   HONEYPOT CONTROL
=============================== */

function updateHoneypotStatus(status){

    let el = document.getElementById("honeypotStatus");
    if(!el) return;

    el.innerText = status.toUpperCase();
    el.classList.remove("running","stopped");

    if(status === "running"){
        el.classList.add("running");
    } else {
        el.classList.add("stopped");
    }
}

function startHoneypot(){
    fetch("/honeypot/start", { method: "POST" })
    .then(res => res.json())
    .then(data => updateHoneypotStatus(data.status));
}

function stopHoneypot(){
    fetch("/honeypot/stop", { method: "POST" })
    .then(res => res.json())
    .then(data => updateHoneypotStatus(data.status));
}

function clearHoneypotLogs(){

    if (!confirm("Clear all Honeypot logs?")) return;

    fetch("/clear_honeypot_logs", { method: "POST" })
        .then(res => {
            if (res.status === 403) {
                alert("Admin access required.");
                return;
            }
            return res.json();
        })
        .then(data => {

            if (!data) return;

            // Clear Honeypot Table
            let table = document.getElementById("honeypotTable");
            if (table) table.innerHTML = "";

            // Reset counter
            hpAttackCount = 0;
            let counter = document.getElementById("hpCounter");
            if(counter) counter.innerText = "0";

            // Reset chart
            if (hpChart) {
                hpChart.data.labels = [];
                hpChart.data.datasets[0].data = [];
                hpChart.update();
            }

            console.log("Honeypot logs cleared successfully");

        })
        .catch(err => console.error(err));
}


fetch("/honeypot/status")
.then(res => res.json())
.then(data => updateHoneypotStatus(data.status));

socket.on("honeypot_status", function(data){
    updateHoneypotStatus(data.status);
});
/* ===============================
   Honeypot Advanced Analytics
=============================== */

let hpAttackCount = 0;
let hpChart = null;

function initHoneypotChart(){

    const ctx = document.getElementById("honeypotChart");
    if(!ctx) return;

    hpChart = new Chart(ctx.getContext("2d"), {
        type: "line",
        data: {
            labels: [],
            datasets: [{
                label: "Honeypot Attacks",
                data: [],
                borderColor: "#ef4444",
                tension: 0.3
            }]
        }
    });
}

initHoneypotChart();


function loadHoneypotLogs(){

    let table = document.getElementById("honeypotTable");
    if(!table) return;

    fetch("/api/honeypot_logs")
        .then(res => res.json())
        .then(data => {

            table.innerHTML = "";
            hpAttackCount = 0;

            data.forEach(log => {

                hpAttackCount++;

                let ipMatch = log[1].match(/from ([^ ]+)/);
                let ip = ipMatch ? ipMatch[1] : "Unknown";

                let riskMatch = log[1].match(/Risk:(\d+)/);
                let risk = riskMatch ? riskMatch[1] : "0";

                let row = `
                    <tr>
                        <td>${log[0]}</td>
                        <td>${ip}</td>
                        <td>${log[2]}</td>
                        <td>${risk}</td>
                    </tr>
                `;

                table.innerHTML += row;
            });

            document.getElementById("hpCounter").innerText = hpAttackCount;

            if(hpChart){
                hpChart.data.labels = data.map(log => log[0]);
                hpChart.data.datasets[0].data = data.map((_, i) => i+1);
                hpChart.update();
            }
        });
}

window.addEventListener("load", loadHoneypotLogs);

socket.on("new_log", function(data){

    if(data.message.includes("Honeypot")){
        loadHoneypotLogs();
    }
});
/* ===============================
   INCIDENT MANAGEMENT
=============================== */

function loadIncidents(){

    let table = document.getElementById("incidentTable");
    if(!table) return;

    fetch("/api/incidents")
        .then(res => res.json())
        .then(data => {

            table.innerHTML = "";

            data.forEach(incident => {

                let severityClass = incident[3].toLowerCase();
                let statusClass = incident[4] === "Resolved" ? "resolved" : "open";

                let row = `
                    <tr>
                        <td>${incident[0]}</td>
                        <td>${incident[1]}</td>
                        <td>${incident[2]}</td>
                        <td><span class="badge ${severityClass}">
                            ${incident[3]}
                        </span></td>
                        <td><span class="status ${statusClass}">
                            ${incident[4]}
                        </span></td>
                        <td>
                            ${incident[4] !== "Resolved" ?
                            `<button class="soc-btn success"
                                onclick="resolveIncident(${incident[0]})">
                                Resolve
                             </button>`
                            : "✔"}
                        </td>
                    </tr>
                `;

                table.innerHTML += row;
            });
        });

    fetch("/api/soc_metrics")
        .then(res => res.json())
        .then(metrics => {
            document.getElementById("openIncidents").innerText = metrics.open_incidents;
            document.getElementById("highAlerts").innerText = metrics.high_alerts;
        });
}


function resolveIncident(id){

    fetch(`/incident/resolve/${id}`, { method: "POST" })
        .then(() => loadIncidents());
}

window.addEventListener("load", loadIncidents);

/* ===============================
   CLEAR INCIDENTS
=============================== */

function clearIncidents(){

    if(!confirm("Are you sure you want to clear ALL incidents?")) return;

    fetch("/clear_incidents", {
        method: "POST"
    })
    .then(res => {

        if(res.status === 403){
            alert("Admin access required.");
            return;
        }

        return res.json();
    })
    .then(data => {

        if(!data) return;

        console.log("Incidents cleared");

        // Reload table + metrics
        loadIncidents();
    })
    .catch(err => console.error(err));
}


/* ===============================
   IOC MANAGEMENT
=============================== */

function loadIOCs() {

    const table = document.getElementById("iocList");
    if (!table) return;

    fetch("/api/iocs")
        .then(res => res.json())
        .then(data => {

            table.innerHTML = "";

            data.forEach(ioc => {

                const id = ioc[0];
                const ip = ioc[1];
                const status = ioc[2] || "Active";

                let statusClass =
                    status === "Resolved" ? "resolved" : "open";

                let actionButtons = "-";

                if (window.isAdmin === true) {

                    if (status === "Resolved") {

                        actionButtons = `
                            <button class="soc-btn primary"
                                onclick="editIOC(${id}, '${ip}')">
                                Edit
                            </button>

                            <button class="soc-btn danger"
                                onclick="deleteIOC(${id})">
                                Clear
                            </button>
                        `;

                    } else {

                        actionButtons = `
                            <button class="soc-btn primary"
                                onclick="editIOC(${id}, '${ip}')">
                                Edit
                            </button>

                            <button class="soc-btn success"
                                onclick="resolveIOC(${id})">
                                Resolve
                            </button>

                            <button class="soc-btn danger"
                                onclick="deleteIOC(${id})">
                                Clear
                            </button>
                        `;
                    }
                }

                table.innerHTML += `
                    <tr>
                        <td>${id}</td>
                        <td>${ip}</td>
                        <td>
                            <span class="status ${statusClass}">
                                ${status}
                            </span>
                        </td>
                        <td>${actionButtons}</td>
                    </tr>
                `;
            });
        });
}


function addIOC() {

    const ip = document.getElementById("iocInput").value.trim();
    if (!ip) return;

    fetch("/ioc/add", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: ip })
    })
    .then(res => res.json())
    .then(data => {

        if (data.status === "ioc_added") {
            document.getElementById("iocInput").value = "";
            loadIOCs();
        } else {
            alert(data.error);
        }
    });
}


function editIOC(id, oldIP) {

    const newIP = prompt("Edit IOC:", oldIP);
    if (!newIP) return;

    fetch(`/ioc/edit/${id}`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: newIP })
    })
    .then(() => loadIOCs());
}


function resolveIOC(id) {

    fetch(`/ioc/resolve/${id}`, {
        method: "POST"
    })
    .then(res => res.json())
    .then(data => {
        if (data.status === "resolved") {
            loadIOCs();
        }
    });
}


function deleteIOC(id) {

    if (!confirm("Delete this IOC?")) return;

    fetch(`/ioc/delete/${id}`, {
        method: "POST"
    })
    .then(() => loadIOCs());
}


function clearAllIOCs() {

    if (!confirm("Clear ALL IOCs?")) return;

    fetch("/clear_iocs", {
        method: "POST"
    })
    .then(() => loadIOCs());
}


document.addEventListener("DOMContentLoaded", loadIOCs);

/* ===============================
   CONFIRM CLEAR
=============================== */

function confirmClear(){

    if(confirm("Are you sure you want to clear all threats?")){
        clearThreats();
    }
}


/* ===============================
   FILTER LOGS
=============================== */

function filterLogs(){

    let filter = document.getElementById("threatFilter").value;
    let logs = document.querySelectorAll(".log-entry");

    logs.forEach(log => {

        if(filter === "All"){
            log.style.display = "grid";
        } else {
            if(log.classList.contains(filter)){
                log.style.display = "grid";
            } else {
                log.style.display = "none";
            }
        }

    });
}


/* ===============================
   EXPORT CSV
=============================== */

function exportLogs(){

    fetch("/api/logs")
        .then(res => res.json())
        .then(data => {

            let csv = "Timestamp,Message,Threat,Geo\n";

            data.forEach(log => {
                csv += `"${log[0]}","${log[1]}","${log[2]}","${log[3]}"\n`;
            });

            let blob = new Blob([csv], { type: "text/csv" });
            let url = window.URL.createObjectURL(blob);

            let a = document.createElement("a");
            a.href = url;
            a.download = "fronx_logs.csv";
            a.click();
        });
}


/* ===============================
   ADD PULSE ON NEW THREAT
=============================== */

socket.on("new_log", function(data){

    setTimeout(() => {

        let firstLog = document.querySelector(".log-entry");
        if(firstLog){
            firstLog.classList.add("pulse");

            setTimeout(() => {
                firstLog.classList.remove("pulse");
            }, 2000);
        }

    }, 100);

});

/* ===============================
   OVERVIEW INCIDENT FEED
=============================== */

function loadOverviewIncidents(){

    let container = document.getElementById("overviewIncidents");
    if(!container) return;

    fetch("/api/incidents")
        .then(res => res.json())
        .then(data => {

            container.innerHTML = "";

            data.forEach(incident => {

                if(incident[4] === "Open"){  // status column

                    let severityClass = incident[3].toLowerCase();

                    let div = document.createElement("div");
                    div.className = "log-entry " + incident[3];

                    div.innerHTML = `
                        <div class="log-threat">${incident[3]}</div>
                        <div class="log-message">
                            Incident #${incident[0]} - ${incident[2]}
                        </div>
                        <div class="log-geo">Assigned: ${incident[5]}</div>
                    `;

                    container.appendChild(div);
                }
            });
        });
}

window.addEventListener("load", loadOverviewIncidents);



// ==============================
// CLEAR ALL
// ==============================
function clearAllIOCs() {

    if (!confirm("Clear ALL IOCs?")) return;

    fetch("/clear_iocs", {
        method: "POST"
    })
    .then(res => res.json())
    .then(() => loadIOCs());
}


// ==============================
// AUTO LOAD
// ==============================
document.addEventListener("DOMContentLoaded", function() {
    loadIOCs();
});