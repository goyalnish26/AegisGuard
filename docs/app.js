const isDemoMode = window.location.hostname.includes("github.io") || window.location.protocol === "file:";

if (isDemoMode) {
    console.log("[AegisGuard] Running in DEMO / MOCK Mode (Local Storage DB)");
    setupMockDatabase();
    
    // Override fetch to support serverless deployment on GitHub Pages
    const originalFetch = window.fetch;
    window.fetch = async function(url, options) {
        const urlStr = url.toString();
        
        if (urlStr.includes("/api/stats")) {
            return mockResponse(getMockStats());
        }
        
        if (urlStr.includes("/api/alerts?")) {
            const urlObj = new URL(urlStr, window.location.origin);
            const severity = urlObj.searchParams.get("severity");
            const status = urlObj.searchParams.get("status");
            return mockResponse(getMockAlerts(severity, status));
        }
        
        if (urlStr.includes("/api/alerts/") && urlStr.endsWith("/resolve")) {
            const match = urlStr.match(/\/api\/alerts\/(\d+)\/resolve/);
            if (match) {
                const id = parseInt(match[1]);
                const body = JSON.parse(options.body);
                updateMockAlertStatus(id, body.status);
                return mockResponse({ status: "success", message: `Alert status updated to ${body.status}` });
            }
        }
        
        if (urlStr.includes("/api/alerts/clear")) {
            clearMockAlerts();
            return mockResponse({ status: "success", message: "All alerts cleared" });
        }
        
        if (urlStr.includes("/api/simulate")) {
            const body = JSON.parse(options.body);
            triggerMockSimulation(body.attack_type);
            return mockResponse({ status: "success", message: `Simulation of ${body.attack_type} started` });
        }
        
        return originalFetch(url, options);
    };
}

function mockResponse(data) {
    return new Response(JSON.stringify(data), {
        status: 200,
        headers: { 'Content-Type': 'application/json' }
    });
}

function setupMockDatabase() {
    if (!localStorage.getItem("aegis_alerts")) {
        const now = new Date();
        const defaultAlerts = [
            {
                id: 1,
                timestamp: new Date(now - 3600000 * 2).toISOString(),
                rule_name: "SQL Injection Attempt",
                source_ip: "198.51.100.42",
                severity: "Critical",
                status: "New",
                description: "SQL injection signatures detected in the request URL or parameters.",
                raw_log: '198.51.100.42 - - [24/May/2026:12:00:00 +0530] "GET /products.php?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users HTTP/1.1" 200 1204 "-" "Mozilla/5.0"'
            },
            {
                id: 2,
                timestamp: new Date(now - 3600000 * 1.5).toISOString(),
                rule_name: "Sensitive Path Access",
                source_ip: "203.0.113.88",
                severity: "Medium",
                status: "Resolved",
                description: "Access attempt targeting administrative, configuration, or environment files.",
                raw_log: '203.0.113.88 - - [24/May/2026:12:30:00 +0530] "GET /.env HTTP/1.1" 404 150 "-" "Mozilla/5.0"'
            },
            {
                id: 3,
                timestamp: new Date(now - 60000 * 10).toISOString(),
                rule_name: "Failed SSH Login Attempt",
                source_ip: "185.220.101.5",
                severity: "Low",
                status: "New",
                description: "A failed SSH authentication attempt was detected. (User: admin)",
                raw_log: '2026-05-24T14:45:00+05:30 [INFO] sshd[12401]: Failed password for admin from 185.220.101.5 port 54312 ssh2'
            }
        ];
        localStorage.setItem("aegis_alerts", JSON.stringify(defaultAlerts));
    }
}

function getMockAlerts(severity, status) {
    let alerts = JSON.parse(localStorage.getItem("aegis_alerts") || "[]");
    alerts.sort((a, b) => b.id - a.id);
    
    if (severity) {
        alerts = alerts.filter(a => a.severity === severity);
    }
    if (status) {
        alerts = alerts.filter(a => a.status === status);
    }
    return { status: "success", data: alerts };
}

function getMockStats() {
    const alerts = JSON.parse(localStorage.getItem("aegis_alerts") || "[]");
    
    const total_alerts = alerts.length;
    const active_alerts = alerts.filter(a => a.status === "New").length;
    
    const severity_breakdown = {
        Critical: alerts.filter(a => a.severity === "Critical").length,
        High: alerts.filter(a => a.severity === "High").length,
        Medium: alerts.filter(a => a.severity === "Medium").length,
        Low: alerts.filter(a => a.severity === "Low").length
    };
    
    const ipCounts = {};
    alerts.forEach(a => {
        ipCounts[a.source_ip] = (ipCounts[a.source_ip] || 0) + 1;
    });
    
    const top_ips = Object.entries(ipCounts)
        .map(([ip, count]) => ({ ip, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 5);
        
    return {
        status: "success",
        data: {
            total_alerts,
            active_alerts,
            severity_breakdown,
            top_ips
        }
    };
}

function updateMockAlertStatus(id, status) {
    const alerts = JSON.parse(localStorage.getItem("aegis_alerts") || "[]");
    const idx = alerts.findIndex(a => a.id === id);
    if (idx !== -1) {
        alerts[idx].status = status;
        localStorage.setItem("aegis_alerts", JSON.stringify(alerts));
    }
}

function clearMockAlerts() {
    localStorage.setItem("aegis_alerts", JSON.stringify([]));
}

function triggerMockSimulation(attackType) {
    const alerts = JSON.parse(localStorage.getItem("aegis_alerts") || "[]");
    const nextId = alerts.length > 0 ? Math.max(...alerts.map(a => a.id)) + 1 : 1;
    const now = new Date().toISOString();
    
    const MALICIOUS_IPS = ["198.51.100.42", "203.0.113.88", "185.220.101.5", "45.143.203.14", "91.241.19.84"];
    const NORMAL_IPS = ["192.168.1.15", "10.0.0.4", "192.168.1.105", "182.21.43.109", "122.160.231.10"];
    const USERNAMES = ["root", "admin", "ubuntu", "user", "oracle", "test", "support"];
    
    const randomMaliciousIp = MALICIOUS_IPS[Math.floor(Math.random() * MALICIOUS_IPS.length)];
    const randomNormalIp = NORMAL_IPS[Math.floor(Math.random() * NORMAL_IPS.length)];
    const randomUser = USERNAMES[Math.floor(Math.random() * USERNAMES.length)];
    
    if (attackType === "normal") {
        console.log("[Demo] Simulated normal traffic successfully.");
        return;
    }
    
    let newAlerts = [];
    
    if (attackType === "brute_force") {
        let tempId = nextId;
        for (let i = 0; i < 5; i++) {
            newAlerts.push({
                id: tempId++,
                timestamp: new Date(Date.now() - (5 - i) * 1000).toISOString(),
                rule_name: "Failed SSH Login Attempt",
                source_ip: randomMaliciousIp,
                severity: "Low",
                status: "New",
                description: `A failed SSH authentication attempt was detected. (User: ${randomUser})`,
                raw_log: `${now} [INFO] sshd[${Math.floor(Math.random() * 20000) + 10000}]: Failed password for ${randomUser} from ${randomMaliciousIp} port ${Math.floor(Math.random() * 25000) + 40000} ssh2`
            });
        }
        
        newAlerts.push({
            id: tempId,
            timestamp: now,
            rule_name: "SSH Login Brute Force",
            source_ip: randomMaliciousIp,
            severity: "High",
            status: "New",
            description: `IP address ${randomMaliciousIp} triggered brute-force threshold: 5 failed attempts within 60s.`,
            raw_log: `Multiple failures. Last log: Failed password for ${randomUser} from ${randomMaliciousIp}`
        });
    } else if (attackType === "sqli") {
        newAlerts.push({
            id: nextId,
            timestamp: now,
            rule_name: "SQL Injection Attempt",
            source_ip: randomMaliciousIp,
            severity: "Critical",
            status: "New",
            description: "SQL injection signatures detected in the request URL or parameters.",
            raw_log: `${randomMaliciousIp} - - [${now}] "GET /products.php?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users HTTP/1.1" 200 1204 "-" "Mozilla/5.0"`
        });
    } else if (attackType === "xss") {
        newAlerts.push({
            id: nextId,
            timestamp: now,
            rule_name: "Cross-Site Scripting (XSS) Attempt",
            source_ip: randomMaliciousIp,
            severity: "High",
            status: "New",
            description: "XSS script execution tags detected in incoming web request.",
            raw_log: `${randomMaliciousIp} - - [${now}] "GET /comment.php?msg=<script>alert('hack')</script> HTTP/1.1" 200 450 "-" "Mozilla/5.0"`
        });
    } else if (attackType === "dir_traversal") {
        newAlerts.push({
            id: nextId,
            timestamp: now,
            rule_name: "Directory Traversal Attempt",
            source_ip: randomMaliciousIp,
            severity: "High",
            status: "New",
            description: "Directory traversal attempt targeting sensitive files or path evasion.",
            raw_log: `${randomMaliciousIp} - - [${now}] "GET /download.php?file=../../../../etc/passwd HTTP/1.1" 403 220 "-" "Mozilla/5.0"`
        });
    } else if (attackType === "sensitive_path") {
        const paths = ["/.env", "/wp-admin", "/config/db.php", "/phpinfo.php"];
        const path = paths[Math.floor(Math.random() * paths.length)];
        newAlerts.push({
            id: nextId,
            timestamp: now,
            rule_name: "Sensitive Path Access",
            source_ip: randomMaliciousIp,
            severity: "Medium",
            status: "New",
            description: "Access attempt targeting administrative, configuration, or environment files.",
            raw_log: `${randomMaliciousIp} - - [${now}] "GET ${path} HTTP/1.1" 404 150 "-" "Mozilla/5.0"`
        });
    }
    
    const updatedAlerts = [...alerts, ...newAlerts];
    localStorage.setItem("aegis_alerts", JSON.stringify(updatedAlerts));
}

let severityChartInstance = null;
let currentAlerts = [];
let lastAlertId = 0;

// Initialize Dashboard
document.addEventListener("DOMContentLoaded", () => {
    initChart();
    fetchData();
    setupNavigation();
    initCyberBackground();
    initTerminalTelemetry();
    // Start auto polling every 3 seconds
    setInterval(fetchData, 3000);
});

// Setup dynamic navigation active class switching and smooth scroll
function setupNavigation() {
    const navLinks = document.querySelectorAll(".nav-links a");
    const mainContent = document.querySelector(".main-content");
    
    const updateActiveLink = () => {
        const currentHash = window.location.hash || "#dashboard";
        navLinks.forEach(link => {
            if (link.getAttribute("href") === currentHash) {
                link.classList.add("active");
            } else {
                link.classList.remove("active");
            }
        });
    };
    
    const navigateTo = (targetId, smooth = true) => {
        if (targetId === "#dashboard" || !targetId) {
            const firstChild = mainContent ? mainContent.querySelector(".header") || mainContent.firstElementChild : null;
            if (firstChild) {
                firstChild.scrollIntoView({ behavior: smooth ? "smooth" : "auto", block: "start" });
            }
        } else {
            const targetElement = document.querySelector(targetId);
            if (targetElement) {
                targetElement.scrollIntoView({ behavior: smooth ? "smooth" : "auto", block: "start" });
            }
        }
    };
    
    window.addEventListener("hashchange", () => {
        updateActiveLink();
        navigateTo(window.location.hash);
    });
    
    updateActiveLink();
    if (window.location.hash) {
        // Scroll to the active hash on load
        setTimeout(() => navigateTo(window.location.hash, false), 200);
    }
    
    navLinks.forEach(link => {
        link.addEventListener("click", (e) => {
            const targetId = link.getAttribute("href");
            if (targetId.startsWith("#")) {
                e.preventDefault();
                if (window.location.hash !== targetId) {
                    window.history.pushState(null, null, targetId);
                    updateActiveLink();
                    navigateTo(targetId);
                } else if (targetId === "#dashboard") {
                    // If already on dashboard and clicking it, scroll to top
                    navigateTo(targetId);
                }
            }
        });
    });
}


// Initialize Chart.js Doughnut Chart with Cyberpunk style
function initChart() {
    const ctx = document.getElementById('severityChart').getContext('2d');
    
    severityChartInstance = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low'],
            datasets: [{
                data: [0, 0, 0, 0],
                backgroundColor: [
                    '#ff2a5f', // Critical (neon red)
                    '#ffaa00', // High (neon gold)
                    '#00f3ff', // Medium (neon cyan)
                    '#00ff66'  // Low (neon matrix green)
                ],
                borderWidth: 2,
                borderColor: '#05070c',
                hoverOffset: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#8f9cae',
                        font: {
                            family: 'Share Tech Mono',
                            size: 12
                        },
                        padding: 15
                    }
                }
            },
            cutout: '70%'
        }
    });
}

// Fetch stats and alert data from FastAPI
async function fetchData() {
    try {
        const severityFilter = document.getElementById("filter-severity").value;
        const statusFilter = document.getElementById("filter-status").value;
        
        // 1. Fetch Stats
        const statsRes = await fetch("/api/stats");
        const statsData = await statsRes.json();
        
        if (statsData.status === "success") {
            updateStatsUI(statsData.data);
        }
        
        // 2. Fetch Alerts
        let alertsUrl = "/api/alerts?limit=50";
        if (severityFilter) alertsUrl += `&severity=${severityFilter}`;
        if (statusFilter) alertsUrl += `&status=${statusFilter}`;
        
        const alertsRes = await fetch(alertsUrl);
        const alertsData = await alertsRes.json();
        
        if (alertsData.status === "success") {
            currentAlerts = alertsData.data;
            updateAlertsTable(currentAlerts);
            updateTerminal(currentAlerts);
        }
    } catch (error) {
        console.error("[!] Error fetching data from server:", error);
    }
}

// Update the Metrics Cards and Charts
function updateStatsUI(stats) {
    document.getElementById("stat-total").innerText = stats.total_alerts;
    document.getElementById("stat-active").innerText = stats.active_alerts;
    
    const criticalAndHigh = (stats.severity_breakdown.Critical || 0) + (stats.severity_breakdown.High || 0);
    document.getElementById("stat-critical").innerText = criticalAndHigh;
    
    // Update system status indicator
    const systemStatusContainer = document.getElementById("system-status-container");
    const statusText = document.getElementById("status-text");
    
    // Check if there are active Critical or High alerts
    // Under attack if active_alerts > 0 AND criticalAndHigh > 0
    if (stats.active_alerts > 0 && criticalAndHigh > 0) {
        systemStatusContainer.className = "system-status-indicator under-attack";
        statusText.innerText = "THREATS DETECTED";
    } else {
        systemStatusContainer.className = "system-status-indicator";
        statusText.innerText = "SYSTEM SECURED";
    }
    
    // Update Doughnut Chart Data
    if (severityChartInstance) {
        severityChartInstance.data.datasets[0].data = [
            stats.severity_breakdown.Critical || 0,
            stats.severity_breakdown.High || 0,
            stats.severity_breakdown.Medium || 0,
            stats.severity_breakdown.Low || 0
        ];
        severityChartInstance.update();
    }
    
    // Update Top Offending IPs List
    const topIpsList = document.getElementById("top-ips-list");
    topIpsList.innerHTML = "";
    
    if (!stats.top_ips || stats.top_ips.length === 0) {
        topIpsList.innerHTML = `<li class="empty-state">No offender metrics found.</li>`;
        return;
    }
    
    const maxCount = stats.top_ips[0].count; // Highest count for scaling width
    
    stats.top_ips.forEach(ipData => {
        const percentage = maxCount > 0 ? (ipData.count / maxCount) * 100 : 0;
        const li = document.createElement("li");
        li.innerHTML = `
            <div class="top-ip-row">
                <span class="ip-address">${ipData.ip}</span>
                <span class="ip-count">${ipData.count} alerts</span>
            </div>
            <div class="ip-bar-wrapper">
                <div class="ip-bar-fill" style="width: ${percentage}%"></div>
            </div>
        `;
        topIpsList.appendChild(li);
    });
}

// Update the Incident Feed Table
function updateAlertsTable(alerts) {
    const tbody = document.getElementById("alerts-tbody");
    tbody.innerHTML = "";
    
    if (alerts.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="table-empty">
                    <i class="fa-solid fa-circle-check" style="color: var(--severity-low)"></i> No alerts found. System is clean.
                </td>
            </tr>
        `;
        return;
    }
    
    alerts.forEach(alert => {
        // Format ISO timestamp to local readable format
        // timestamp format: 2026-05-24T14:15:00.123456
        let formattedTime = alert.timestamp;
        try {
            const date = new Date(alert.timestamp);
            formattedTime = date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) + 
                            " " + date.toLocaleDateString([], { month: 'short', day: 'numeric' });
        } catch(e) {}
        
        const tr = document.createElement("tr");
        tr.innerHTML = `
            <td class="timestamp-col">${formattedTime}</td>
            <td><strong>${escapeHtml(alert.rule_name)}</strong></td>
            <td class="ip-col">${escapeHtml(alert.source_ip)}</td>
            <td><span class="severity-pill ${alert.severity.toLowerCase()}">${alert.severity}</span></td>
            <td><span class="status-pill ${alert.status.toLowerCase()}">${alert.status}</span></td>
            <td>
                <button class="btn btn-secondary" style="padding: 0.35rem 0.75rem; font-size: 0.75rem;" onclick="openModal(${alert.id})">
                    Investigate
                </button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

// Trigger simulated logs
async function triggerSimulation(attackType) {
    try {
        const response = await fetch("/api/simulate", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ attack_type: attackType })
        });
        const result = await response.json();
        if (result.status === "success") {
            // Instantly fetch data after a short timeout so log ingestion finishes
            setTimeout(fetchData, 400);
        }
    } catch (e) {
        console.error("Error triggering simulation:", e);
    }
}

// Modal handling
function openModal(alertId) {
    const alert = currentAlerts.find(a => a.id === alertId);
    if (!alert) return;
    
    document.getElementById("modal-title").innerText = alert.rule_name;
    document.getElementById("modal-timestamp").innerText = alert.timestamp;
    document.getElementById("modal-ip").innerText = alert.source_ip;
    document.getElementById("modal-rule").innerText = alert.rule_name;
    
    const severityBadge = document.getElementById("modal-severity");
    severityBadge.className = `badge severity-pill ${alert.severity.toLowerCase()}`;
    severityBadge.innerText = alert.severity;
    
    document.getElementById("modal-desc").innerText = alert.description;
    document.getElementById("modal-raw-log").innerText = alert.raw_log;
    
    const footerActions = document.getElementById("modal-footer-actions");
    footerActions.innerHTML = "";
    
    if (alert.status === "New") {
        footerActions.innerHTML = `
            <button class="btn btn-secondary" onclick="updateAlertStatus(${alert.id}, 'Dismissed')">Dismiss Alert</button>
            <button class="btn btn-primary" onclick="updateAlertStatus(${alert.id}, 'Resolved')">
                <i class="fa-solid fa-check"></i> Mark Resolved
            </button>
        `;
    } else {
        footerActions.innerHTML = `
            <button class="btn btn-secondary" onclick="updateAlertStatus(${alert.id}, 'New')">Reopen Incident</button>
            <button class="btn btn-secondary" onclick="closeModal()">Close</button>
        `;
    }
    
    document.getElementById("alert-modal").style.display = "flex";
}

function closeModal() {
    document.getElementById("alert-modal").style.display = "none";
}

// Update alert status (resolve/dismiss/reopen)
async function updateAlertStatus(alertId, newStatus) {
    try {
        const response = await fetch(`/api/alerts/${alertId}/resolve`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ status: newStatus })
        });
        const result = await response.json();
        if (result.status === "success") {
            closeModal();
            fetchData();
        }
    } catch (e) {
        console.error("Error updating status:", e);
    }
}

// Clear database alerts
async function clearAllAlerts() {
    if (!confirm("Are you sure you want to clear all security incidents from the database? This cannot be undone.")) {
        return;
    }
    try {
        const response = await fetch("/api/alerts/clear", { method: "POST" });
        const result = await response.json();
        if (result.status === "success") {
            fetchData();
        }
    } catch (e) {
        console.error("Error clearing DB:", e);
    }
}

// Helper to escape HTML and prevent injection in UI
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return String(text).replace(/[&<>"']/g, function(m) { return map[m]; });
}

// Dynamic Cyber Matrix Rain Background Canvas
function initCyberBackground() {
    const canvas = document.getElementById("cyber-canvas");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    
    let width = canvas.width = window.innerWidth;
    let height = canvas.height = window.innerHeight;
    
    window.addEventListener("resize", () => {
        width = canvas.width = window.innerWidth;
        height = canvas.height = window.innerHeight;
    });
    
    const columns = Math.floor(width / 24) + 1;
    const ypos = Array(columns).fill(0);
    
    function draw() {
        ctx.fillStyle = "rgba(5, 7, 12, 0.05)";
        ctx.fillRect(0, 0, width, height);
        
        ctx.fillStyle = "rgba(0, 255, 102, 0.08)"; // Subtle neon green/matrix color
        ctx.font = "11px monospace";
        
        ypos.forEach((y, ind) => {
            // Generate a random visual cyber token character
            const chars = "01010101ABCDEFGHIJKLMNOPQRSTUVWXYZ@#$*&";
            const text = chars.charAt(Math.floor(Math.random() * chars.length));
            const x = ind * 24;
            ctx.fillText(text, x, y);
            if (y > 100 + Math.random() * 10000) {
                ypos[ind] = 0;
            } else {
                ypos[ind] = y + 15;
            }
        });
    }
    
    setInterval(draw, 50);
}

// Live telemetry log feed terminal update
function updateTerminal(alerts) {
    const terminalBody = document.getElementById("terminal-body");
    if (!terminalBody) return;
    
    // Get alerts that have ids larger than lastAlertId
    const newAlerts = alerts.filter(a => a.id > lastAlertId).reverse();
    if (newAlerts.length > 0) {
        lastAlertId = Math.max(...alerts.map(a => a.id));
        
        newAlerts.forEach(alert => {
            const line = document.createElement("div");
            line.className = `terminal-line alert-line ${alert.severity.toLowerCase()}`;
            
            // Generate clean datetime stamp
            let dateStr = "";
            try {
                const date = new Date(alert.timestamp);
                dateStr = date.toLocaleTimeString();
            } catch(e) {
                dateStr = new Date().toLocaleTimeString();
            }
            
            line.innerHTML = `<span class="term-lbl-crit">[${dateStr}] [SEC-ALERT] [${alert.severity.toUpperCase()}]</span> IP: ${escapeHtml(alert.source_ip)} :: Match rule: ${escapeHtml(alert.rule_name)} -> Payload: ${escapeHtml(alert.description)}`;
            terminalBody.appendChild(line);
        });
        
        // Auto scroll
        terminalBody.scrollTop = terminalBody.scrollHeight;
    }
}

// continuous tactical background security logs
function initTerminalTelemetry() {
    const terminalBody = document.getElementById("terminal-body");
    if (!terminalBody) return;
    
    const telemetryMsgs = [
        "AegisGuard daemon sentinel initialized.",
        "Ingested log block. Status: 0 threat signatures matched.",
        "Heartbeat broadcast received from monitoring node AEGIS-01.",
        "Internal DB integrity check: OK. Access logs indexed.",
        "Network packet buffer analyzed. 0 malformed headers.",
        "Listening for intrusion signatures on default interfaces...",
        "Telemetry agent active: CPU 1.2%, Mem 42MB.",
        "Port scan sensor calibrating rules...",
        "IP reputation check completed: 0 flagged sources."
    ];
    
    setInterval(() => {
        // Occasionally append standard console logging for SOC realism
        if (Math.random() > 0.4) {
            const msg = telemetryMsgs[Math.floor(Math.random() * telemetryMsgs.length)];
            const line = document.createElement("div");
            line.className = "terminal-line telemetry-line";
            line.innerHTML = `<span class="term-lbl-tele">[${new Date().toLocaleTimeString()}] [MONITOR]</span> ${msg}`;
            terminalBody.appendChild(line);
            
            // Keep container clean of memory leaks (max 80 lines)
            while (terminalBody.childElementCount > 80) {
                terminalBody.removeChild(terminalBody.firstChild);
            }
            terminalBody.scrollTop = terminalBody.scrollHeight;
        }
    }, 4500);
}
