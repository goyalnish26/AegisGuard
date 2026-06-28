// AegisGuard Core Configuration
// For live production deployment (e.g. Render/Railway), configure your URL here:
const API_BASE_URL = window.location.hostname.includes("github.io")
    ? "https://aegisguard-backend.onrender.com" // Replace with actual deployed Render URL
    : ""; // Empty for relative URLs when running locally

// Set to true to connect to the live backend even on github.io or file://
const FORCE_LIVE_BACKEND = false;

const isDemoMode = (window.location.hostname.includes("github.io") || window.location.protocol === "file:") && !FORCE_LIVE_BACKEND;

// JWT Token state management
let jwtToken = localStorage.getItem("aegis_jwt_token");

async function checkAndAcquireToken() {
    if (isDemoMode) return;
    
    if (!jwtToken) {
        try {
            console.log("[AegisGuard] Attempting automatic JWT silent login...");
            const params = new URLSearchParams();
            params.append('username', 'admin');
            params.append('password', 'aegisguard');
            
            const response = await fetch(`${API_BASE_URL}/api/login`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded"
                },
                body: params
            });
            const result = await response.json();
            if (result.access_token) {
                jwtToken = result.access_token;
                localStorage.setItem("aegis_jwt_token", jwtToken);
                console.log("[AegisGuard] JWT silent login successful.");
            }
        } catch (e) {
            console.error("[AegisGuard] Failed to auto-login:", e);
        }
    }
}

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
        
        if (urlStr.includes("/api/alerts") && urlStr.includes("limit=")) {
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
                raw_log: '198.51.100.42 - - [24/May/2026:12:00:00 +0530] "GET /products.php?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users HTTP/1.1" 200 1204 "-" "Mozilla/5.0"',
                lat: 40.7128,
                lng: -74.0060,
                mitre_id: "T1190",
                mitre_name: "Exploit Public-Facing Application"
            },
            {
                id: 2,
                timestamp: new Date(now - 3600000 * 1.5).toISOString(),
                rule_name: "Sensitive Path Access",
                source_ip: "203.0.113.88",
                severity: "Medium",
                status: "Resolved",
                description: "Access attempt targeting administrative, configuration, or environment files.",
                raw_log: '203.0.113.88 - - [24/May/2026:12:30:00 +0530] "GET /.env HTTP/1.1" 404 150 "-" "Mozilla/5.0"',
                lat: 51.5074,
                lng: -0.1278,
                mitre_id: "T1595",
                mitre_name: "Active Scanning"
            },
            {
                id: 3,
                timestamp: new Date(now - 60000 * 10).toISOString(),
                rule_name: "Failed SSH Login Attempt",
                source_ip: "185.220.101.5",
                severity: "Low",
                status: "New",
                description: "A failed SSH authentication attempt was detected. (User: admin)",
                raw_log: '2026-05-24T14:45:00+05:30 [INFO] sshd[12401]: Failed password for admin from 185.220.101.5 port 54312 ssh2',
                lat: 52.5200,
                lng: 13.4050,
                mitre_id: "T1110",
                mitre_name: "Brute Force"
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
    const USERNAMES = ["root", "admin", "ubuntu", "user", "oracle", "test", "support"];
    
    const randomMaliciousIp = MALICIOUS_IPS[Math.floor(Math.random() * MALICIOUS_IPS.length)];
    const randomUser = USERNAMES[Math.floor(Math.random() * USERNAMES.length)];
    
    if (attackType === "normal") {
        console.log("[Demo] Simulated normal traffic successfully.");
        return;
    }
    
    let newAlerts = [];
    
    // Get geolocation mock fallbacks for simulation
    const geo = getSeverityColor(attackType); // just placeholder or standard geo mock
    const geoDetails = {
        "198.51.100.42": { lat: 40.7128, lng: -74.0060 },
        "203.0.113.88": { lat: 51.5074, lng: -0.1278 },
        "185.220.101.5": { lat: 52.5200, lng: 13.4050 },
        "45.143.203.14": { lat: 35.6762, lng: 139.6503 },
        "91.241.19.84": { lat: -23.5505, lng: -46.6333 }
    }[randomMaliciousIp] || { lat: 26.9124, lng: 75.7873 };
    
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
                raw_log: `${now} [INFO] sshd[${Math.floor(Math.random() * 20000) + 10000}]: Failed password for ${randomUser} from ${randomMaliciousIp} port ${Math.floor(Math.random() * 25000) + 40000} ssh2`,
                lat: geoDetails.lat,
                lng: geoDetails.lng,
                mitre_id: "T1110",
                mitre_name: "Brute Force"
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
            raw_log: `Multiple failures. Last log: Failed password for ${randomUser} from ${randomMaliciousIp}`,
            lat: geoDetails.lat,
            lng: geoDetails.lng,
            mitre_id: "T1110",
            mitre_name: "Brute Force"
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
            raw_log: `${randomMaliciousIp} - - [${now}] "GET /products.php?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users HTTP/1.1" 200 1204 "-" "Mozilla/5.0"`,
            lat: geoDetails.lat,
            lng: geoDetails.lng,
            mitre_id: "T1190",
            mitre_name: "Exploit Public-Facing Application"
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
            raw_log: `${randomMaliciousIp} - - [${now}] "GET /comment.php?msg=<script>alert('hack')</script> HTTP/1.1" 200 450 "-" "Mozilla/5.0"`,
            lat: geoDetails.lat,
            lng: geoDetails.lng,
            mitre_id: "T1189",
            mitre_name: "Drive-by Compromise"
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
            raw_log: `${randomMaliciousIp} - - [${now}] "GET /download.php?file=../../../../etc/passwd HTTP/1.1" 403 220 "-" "Mozilla/5.0"`,
            lat: geoDetails.lat,
            lng: geoDetails.lng,
            mitre_id: "T1083",
            mitre_name: "File and Directory Discovery"
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
            raw_log: `${randomMaliciousIp} - - [${now}] "GET ${path} HTTP/1.1" 404 150 "-" "Mozilla/5.0"`,
            lat: geoDetails.lat,
            lng: geoDetails.lng,
            mitre_id: "T1595",
            mitre_name: "Active Scanning"
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
    setupMobileMenu();
    
    // AegisGuard v2 Premium Initializations
    initCounters();
    initParticlesBg();
    initGlobe();
    initTiltEffect();
    
    if (!isDemoMode) {
        initWebSocket();
        setInterval(fetchData, 30000); // Poll less frequently when WebSocket is active
    } else {
        setInterval(fetchData, 3000); // Standard poll for local storage demo
    }
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
                    navigateTo(targetId);
                }
            }
        });
    });
}

function setupMobileMenu() {
    const toggleBtn = document.getElementById("mobile-menu-toggle");
    const sidebar = document.querySelector(".sidebar");
    const overlay = document.getElementById("sidebar-overlay");
    const navLinks = document.querySelectorAll(".nav-links a");
    
    if (!toggleBtn || !sidebar || !overlay) return;
    
    const openMenu = () => {
        sidebar.classList.add("active");
        overlay.classList.add("active");
    };
    
    const closeMenu = () => {
        sidebar.classList.remove("active");
        overlay.classList.remove("active");
    };
    
    toggleBtn.addEventListener("click", openMenu);
    overlay.addEventListener("click", closeMenu);
    
    navLinks.forEach(link => {
        link.addEventListener("click", closeMenu);
    });
}

// Initialize Chart.js Doughnut Chart with Cyberpunk style
function initChart() {
    const canvasEl = document.getElementById('severityChart');
    if (!canvasEl) return;
    const ctx = canvasEl.getContext('2d');
    
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
                    '#8f9cae'  // Low (muted gray)
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
        const statsRes = await fetch(`${API_BASE_URL}/api/stats`);
        const statsData = await statsRes.json();
        
        if (statsData.status === "success") {
            updateStatsUI(statsData.data);
        }
        
        // 2. Fetch Alerts
        let alertsUrl = `${API_BASE_URL}/api/alerts?limit=50`;
        if (severityFilter) alertsUrl += `&severity=${severityFilter}`;
        if (statusFilter) alertsUrl += `&status=${statusFilter}`;
        
        const alertsRes = await fetch(alertsUrl);
        const alertsData = await alertsRes.json();
        
        if (alertsData.status === "success") {
            currentAlerts = alertsData.data;
            updateAlertsTable(currentAlerts);
            updateTerminal(currentAlerts);
            updateGlobePoints();
        }
    } catch (error) {
        console.error("[!] Error fetching data from server:", error);
    }
}

// Update the Metrics Cards and Charts
function updateStatsUI(stats) {
    const criticalAndHigh = (stats.severity_breakdown.Critical || 0) + (stats.severity_breakdown.High || 0);
    
    // Update animated counters or raw values
    if (countUpTotal && countUpActive && countUpCritical) {
        countUpTotal.update(stats.total_alerts);
        countUpActive.update(stats.active_alerts);
        countUpCritical.update(criticalAndHigh);
    } else {
        document.getElementById("stat-total").innerText = stats.total_alerts;
        document.getElementById("stat-active").innerText = stats.active_alerts;
        document.getElementById("stat-critical").innerText = criticalAndHigh;
    }
    
    // Update system status indicator
    const systemStatusContainer = document.getElementById("system-status-container");
    const statusText = document.getElementById("status-text");
    
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
}

// Update the Incident Feed Table
function updateAlertsTable(alerts) {
    const tbody = document.getElementById("alerts-tbody");
    tbody.innerHTML = "";
    
    if (alerts.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="table-empty">
                    <i class="fa-solid fa-circle-check" style="color: var(--cyber-green)"></i> No alerts found. System is clean.
                </td>
            </tr>
        `;
        return;
    }
    
    alerts.forEach(alert => {
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
        const response = await fetch(`${API_BASE_URL}/api/simulate`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ attack_type: attackType })
        });
        const result = await response.json();
        if (result.status === "success") {
            setTimeout(fetchData, 400);
        }
    } catch (e) {
        console.error("Error triggering simulation:", e);
    }
}

// Modal handling with text scramble animation
function openModal(alertId) {
    const alert = currentAlerts.find(a => a.id === alertId);
    if (!alert) return;
    
    document.getElementById("alert-modal").style.display = "flex";
    
    // MONOSPACE SCRAMBLE "DECRYPTING" ANIMATION
    decryptField("modal-title", alert.rule_name.toUpperCase());
    decryptField("modal-timestamp", alert.timestamp);
    decryptField("modal-ip", alert.source_ip);
    decryptField("modal-rule", alert.rule_name);
    
    const severityBadge = document.getElementById("modal-severity");
    severityBadge.className = `badge severity-pill ${alert.severity.toLowerCase()}`;
    severityBadge.innerText = alert.severity;
    
    decryptField("modal-desc", alert.description);
    decryptField("modal-raw-log", alert.raw_log);
    
    // Populate MITRE fields
    const mitreId = alert.mitre_id || "N/A";
    const mitreName = alert.mitre_name || "N/A";
    decryptField("modal-mitre-id", mitreId);
    decryptField("modal-mitre-name", mitreName);
    
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
}

function closeModal() {
    document.getElementById("alert-modal").style.display = "none";
}

// Update alert status (resolve/dismiss/reopen) with JWT Authorization headers
async function updateAlertStatus(alertId, newStatus) {
    if (isDemoMode) {
        updateMockAlertStatus(alertId, newStatus);
        closeModal();
        fetchData();
        return;
    }
    
    await checkAndAcquireToken();
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/alerts/${alertId}/resolve`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json",
                "Authorization": `Bearer ${jwtToken}`
            },
            body: JSON.stringify({ status: newStatus })
        });
        
        if (response.status === 401) {
            localStorage.removeItem("aegis_jwt_token");
            jwtToken = null;
            await checkAndAcquireToken();
            
            // Retry request
            await fetch(`${API_BASE_URL}/api/alerts/${alertId}/resolve`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    "Authorization": `Bearer ${jwtToken}`
                },
                body: JSON.stringify({ status: newStatus })
            });
        }
        
        closeModal();
        fetchData();
    } catch (e) {
        console.error("Error updating status:", e);
    }
}

// Clear database alerts with JWT Authorization headers
async function clearAllAlerts() {
    if (!confirm("Are you sure you want to clear all security incidents from the database? This cannot be undone.")) {
        return;
    }
    
    if (isDemoMode) {
        clearMockAlerts();
        fetchData();
        return;
    }
    
    await checkAndAcquireToken();
    
    try {
        const response = await fetch(`${API_BASE_URL}/api/alerts/clear`, {
            method: "POST",
            headers: {
                "Authorization": `Bearer ${jwtToken}`
            }
        });
        
        if (response.status === 401) {
            localStorage.removeItem("aegis_jwt_token");
            jwtToken = null;
            await checkAndAcquireToken();
            
            // Retry request
            await fetch(`${API_BASE_URL}/api/alerts/clear`, {
                method: "POST",
                headers: {
                    "Authorization": `Bearer ${jwtToken}`
                }
            });
        }
        
        fetchData();
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
    
    let columns = Math.floor(width / 24) + 1;
    let ypos = Array(columns).fill(0);
    
    let lastWidth = window.innerWidth;
    window.addEventListener("resize", () => {
        if (window.innerWidth !== lastWidth) {
            lastWidth = window.innerWidth;
            width = canvas.width = window.innerWidth;
            height = canvas.height = window.innerHeight;
            columns = Math.floor(width / 24) + 1;
            ypos = Array(columns).fill(0);
        }
    });
    
    function draw() {
        ctx.fillStyle = "rgba(5, 7, 12, 0.05)";
        ctx.fillRect(0, 0, width, height);
        
        ctx.fillStyle = "rgba(0, 255, 102, 0.08)";
        ctx.font = "11px monospace";
        
        ypos.forEach((y, ind) => {
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
    
    const newAlerts = alerts.filter(a => a.id > lastAlertId).reverse();
    if (newAlerts.length > 0) {
        lastAlertId = Math.max(...alerts.map(a => a.id));
        
        newAlerts.forEach(alert => {
            const line = document.createElement("div");
            line.className = `terminal-line alert-line ${alert.severity.toLowerCase()}`;
            
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
        if (Math.random() > 0.4) {
            const msg = telemetryMsgs[Math.floor(Math.random() * telemetryMsgs.length)];
            const line = document.createElement("div");
            line.className = "terminal-line telemetry-line";
            line.innerHTML = `<span class="term-lbl-tele">[${new Date().toLocaleTimeString()}] [MONITOR]</span> ${msg}`;
            terminalBody.appendChild(line);
            
            while (terminalBody.childElementCount > 80) {
                terminalBody.removeChild(terminalBody.firstChild);
            }
            terminalBody.scrollTop = terminalBody.scrollHeight;
        }
    }, 4500);
}

// --- AegisGuard v2 Premium Integrations ---

// Animated counters using CountUp.js
let countUpTotal, countUpActive, countUpCritical;

function initCounters() {
    if (window.countUp) {
        const { CountUp } = window.countUp;
        countUpTotal = new CountUp('stat-total', 0, { duration: 1.2, useEasing: true, useGrouping: true });
        countUpActive = new CountUp('stat-active', 0, { duration: 1.2, useEasing: true, useGrouping: true });
        countUpCritical = new CountUp('stat-critical', 0, { duration: 1.2, useEasing: true, useGrouping: true });
        
        countUpTotal.start();
        countUpActive.start();
        countUpCritical.start();
    }
}

// Particle background network using tsParticles
function initParticlesBg() {
    if (window.tsParticles) {
        tsParticles.load("particles-js", {
            fpsLimit: 60,
            particles: {
                number: {
                    value: 40,
                    density: {
                        enable: true,
                        value_area: 800
                    }
                },
                color: {
                    value: "#00f3ff"
                },
                shape: {
                    type: "circle"
                },
                opacity: {
                    value: 0.12,
                    random: true
                },
                size: {
                    value: 2.2,
                    random: true
                },
                links: {
                    enable: true,
                    distance: 140,
                    color: "#00f3ff",
                    opacity: 0.06,
                    width: 1
                },
                move: {
                    enable: true,
                    speed: 0.8,
                    direction: "none",
                    random: true,
                    straight: false,
                    outModes: {
                        default: "out"
                    }
                }
            },
            interactivity: {
                detectsOn: "canvas",
                events: {
                    onHover: {
                        enable: true,
                        mode: "grab"
                    },
                    resize: true
                },
                modes: {
                    grab: {
                        distance: 160,
                        links: {
                            opacity: 0.15
                        }
                    }
                }
            },
            retina_detect: true
        });
    }
}

// 3D rotating globe centerpiece using Globe.gl & Three.js
let myGlobe;

function initGlobe() {
    const container = document.getElementById('globe-container');
    if (!container) return;
    
    const width = container.clientWidth || 300;
    const height = container.clientHeight || 250;
    
    myGlobe = Globe()(container)
        .width(width)
        .height(height)
        .backgroundColor('rgba(0,0,0,0)')
        .showGlobe(true)
        .showAtmosphere(true)
        .atmosphereColor('#00f3ff')
        .atmosphereAltitude(0.15)
        .globeImageUrl(null)
        .arcColor(d => getSeverityColor(d.severity))
        .arcDashLength(0.4)
        .arcDashGap(0.2)
        .arcDashAnimateTime(1200)
        .pointColor(d => d.color || '#1D9E75')
        .pointAltitude(0.01)
        .pointRadius(0.35)
        .pointsData([]);
        
    // Apply wireframe style to material
    setTimeout(() => {
        try {
            const globeMaterial = myGlobe.globeMaterial();
            globeMaterial.color.setHex(0x0a0e17);
            globeMaterial.emissive.setHex(0x00f3ff);
            globeMaterial.emissiveIntensity = 0.15;
            globeMaterial.wireframe = true;
        } catch (e) {
            console.error("Error setting wireframe material:", e);
        }
    }, 150);
    
    // Load land boundaries
    fetch('https://unpkg.com/globe.gl/example/datasets/ne_110m_admin_0_countries.geojson')
        .then(res => res.json())
        .then(countries => {
            if (myGlobe) {
                myGlobe.hexPolygonsData(countries.features)
                    .hexPolygonResolution(3)
                    .hexPolygonMargin(0.3)
                    .hexPolygonColor(() => 'rgba(0, 243, 255, 0.15)');
            }
        })
        .catch(err => console.error("Error loading country boundaries:", err));
        
    // Slow auto-rotation
    let isHovered = false;
    container.addEventListener('mouseenter', () => isHovered = true);
    container.addEventListener('mouseleave', () => isHovered = false);
    
    setInterval(() => {
        if (!isHovered && myGlobe) {
            myGlobe.controls().autoRotate = true;
            myGlobe.controls().autoRotateSpeed = 0.35;
        } else if (myGlobe) {
            myGlobe.controls().autoRotate = false;
        }
    }, 100);
    
    // Handle container resize
    window.addEventListener('resize', () => {
        if (myGlobe && container) {
            myGlobe.width(container.clientWidth).height(container.clientHeight);
        }
    });
}

function updateGlobePoints() {
    if (!myGlobe || currentAlerts.length === 0) return;
    
    const offenderPoints = [];
    const ipSet = new Set();
    
    currentAlerts.forEach(alert => {
        if (alert.lat && alert.lng && !ipSet.has(alert.source_ip)) {
            ipSet.add(alert.source_ip);
            offenderPoints.push({
                lat: alert.lat,
                lng: alert.lng,
                name: `${alert.source_ip} (${alert.country || 'Unknown'})`,
                color: getSeverityColor(alert.severity)
            });
        }
    });
    
    myGlobe.pointsData(offenderPoints);
}

function getSeverityColor(severity) {
    const colors = {
        'Critical': '#ff2a5f',
        'High': '#ffaa00',
        'Medium': '#00f3ff',
        'Low': '#8f9cae'
    };
    return colors[severity] || '#00f3ff';
}

// Card mouse tilt effect using Vanilla-Tilt.js
function initTiltEffect() {
    if (window.VanillaTilt) {
        VanillaTilt.init(document.querySelectorAll(".metric-card, .chart-container, .sim-btn"), {
            max: 6,
            speed: 300,
            glare: true,
            "max-glare": 0.08,
        });
    }
}

// WebSocket client connection setup
let socket;

function initWebSocket() {
    let wsUrl;
    if (API_BASE_URL) {
        try {
            const tempUrl = new URL(API_BASE_URL);
            const protocol = tempUrl.protocol === "https:" ? "wss:" : "ws:";
            wsUrl = `${protocol}//${tempUrl.host}/ws/alerts`;
        } catch (e) {
            const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
            wsUrl = `${protocol}//${window.location.host}/ws/alerts`;
        }
    } else {
        const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
        wsUrl = `${protocol}//${window.location.host}/ws/alerts`;
    }
    
    socket = new WebSocket(wsUrl);
    
    socket.onopen = () => {
        console.log("[AegisGuard] Live push WebSocket connected.");
    };
    
    socket.onmessage = (event) => {
        try {
            const alert = JSON.parse(event.data);
            console.log("[AegisGuard] Real-time alert pushed:", alert);
            
            // Trigger globe travel arc
            if (myGlobe && alert.lat && alert.lng) {
                const newArc = {
                    startLat: alert.lat,
                    startLng: alert.lng,
                    endLat: 26.9124, // Server location Jaipur
                    endLng: 75.7873,
                    severity: alert.severity
                };
                
                const currentArcs = myGlobe.arcsData();
                const updatedArcs = [...currentArcs, newArc].slice(-15);
                myGlobe.arcsData(updatedArcs);
            }
            
            // Refresh stats & alerts table
            fetchData();
        } catch (e) {
            console.error("Error handling live socket message:", e);
        }
    };
    
    socket.onclose = () => {
        console.log("[AegisGuard] WebSocket disconnected. Retrying connection in 5s...");
        setTimeout(initWebSocket, 5000);
    };
}

// Scramble text decryption animation
function scrambleText(element, finalText, duration = 300) {
    const chars = "!@#$%^&*()_+~`|}{[]:;?><,./-=";
    const start = Date.now();
    
    function update() {
        const timePassed = Date.now() - start;
        const progress = Math.min(timePassed / duration, 1);
        
        let currentText = "";
        for (let i = 0; i < finalText.length; i++) {
            if (finalText[i] === " " || progress > (i / finalText.length)) {
                currentText += finalText[i];
            } else {
                currentText += chars[Math.floor(Math.random() * chars.length)];
            }
        }
        
        element.innerText = currentText;
        
        if (progress < 1) {
            requestAnimationFrame(update);
        } else {
            element.innerText = finalText;
        }
    }
    
    update();
}

function decryptField(elementId, finalText) {
    const element = document.getElementById(elementId);
    if (!element) return;
    scrambleText(element, String(finalText), 250);
}
