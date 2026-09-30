const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const EventEmitter = require('events');
const geminiService = require('./geminiService');

let express, WebSocket;
try {
    express = require('express');
    WebSocket = require('ws');
} catch (e) {
    // Zero-dependency fallback shims
    express = function() {
        const routes = { GET: [], POST: [] };
        let staticDir = null;

        const app = function(req, res) {
            res.json = function(data) {
                res.setHeader('Content-Type', 'application/json');
                res.end(JSON.stringify(data));
            };
            res.status = function(code) {
                res.statusCode = code;
                return res;
            };

            let bodyData = '';
            req.on('data', chunk => bodyData += chunk);
            req.on('end', () => {
                try {
                    req.body = bodyData ? JSON.parse(bodyData) : {};
                } catch (err) {
                    req.body = {};
                }

                const urlPath = req.url.split('?')[0];
                const routeList = routes[req.method] || [];
                const matched = routeList.find(r => r.path === urlPath);
                if (matched) {
                    return matched.handler(req, res);
                }

                if (req.method === 'GET' && staticDir) {
                    let relativePath = urlPath === '/' ? '/index.html' : urlPath;
                    let safePath = path.normalize(relativePath).replace(/^(\.\.[\/\\])+/, '');
                    let filePath = path.join(staticDir, safePath);

                    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
                        const ext = path.extname(filePath).toLowerCase();
                        const mimeTypes = {
                            '.html': 'text/html',
                            '.css': 'text/css',
                            '.js': 'application/javascript',
                            '.json': 'application/json',
                            '.png': 'image/png',
                            '.jpg': 'image/jpeg',
                            '.svg': 'image/svg+xml'
                        };
                        res.setHeader('Content-Type', mimeTypes[ext] || 'application/octet-stream');
                        return fs.createReadStream(filePath).pipe(res);
                    }
                }

                res.statusCode = 404;
                res.end('404 Not Found');
            });
        };

        app.use = function(middleware) {
            if (typeof middleware === 'function' && middleware.staticDir) {
                staticDir = middleware.staticDir;
            }
        };
        app.post = function(path, handler) { routes.POST.push({ path, handler }); };
        app.get = function(path, handler) { routes.GET.push({ path, handler }); };

        return app;
    };
    express.json = function() { return function() {}; };
    express.static = function(dir) {
        const fn = function() {};
        fn.staticDir = dir;
        return fn;
    };

    class MiniWSClient extends EventEmitter {
        constructor(socket) {
            super();
            this.socket = socket;
            this.readyState = 1;
            socket.on('close', () => { this.readyState = 3; this.emit('close'); });
            socket.on('error', () => { this.readyState = 3; this.emit('close'); });
        }
        send(data) {
            if (this.readyState !== 1) return;
            const payload = Buffer.from(data);
            const len = payload.length;
            let header;
            if (len <= 125) {
                header = Buffer.from([0x81, len]);
            } else if (len <= 65535) {
                header = Buffer.alloc(4);
                header[0] = 0x81; header[1] = 126; header.writeUInt16BE(len, 2);
            } else {
                header = Buffer.alloc(10);
                header[0] = 0x81; header[1] = 127; header.writeBigUInt64BE(BigInt(len), 2);
            }
            try { this.socket.write(Buffer.concat([header, payload])); } catch (e) { this.readyState = 3; }
        }
    }

    class MiniWSServer extends EventEmitter {
        constructor() {
            super();
            this.clients = new Set();
        }
        handleUpgrade(request, socket, head, callback) {
            const key = request.headers['sec-websocket-key'];
            if (!key) { socket.destroy(); return; }
            const acceptKey = crypto.createHash('sha1')
                .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
                .digest('base64');
            const headers = [
                'HTTP/1.1 101 Switching Protocols',
                'Upgrade: websocket',
                'Connection: Upgrade',
                `Sec-WebSocket-Accept: ${acceptKey}`,
                '\r\n'
            ];
            socket.write(headers.join('\r\n'));
            const client = new MiniWSClient(socket);
            this.clients.add(client);
            client.on('close', () => this.clients.delete(client));
            callback(client);
        }
    }

    WebSocket = { OPEN: 1, Server: MiniWSServer };
}

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ noServer: true });

const PORT = process.env.PORT || 8080;
const LOG_FILE = path.join(__dirname, 'soc_audit_trail.log');

// Express Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Global State - Initialized cleanly with baseline telemetry (No mock data)
let socState = {
    threatLevel: 10.0,
    ingressRate: 1.50,
    mitigationRate: 100.0,
    activeAlerts: [],
    auditTrail: [],
    networkNodes: [
        { name: "DB-PROD-01", ip: "10.142.45.189", risk: 10, status: "safe", metrics: "CPU: 15% | Operational Safe", rawCpu: 15 },
        { name: "WEB-CLUSTER-01", ip: "10.142.45.101", risk: 10, status: "safe", metrics: "CPU: 18% | Normal", rawCpu: 18 },
        { name: "AUTH-SERVICE", ip: "10.142.45.12", risk: 10, status: "safe", metrics: "CPU: 12% | Normal", rawCpu: 12 },
        { name: "API-GATEWAY", ip: "10.142.0.10", risk: 10, status: "safe", metrics: "CPU: 16% | Ingress Normal", rawCpu: 16 },
        { name: "DEV-STAGE-01", ip: "10.142.45.92", risk: 10, status: "safe", metrics: "CPU: 10% | Normal", rawCpu: 10 },
        { name: "VM-PAYMENTS-03", ip: "10.142.90.4", risk: 10, status: "safe", metrics: "CPU: 14% | Operational Safe", rawCpu: 14 }
    ],
    autopilotBannerActive: false
};

// Helper: Append entries to local physical log file & stream live over WebSocket
function broadcastLog(logObj) {
    const data = JSON.stringify({ type: "LOG_STREAM", log: logObj });
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(data);
        }
    });
}

function logAuditEvent(target, desc, source, actions, status) {
    const timestamp = new Date().toISOString();
    const logObj = { timestamp, target, desc, source, actions, status };

    fs.appendFile(LOG_FILE, JSON.stringify(logObj) + '\n', (err) => {
        if (err) console.error("Error writing to audit log:", err);
    });

    broadcastLog(logObj);
}

// Log initial startup event
logAuditEvent("SYSTEM", "Aegis SOC Core Autopilot Initialized", "SYSTEM", "Port binding successful", "ONLINE");

// Helper: Broadcast current state to all WebSocket clients
function broadcastState() {
    const data = JSON.stringify({ type: "STATE_UPDATE", state: socState });
    wss.clients.forEach(client => {
        if (client.readyState === WebSocket.OPEN) {
            client.send(data);
        }
    });
}

// REST APIs
// 1. Mitigate alert
app.post('/api/mitigate', (req, res) => {
    const { alertId } = req.body;
    const alertIndex = socState.activeAlerts.findIndex(a => a.id === alertId);

    if (alertIndex !== -1) {
        const alert = socState.activeAlerts[alertIndex];

        const mitId = `MIT-${Math.floor(Math.random() * 900) + 100}`;
        const actions = `Secured target ${alert.target} & blocked source IP ${alert.sourceIp}`;

        socState.auditTrail.unshift({
            id: mitId,
            target: alert.target,
            desc: alert.title,
            source: "Operator Action",
            actions: actions,
            status: "Mitigated"
        });

        // Restore target node status & metrics
        const node = socState.networkNodes.find(n => n.name === alert.target);
        if (node && node.status !== "isolated") {
            node.risk = Math.max(10, node.risk - 45);
            node.rawCpu = Math.floor(Math.random() * 10) + 15;
            node.metrics = `CPU: ${node.rawCpu}% | Operational Safe`;
        }

        // Multi-phase mitigation terminal stream logs
        logAuditEvent(alert.target, `FIREWALL RULE ACTIVATED: WAF Rule 409 deployed`, "Operator Action", `Blocked IP ${alert.sourceIp}`, "Mitigated");
        setTimeout(() => {
            logAuditEvent(alert.target, `NULL ROUTE EXECUTION: Attacker IP ${alert.sourceIp} dropped at perimeter`, "Gateway Firewall", "Null-route active", "Mitigated");
        }, 150);
        setTimeout(() => {
            logAuditEvent(alert.target, `HOST RESTORED: Node ${alert.target} load normalized to 18% CPU`, "Node Monitor", "Operational baseline restored", "ONLINE");
        }, 300);

        // Remove alert
        socState.activeAlerts.splice(alertIndex, 1);

        // Adjust metrics
        socState.threatLevel = Math.max(12.4, parseFloat((socState.threatLevel - 7.5).toFixed(1)));

        broadcastState();
        res.json({ success: true, state: socState });
    } else {
        res.status(404).json({ success: false, error: "Alert not found" });
    }
});

// 2. Isolate network node
app.post('/api/isolate', (req, res) => {
    const { nodeName } = req.body;
    const node = socState.networkNodes.find(n => n.name === nodeName);

    if (node) {
        node.status = "isolated";
        node.metrics = "OFFLINE - ISOLATED BY OPERATOR";
        node.rawCpu = 0;
        node.risk = 0;

        const actions = `Isolated host subnet gateway IP ${node.ip}`;
        socState.auditTrail.unshift({
            id: `MIT-${Math.floor(Math.random() * 900) + 100}`,
            target: node.name,
            desc: "Operator Isolation Triggered",
            source: "Operator Admin",
            actions: actions,
            status: "Mitigated"
        });

        logAuditEvent(node.name, `SUBNET ISOLATION: Host Gateway Interface ${node.ip} disabled`, "Operator Admin", actions, "Mitigated");
        setTimeout(() => {
            logAuditEvent(node.name, `CONTAINMENT ACTIVE: Node ${node.name} disconnected from gateway routing`, "Cluster Firewall", "Host Offline", "Mitigated");
        }, 150);

        broadcastState();
        res.json({ success: true, state: socState });
    } else {
        res.status(404).json({ success: false, error: "Node not found" });
    }
});

// 3. Reconnect network node
app.post('/api/reconnect', (req, res) => {
    const { nodeName } = req.body;
    const node = socState.networkNodes.find(n => n.name === nodeName);

    if (node) {
        node.status = "safe";
        node.risk = 10;
        node.rawCpu = 18;
        node.metrics = "CPU: 18% | Reconnected. Normal.";

        const actions = `Restored gateway interface to IP ${node.ip}`;
        socState.auditTrail.unshift({
            id: `MIT-${Math.floor(Math.random() * 900) + 100}`,
            target: node.name,
            desc: "Subnet Connection Re-established",
            source: "Operator Admin",
            actions: actions,
            status: "Mitigated"
        });

        logAuditEvent(node.name, `INTERFACE RESTORED: Host Subnet Gateway IP ${node.ip} re-enabled`, "Operator Admin", actions, "ONLINE");

        broadcastState();
        res.json({ success: true, state: socState });
    } else {
        res.status(404).json({ success: false, error: "Node not found" });
    }
});

// 4. Autopilot playbook trigger
app.post('/api/autopilot', (req, res) => {
    if (!socState.autopilotBannerActive) {
        return res.status(400).json({ success: false, error: "Autopilot playbook already executed" });
    }

    const prodNode = socState.networkNodes.find(n => n.name === 'DB-PROD-01');
    if (prodNode) {
        prodNode.status = "isolated";
        prodNode.rawCpu = 0;
        prodNode.risk = 0;
        prodNode.metrics = "OFFLINE - ISOLATED BY AUTOPILOT";
    }

    const actions = "Isolated database host subnet due to credential dump attempt";
    socState.auditTrail.unshift({
        id: `MIT-AUT-04`,
        target: "DB-PROD-01",
        desc: "AI Autopilot: Suspicious Host Isolation",
        source: "AI Autopilot",
        actions: actions,
        status: "Mitigated"
    });

    logAuditEvent("DB-PROD-01", "AI AUTOPILOT EXECUTION: Suspicious Host Isolation Triggered", "AI Autopilot", actions, "Mitigated");

    socState.threatLevel = 18.5;
    socState.autopilotBannerActive = false;

    broadcastState();
    res.json({ success: true, state: socState });
});

// 5. Copilot Chat Endpoint (Dynamic Real-Time SOC Intelligence)
app.post('/api/chat', (req, res) => {
    const { query } = req.body;
    if (!query) return res.status(400).json({ error: "Missing query" });

    let lowercaseQuery = query.toLowerCase();
    let aiAnswer = "";

    // Search for matched node in query
    const matchedNode = socState.networkNodes.find(n => lowercaseQuery.includes(n.name.toLowerCase()) || lowercaseQuery.includes(n.name.replace('-', '').toLowerCase()));

    if (matchedNode) {
        const activeNodeAlerts = socState.activeAlerts.filter(a => a.target === matchedNode.name);
        const isIsolated = matchedNode.status === 'isolated';

        aiAnswer = `
            <strong>Node ${matchedNode.name} (${matchedNode.ip}) Real-Time Intelligence:</strong><br>
            - Host Operational Status: <code>${matchedNode.status.toUpperCase()}</code><br>
            - Current CPU Workload: <strong>${matchedNode.rawCpu}%</strong> capacity<br>
            - Calculated Risk Score: <strong>${matchedNode.risk}%</strong><br>
            - Active Incidents Targeting Host: <strong>${activeNodeAlerts.length}</strong><br>
            ${activeNodeAlerts.length > 0 ? `
                <div style="margin-top: 4px; padding: 6px; background: rgba(255,59,48,0.1); border-left: 3px solid #ff3b30; border-radius: 4px;">
                    <strong>Active Threat Vector:</strong> ${activeNodeAlerts[0].title}<br>
                    <strong>Attacker Source IP:</strong> <code>${activeNodeAlerts[0].sourceIp}</code> | Severity: <code>${activeNodeAlerts[0].score}</code><br>
                    <strong>Recommended Action:</strong> Click <em>Mitigate</em> on incident ID <code>${activeNodeAlerts[0].id}</code> or run:<br>
                    <code>iptables -A INPUT -s ${activeNodeAlerts[0].sourceIp} -j DROP</code>
                </div>
            ` : `
                <span style="color: #30d158;"><i class="fa-solid fa-circle-check"></i> No active threat vectors currently targeting this host subnet.</span>
            `}
        `;
    } else if (lowercaseQuery.includes("summarize") || lowercaseQuery.includes("threat") || lowercaseQuery.includes("attack") || lowercaseQuery.includes("status")) {
        const criticalCount = socState.activeAlerts.filter(a => a.severity === 'critical').length;
        aiAnswer = `
            <strong>Active SOC Threat Landscape Summary:</strong><br>
            - Global Threat Index: <strong style="color:${socState.threatLevel > 40 ? '#ff3b30' : '#30d158'}">${socState.threatLevel}%</strong><br>
            - Unresolved Incidents in Queue: <strong>${socState.activeAlerts.length}</strong> (${criticalCount} Critical)<br>
            - Active Network Ingress Flow: <strong>${socState.ingressRate.toFixed(2)} GB/s</strong><br>
            - Top Target Subnet: <code>${socState.activeAlerts.length > 0 ? socState.activeAlerts[0].target : 'DB-PROD-01'}</code><br>
            - Mitigation Recommendation: Deploy WAF filtering rules or execute manual host isolation on high-risk nodes.
        `;
    } else if (lowercaseQuery.includes("firewall") || lowercaseQuery.includes("recommendation") || lowercaseQuery.includes("rule") || lowercaseQuery.includes("guidelines")) {
        aiAnswer = `
            <strong>AEGIS Tactical Firewall Policy Guidelines:</strong><br>
            1. <strong>WAF Payload Rule 409:</strong> Filter incoming URI parameters matching regex: <code>/\\s*OR\\s+1\\s*=\\s*1/i</code>.<br>
            2. <strong>Perimeter Rate Limiting:</strong> Drop incoming UDP reflection flows exceeding 100,000 req/sec on port 1900/123.<br>
            3. <strong>SSH Containment:</strong> Enforce SSH Key Authentication only and drop root auth attempts after 5 failures via <code>fail2ban-client set sshd banip &lt;IP&gt;</code>.
        `;
    } else if (lowercaseQuery.includes("ip") || lowercaseQuery.includes("block")) {
        aiAnswer = `
            <strong>Attacker IP Blocklist Protocol:</strong><br>
            Attacking source IPs can be blocklisted at the perimeter router by clicking <strong>Mitigate</strong> on any active incident card. You can also run CLI command:<br>
            <code>route add -host &lt;Attacker_IP&gt; reject</code>
        `;
    } else {
        aiAnswer = `
            Aegis AI Security Engine evaluated prompt <strong>"${query}"</strong>.<br>
            Current System Telemetry: <strong>${socState.activeAlerts.length}</strong> active threat vectors detected. Global Threat Index is at <strong>${socState.threatLevel}%</strong>. Select a host card or active incident to trigger automated mitigations.
        `;
    }

    res.json({ answer: aiAnswer });
});

// 6. Manual Attack Simulation Endpoint
app.post('/api/simulate-attack', (req, res) => {
    const { title, severity, score, targetNode, sourceIp, payload, recommendation } = req.body;

    let target = targetNode;
    if (!target) {
        const activeNodes = socState.networkNodes.filter(n => n.status !== 'isolated');
        target = activeNodes.length > 0 ? activeNodes[Math.floor(Math.random() * activeNodes.length)].name : 'DB-PROD-01';
    }

    const selectedNode = socState.networkNodes.find(n => n.name === target);

    const randomIp = sourceIp || `${Math.floor(Math.random() * 190) + 10}.${Math.floor(Math.random() * 200)}.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}`;
    const randomIncId = `INC-SIM-${Math.floor(Math.random() * 8000) + 1000}`;

    const newAlert = {
        id: randomIncId,
        title: title || "Simulated Security Incident",
        severity: severity || "high",
        score: (score || 8.5).toString(),
        sourceIp: randomIp,
        target: target,
        time: "Just Now",
        payload: payload || `MANUAL SIMULATION INJECTION\nTarget Endpoint: ${selectedNode ? selectedNode.ip : '10.142.0.1'}\nPayload signature matched attack vector database.`,
        recommendation: recommendation || "Simulated attack in progress. Execute target subnet isolation or deploy WAF rules immediately."
    };

    socState.activeAlerts.unshift(newAlert);

    const attackScore = parseFloat(newAlert.score);
    socState.threatLevel = Math.min(100.0, parseFloat((socState.threatLevel + attackScore / 2).toFixed(1)));

    if (selectedNode && selectedNode.status !== 'isolated') {
        selectedNode.risk = Math.min(99, selectedNode.risk + 35);
        selectedNode.rawCpu = Math.min(99, selectedNode.rawCpu + 45);
        selectedNode.metrics = `CPU: ${selectedNode.rawCpu}% | HIGH LOAD - UNDER ATTACK`;
    }

    // Multi-phase attack simulation logging over WebSockets
    logAuditEvent(target, `PACKET INGRESS: TCP ${randomIp}:49152 -> ${selectedNode ? selectedNode.ip : '10.142.0.1'}:80 (SYN)`, "Perimeter Gateway API-RT-01", "Packet Inspection Active", "Telemetry Stream");

    setTimeout(() => {
        logAuditEvent(target, `SECURITY THREAT MATCH: ${newAlert.title}`, "Signature Detection Engine", `Source IP: ${randomIp}`, "Active Threat");
    }, 150);

    setTimeout(() => {
        logAuditEvent(target, `HOST LOAD ALERT: Target ${target} CPU load spiked to ${selectedNode ? selectedNode.rawCpu : 98}%`, "Node Monitor", "Subnet threshold exceeded", "Active Threat");
    }, 300);

    setTimeout(() => {
        logAuditEvent(target, `AUTOPILOT ADVISORY: ${newAlert.recommendation}`, "AI Autopilot", "Action ready for deployment", "Advisory");
    }, 450);

    broadcastState();
    res.json({ success: true, alert: newAlert, state: socState });
});

// 7. Reset SOC System State Endpoint
app.post('/api/reset', (req, res) => {
    socState.activeAlerts = [];
    socState.threatLevel = 12.4;
    socState.ingressRate = 3.25;
    socState.mitigationRate = 98.5;
    socState.autopilotBannerActive = true;

    socState.networkNodes.forEach(node => {
        node.status = "safe";
        node.risk = Math.floor(Math.random() * 15) + 10;
        node.rawCpu = Math.floor(Math.random() * 20) + 15;
        node.metrics = `CPU: ${node.rawCpu}% | Normal Operational State`;
    });

    logAuditEvent("SYSTEM", "SOC Dashboard State Reset Executed", "Operator Admin", "Cleared active incidents & restored nodes", "ONLINE");

    broadcastState();
    res.json({ success: true, state: socState });
});

// Dynamic Threat Simulation Speed Config (Paused by default so threats occur ONLY via Attack Simulator)
let simulationMode = "paused"; // "fast", "normal", "paused"
let threatTimer = null;

function getIntervalForMode(mode) {
    if (mode === "fast") return 5000;
    if (mode === "paused") return 99999999;
    return 12000; // normal
}

// Threat generator templates
const threatTemplates = [
    {
        title: "DDoS Reflection Flood",
        severity: "high",
        score: "8.1",
        payload: "UDP reflection flow targeting port 80. Protocol: NTP reflection. Bandwidth threshold: 820MB/s.",
        recommendation: "Enable edge router rate filtering for UDP port 123. Enable firewall null-route actions."
    },
    {
        title: "Suspicious Host Scan (Port Scan)",
        severity: "medium",
        score: "6.0",
        payload: "TCP SYN port scan. Port range scanned: 1-1024. Pattern: horizontal sweep search from external node.",
        recommendation: "Rate limit connection attempts per IP. Block source scan host at perimeter router."
    },
    {
        title: "Malicious File Upload (Webshell)",
        severity: "critical",
        score: "9.5",
        payload: "POST /uploads/profile.php HTTP/1.1\nContent-Type: multipart/form-data\n\n<?php system($_GET['cmd']); ?>",
        recommendation: "Immediate web container isolation. Terminate active container. Delete uploaded profile.php and audit folder access."
    },
    {
        title: "Anomalous DNS Tunneling Activity",
        severity: "high",
        score: "7.6",
        payload: "DNS lookup queries: sub.long-exfil-hash-domain.com TXT records. Length limit: 255 chars, count: 489/sec.",
        recommendation: "Block domain queries on DNS level. Isolate outbound DNS lookup nodes and examine system process lists."
    }
];

function spawnBackgroundThreat() {
    if (simulationMode === "paused") return;
    if (socState.activeAlerts.length >= 10) return;

    const activeTargetNodes = socState.networkNodes.filter(n => n.status !== 'isolated');
    if (activeTargetNodes.length === 0) return;

    const selectedTarget = activeTargetNodes[Math.floor(Math.random() * activeTargetNodes.length)];
    const template = threatTemplates[Math.floor(Math.random() * threatTemplates.length)];

    const randomIp = `${Math.floor(Math.random() * 190) + 10}.${Math.floor(Math.random() * 200)}.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}`;
    const randomIncId = `INC-${Math.floor(Math.random() * 8000) + 1000}`;

    const newAlert = {
        id: randomIncId,
        title: template.title,
        severity: template.severity,
        score: template.score,
        sourceIp: randomIp,
        target: selectedTarget.name,
        time: "Just Now",
        payload: `Target Endpoint: ${selectedTarget.ip}\nTelemetry logs:\n${template.payload}`,
        recommendation: template.recommendation
    };

    socState.activeAlerts.unshift(newAlert);
    socState.threatLevel = Math.min(100.0, parseFloat((socState.threatLevel + parseFloat(template.score) / 2).toFixed(1)));

    logAuditEvent(selectedTarget.name, `Threat Detected: ${template.title}`, "Threat Intelligence Engine", `Source IP: ${randomIp}`, "Active Threat");

    selectedTarget.risk = Math.min(98, selectedTarget.risk + 15);

    broadcastState();
}

function resetThreatTimer() {
    if (threatTimer) clearInterval(threatTimer);
    if (simulationMode !== "paused") {
        threatTimer = setInterval(spawnBackgroundThreat, getIntervalForMode(simulationMode));
    }
}

app.post('/api/simulation-config', (req, res) => {
    const { mode } = req.body;
    if (['fast', 'normal', 'paused'].includes(mode)) {
        simulationMode = mode;
        resetThreatTimer();
        logAuditEvent("SYSTEM", `Simulation Mode updated to: ${mode.toUpperCase()}`, "Operator Admin", `Interval set to ${mode}`, "CONFIG_CHANGED");
        return res.json({ success: true, mode: simulationMode });
    }
    res.status(400).json({ success: false, error: "Invalid mode" });
});

// Periodic Telemetry updates simulator (Reflects REAL node status & load)
setInterval(() => {
    socState.networkNodes.forEach(node => {
        if (node.status !== "isolated") {
            const nodeAlerts = socState.activeAlerts.filter(a => a.target === node.name);
            if (nodeAlerts.length > 0) {
                // Node is under active attack
                node.rawCpu = Math.min(99, Math.max(75, node.rawCpu + (Math.floor(Math.random() * 5) - 2)));
                node.risk = Math.min(99, Math.max(60, node.risk));
                node.metrics = `CPU: ${node.rawCpu}% | UNDER ATTACK (${nodeAlerts[0].title})`;
            } else {
                // Node is operating normally
                node.rawCpu = Math.min(30, Math.max(8, node.rawCpu + (Math.floor(Math.random() * 3) - 1)));
                node.risk = Math.max(5, Math.min(15, node.risk - 2));
                node.metrics = `CPU: ${node.rawCpu}% | Operational Safe`;
            }
        }
    });

    const flowFluctuation = (Math.random() * 0.1) - 0.05;
    socState.ingressRate = Math.min(10.0, Math.max(1.0, socState.ingressRate + flowFluctuation));

    broadcastState();
}, 1000);

// Start background threat generator (Paused by default)
resetThreatTimer();

// WebSocket Setup
server.on('upgrade', (request, socket, head) => {
    wss.handleUpgrade(request, socket, head, (ws) => {
        wss.emit('connection', ws, request);
    });
});

wss.on('connection', (ws) => {
    console.log("Client connected to SOC WebSocket gateway");

    // Send initial complete state upon connecting
    ws.send(JSON.stringify({
        type: "INITIAL_STATE",
        state: socState
    }));

    ws.on('close', () => {
        console.log("Client disconnected from WebSocket gateway");
    });
});

// Start Server
server.listen(PORT, () => {
    console.log(`AEGIS SOC Core running on port ${PORT}`);
    console.log(`Audit log: ${LOG_FILE}`);
});
