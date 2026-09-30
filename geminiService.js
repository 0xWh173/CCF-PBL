const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');

// Auto-load .env file if available
try {
    const envPath = path.join(__dirname, '.env');
    if (fs.existsSync(envPath)) {
        const envContent = fs.readFileSync(envPath, 'utf8');
        envContent.split('\n').forEach(line => {
            const match = line.match(/^\s*([\w.-]+)\s*=\s*(.*)?\s*$/);
            if (match) {
                const key = match[1];
                let value = match[2] || '';
                if (value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
                if (!process.env[key]) process.env[key] = value.trim();
            }
        });
    }
} catch (e) {
    // Ignore env loading errors
}

// Helper: Get active API key from environment variable
function getApiKey() {
    return process.env.GEMINI_API_KEY;
}

// Candidate models in order of priority (prioritizing instant-capacity lite models)
const MODELS = [
    'gemini-3.1-flash-lite',
    'gemini-3.5-flash-lite',
    'gemini-3-flash-preview',
    'gemini-flash-latest',
    'gemini-3.8-flash',
    'gemini-3.7-flash',
    'gemini-3.6-flash'
];

/**
 * Make HTTPS POST request to Gemini API
 */
function makeGeminiRequest(model, payload) {
    return new Promise((resolve, reject) => {
        const apiKey = getApiKey();
        if (!apiKey) {
            return reject(new Error("GEMINI_API_KEY environment variable is missing"));
        }
        const dataString = JSON.stringify(payload);
        const options = {
            hostname: 'generativelanguage.googleapis.com',
            path: `/v1beta/models/${model}:generateContent?key=${apiKey}`,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(dataString)
            },
            timeout: 45000
        };

        const req = https.request(options, (res) => {
            let body = '';
            res.on('data', (chunk) => body += chunk);
            res.on('end', () => {
                if (res.statusCode >= 200 && res.statusCode < 300) {
                    try {
                        const parsed = JSON.parse(body);
                        resolve(parsed);
                    } catch (e) {
                        reject(new Error(`Failed to parse response: ${e.message}`));
                    }
                } else {
                    reject(new Error(`Gemini API HTTP ${res.statusCode}: ${body}`));
                }
            });
        });

        req.on('error', (err) => reject(err));
        req.on('timeout', () => {
            req.destroy();
            reject(new Error('Gemini API request timed out'));
        });

        req.write(dataString);
        req.end();
    });
}

/**
 * Format raw markdown text from Gemini into HTML tags for the dashboard UI bubble
 */
function formatMarkdownToHtml(text) {
    if (!text) return "";
    let html = text;

    // Code blocks ``` ... ```
    html = html.replace(/```([\s\S]*?)```/g, (match, p1) => {
        return `<pre style="background: rgba(0,0,0,0.4); padding: 8px; border-radius: 4px; border: 1px solid rgba(255,255,255,0.1); font-family: monospace; overflow-x: auto; font-size: 0.8rem; margin: 6px 0;"><code>${p1.trim()}</code></pre>`;
    });

    // Inline code `code`
    html = html.replace(/`([^`]+)`/g, '<code>$1</code>');

    // Bold **text**
    html = html.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');

    // Italic *text* or _text_
    html = html.replace(/\*([^*]+)\*/g, '<em>$1</em>');
    html = html.replace(/_([^_]+)_/g, '<em>$1</em>');

    // Bullet points (- or *)
    html = html.replace(/^\s*[\-\*]\s+(.+)$/gm, '• $1<br>');

    // Line breaks (if not already handled)
    html = html.replace(/\n/g, '<br>');

    return html;
}

/**
 * Generate AI SOC Copilot analysis using Gemini API
 */
async function generateSocAnalysis(userQuery, socState) {
    const systemInstruction = `You are Aegis AI Autopilot, an advanced, highly specialized AI Security Operations Center (SOC) copilot embedded in the Aegis Dashboard.

CURRENT LIVE SOC TELEMETRY & SYSTEM STATE:
- Global Threat Index: ${socState.threatLevel}% (Range: 0-100%)
- Live Ingress Traffic: ${socState.ingressRate.toFixed(2)} GB/s
- System Mitigation Rate: ${socState.mitigationRate.toFixed(1)}%
- Active Unresolved Security Incidents (${socState.activeAlerts.length}):
${JSON.stringify(socState.activeAlerts, null, 2)}
- Managed Infrastructure Nodes (${socState.networkNodes.length}):
${JSON.stringify(socState.networkNodes, null, 2)}
- Recent Audit Trail Log Snippet:
${JSON.stringify(socState.auditTrail.slice(0, 5), null, 2)}

OPERATIONAL GUIDELINES:
1. Answer the operator's security query directly, authoritatively, and professionally based on live telemetry.
2. If the user asks about specific nodes, IP addresses, or active alerts, extract precise metrics, risk scores, and recommended actions from the live telemetry.
3. Be concise and structured. Use HTML tags (e.g. <strong>, <code>, <em>, <br>) or standard markdown formatting.
4. Highlight critical threat vectors, IP addresses to block, firewall rules to deploy, or host isolation actions when necessary.`;

    const payload = {
        contents: [
            {
                role: 'user',
                parts: [{ text: `${systemInstruction}\n\nOPERATOR QUERY: ${userQuery}` }]
            }
        ],
        generationConfig: {
            temperature: 0.4,
            maxOutputTokens: 800
        }
    };

    let lastError = null;
    for (const model of MODELS) {
        try {
            console.log(`[Gemini AI] Requesting analysis using model ${model}...`);
            const responseData = await makeGeminiRequest(model, payload);
            
            const candidate = responseData.candidates?.[0];
            const textPart = candidate?.content?.parts?.[0]?.text;

            if (textPart) {
                console.log(`[Gemini AI] Successfully generated response from ${model}`);
                const formattedHtml = formatMarkdownToHtml(textPart);
                return {
                    success: true,
                    model: model,
                    answer: formattedHtml
                };
            }
        } catch (err) {
            console.warn(`[Gemini AI] Model ${model} failed: ${err.message}`);
            lastError = err;
        }
    }

    // Return failure if all models failed
    return {
        success: false,
        error: lastError ? lastError.message : "All Gemini API models failed"
    };
}

module.exports = {
    generateSocAnalysis,
    getApiKey
};
