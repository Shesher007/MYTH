/**
 * ⌬ MYTH Sovereign Sentinel Hub (v3.1)
 * --------------------------------------------------
 * INDUSTRIAL SENTINEL INFRASTRUCTURE:
 * - JSON-Structured Registry (Rich Metadata)
 * - Sentinel Rate Limiter (IP Brute-Force Shield)
 * - Geo-Spatial Intelligence (CF-Edge Analytics)
 * - Administrative Audit Engine (Chronological Traceability)
 * - Tactical Search Console (Real-time Filtering)
 * - Security Monitor (Live Violation Tracking)
 * - Glassmorphic Industrial HUD
 */

const APP_NAME = "MYTH";
const VERSION = "1.1.6";
const LICENSING_TIER = "Pro-Elite";
const EXPIRATION = "perpetual";

// Configuration
const RATE_LIMIT_THRESHOLD = 10; // Max 10 attempts per minute per IP
const RATE_LIMIT_TTL = 60 * 60 * 24; // 24-hour ban for offenders

export default {
    async fetch(request, env) {
        if (request.method === "OPTIONS") {
            return new Response(null, { headers: getCorsHeaders() });
        }

        try {
            validateEnvironment(env);
            const url = new URL(request.url);
            const clientIP = request.headers.get('cf-connecting-ip') || '0.0.0.0';

            // --- ADMIN ZONE (SOVEREIGN HUD) ---
            if (url.pathname.startsWith('/admin')) {
                const token = url.searchParams.get('token') || request.headers.get('Authorization')?.split(' ')[1];
                if (!timingSafeEqual(token, env.MASTER_ADMIN_TOKEN)) {
                    await logAudit(env, 'UNAUTHORIZED_ADMIN_ATTEMPT', { ip: clientIP }, 'CRITICAL');
                    return respondError('⌬ UNAUTHORIZED_ACCESS_DETECTED', 403);
                }

                // Enforce POST for state-changing actions (CSRF Mitigation)
                if (url.pathname === '/admin/revoke') {
                    if (request.method !== 'POST') return respondError('⌬ METHOD_NOT_ALLOWED: POST_REQUIRED', 405);
                    return handleRevoke(url, env, clientIP);
                }
                if (url.pathname === '/admin/generate') {
                    if (request.method !== 'POST') return respondError('⌬ METHOD_NOT_ALLOWED: POST_REQUIRED', 405);
                    return handleGenerate(url, env, clientIP);
                }
                
                if (url.pathname === '/admin/audit') return handleAuditView(env);
                
                const response = await handleDashboard(request, env, token);
                // Inject Cache-Control for administrative privacy
                response.headers.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
                return response;
            }

            // --- ACTIVATION API ---
            if (request.method === 'POST' && url.pathname === '/activate') {
                // Sentinel Protection
                if (await isRateLimited(env, clientIP)) {
                    await logAudit(env, 'RATE_LIMIT_BLOCK', { ip: clientIP });
                    return respondError('⌬ RATE_LIMIT_EXCEEDED: IP_RESTRICTED', 429);
                }
                return handleActivation(request, env, clientIP);
            }

            return new Response(`⌬ ${APP_NAME} Sovereign Node Operational (${VERSION})`, { 
                status: 200, 
                headers: { ...getCorsHeaders(), 'Content-Type': 'text/plain' } 
            });

        } catch (err) {
            const errorMsg = err instanceof Error ? err.stack || err.message : String(err);
            console.error(`🚨 Fatal Node Error: ${errorMsg}`);
            return respondError(errorMsg, err.status || 500);
        }
    }
};

// --- [CORE LOGIC: SENTINEL ENGINE] ---

async function isRateLimited(env, ip) {
    const key = `RL:${ip}`;
    const current = await env.MYTH_LICENSES.get(key);
    const count = current ? parseInt(current) : 0;

    if (count >= RATE_LIMIT_THRESHOLD) return true;

    const nextCount = count + 1;
    const ttl = nextCount >= RATE_LIMIT_THRESHOLD ? RATE_LIMIT_TTL : 60;

    await env.MYTH_LICENSES.put(key, nextCount.toString(), { expirationTtl: ttl });
    return false;
}

async function logAudit(env, action, details, severity = 'INFO') {
    const timestamp = new Date().toISOString();
    const id = `AUDIT:${Date.now()}`;
    await env.MYTH_LICENSES.put(id, JSON.stringify({ 
        action, 
        timestamp, 
        severity,
        ...details 
    }), { expirationTtl: 60 * 60 * 24 * 7 }); // 7-day retention
}

// --- [CORE LOGIC: ADMIN HUD v3.1] ---

async function handleDashboard(request, env, token) {
    const listStartTime = Date.now();
    try {
        await env.MYTH_LICENSES.list();
    } catch {
        return respondError('⌬ KV_READ_FAULT: Failed to list registry', 500);
    }
    const listLatency = Date.now() - listStartTime;
    
    // --- [INDUSTRIAL REGISTRY ORCHESTRATOR] ---
    const registryData = await orchestrateRegistry(env);
    const registrations = registryData.registrations || [];
    const auditLogs = registryData.auditLogs || [];
    const stats = registryData.stats || { total: 0, active: 0, unassigned: 0, geo: {}, violations: 0 };

    const threatScore = Math.min(100, Math.ceil((stats.violations / (stats.total || 1)) * 500));
    const systemStatus = threatScore > 50 ? 'CRITICAL_ALERT' : (threatScore > 10 ? 'ANOMALY_DETECTED' : 'NOMINAL');
    const statusColor = threatScore > 50 ? 'text-red-500' : (threatScore > 10 ? 'text-amber-500' : 'text-emerald-500');
    const statusPulse = threatScore > 50 ? 'bg-red-500' : (threatScore > 10 ? 'bg-amber-500' : 'bg-emerald-500');

    // High-Fidelity Integrity Engine (Stateless)
    const calculateIntegrity = (r, audits, regs) => {
        try {
            if (!r || !r.hwid || r.hwid === 'UNASSIGNED' || r.hwid === 'MALFORMED') return { score: 0, label: 'UNBOUND' };
            let score = 100;
            const keyAudits = (audits || []).filter(a => a && a.key === r.key);
            score -= (keyAudits.filter(a => a.action === 'SECURITY_VIOLATION_HWID').length * 40);
            if (r.version !== VERSION) score -= 20;
            const sharedHwid = (regs || []).filter(reg => reg && reg.hwid === r.hwid && reg.key !== r.key).length;
            if (sharedHwid > 0) score -= (sharedHwid * 25);
            score = Math.max(0, score);
            return { score, label: score >= 90 ? 'SECURE' : (score >= 60 ? 'STABLE' : (score > 0 ? 'DEGRADED' : 'COMPROMISED')) };
        } catch {
            return { score: 0, label: 'SCAN_FAULT' };
        }
    };

    const auditHtml = (auditLogs || []).slice(0, 10).map(a => {
        const actionStr = String(a.action || 'UNKNOWN').replace(/_/g, ' ');
        const severity = a.severity || 'INFO';
        const timestamp = a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : 'N/A';
        const detail = a.ip || a.key || 'ADMIN';
        const sevClass = (severity === 'CRITICAL' || actionStr.includes('VIOLATION')) ? 'text-red-500' : (severity === 'WARN' ? 'text-amber-500' : 'text-gray-400');
        return `
            <div class="text-[9px] border-b border-white/5 pb-2">
                <div class="flex justify-between items-start mb-1">
                    <span class="font-bold uppercase ${sevClass}">${actionStr}</span>
                    <span class="text-gray-600">${timestamp}</span>
                </div>
                <div class="flex justify-between items-center text-gray-400 font-mono">
                    <span class="truncate max-w-[120px]">${detail}</span>
                    <span class="text-[7px] px-1 rounded border ${severity === 'CRITICAL' ? 'border-red-500 text-red-500' : 'border-gray-500'}">${severity}</span>
                </div>
            </div>`;
    }).join('') || '<p class="text-[10px] text-gray-700 italic">No security events detected. Registry clean.</p>';

    const registrationsHtml = (registrations || []).map(r => {
        const isBound = r.hwid && r.hwid !== 'UNASSIGNED';
        const integrity = calculateIntegrity(r, auditLogs, registrations);
        
        let geoHtml = '';
        if (typeof r.geo === 'object' && r.geo !== null) {
            geoHtml = `
                <div class="flex flex-col gap-1">
                    <div class="flex items-center gap-2 text-cyan-400 font-bold uppercase tracking-widest text-[10px]">
                        <svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><path d="M20 10c0 6-8 12-8 12s-8-6-8-12a8 8 0 0 1 16 0Z"/><circle cx="12" cy="10" r="3"/></svg>
                        ${r.geo.city || 'Unknown'}, ${r.geo.country || 'Unknown'}
                    </div>
                    <div class="text-[9px] text-gray-600 uppercase font-bold text-[9px]"><span class="text-cyan-900">ISP:</span> ${r.geo.isp || 'N/A'}</div>
                    <div class="text-[8px] text-gray-700 italic">Edge Node: ${r.geo.colo || 'Unknown'}</div>
                </div>`;
        } else {
            geoHtml = `<div class="text-gray-600 uppercase font-bold">${r.geo || 'N/A'}</div><div class="text-[8px] text-gray-800 italic mt-1">Legacy Record</div>`;
        }

        return `
            <tr class="hover:bg-cyan-500/[0.02] transition-colors group">
                <td class="p-5 font-mono text-cyan-400/90 text-[13px] truncate">
                    <div class="flex items-center gap-3">
                        <span class="truncate">${r.key}</span>
                        <button onclick="copyToClipboard('${r.key}', this)" class="text-gray-600 hover:text-cyan-400 transition-colors p-1">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                        </button>
                    </div>
                </td>
                <td class="p-5 font-mono text-gray-500 text-[11px] truncate">${r.hwid || 'N/A'}</td>
                <td class="p-5 font-mono text-gray-600 text-[10px] uppercase">${r.ip || 'N/A'}</td>
                <td class="p-5 text-center"><span class="text-[9px] font-bold px-2 py-0.5 rounded border border-cyan-500/20 text-cyan-500/60 bg-cyan-500/5">${r.version || 'v1.1.0'}</span></td>
                <td class="p-5">${geoHtml}</td>
                <td class="p-5 text-center">
                    <div class="flex flex-col items-center gap-1">
                        <div class="w-12 h-1 bg-white/5 rounded-full overflow-hidden">
                            <div class="h-full bg-cyan-500 shadow-[0_0_8px_rgba(34,211,238,0.5)]" style="width: ${integrity.score}%"></div>
                        </div>
                        <span class="text-[8px] font-bold text-gray-600">${integrity.label}</span>
                    </div>
                </td>
                <td class="p-5 text-center"><span class="badge ${isBound ? 'badge-active' : 'badge-ready'}">${isBound ? 'Bound' : 'Standby'}</span></td>
                <td class="p-5 text-right">
                    ${isBound ? `<button onclick="revoke('${r.key}')" class="text-[10px] font-bold border border-red-500/20 text-red-500/40 hover:border-red-500 hover:bg-red-500 hover:text-white px-4 py-1.5 rounded-md transition-all">REVOKE</button>` : `<span class="text-[9px] text-gray-700 font-bold uppercase italic tracking-widest">Listening...</span>`}
                </td>
            </tr>`;
    }).join('');

    const html = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>${APP_NAME} Tactical Console</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
        <style>
            body { background: #070708; color: #e5e7eb; font-family: 'JetBrains Mono', monospace; overflow-x: hidden; }
            .glass { background: rgba(255, 255, 255, 0.03); backdrop-filter: blur(12px); border: 1px solid rgba(255, 255, 255, 0.08); }
            .glow-cyan { text-shadow: 0 0 15px rgba(34, 211, 238, 0.5); }
            .scanline { position: fixed; top: 0; left: 0; width: 100%; height: 2px; background: rgba(34, 211, 238, 0.05); animation: scan 8s linear infinite; pointer-events: none; }
            @keyframes scan { 0% { top: -2%; } 100% { top: 100%; } }
            .forge-input { background: rgba(0,0,0,0.3); border: 1px solid rgba(255,255,255,0.1); color: #fff; padding: 0.5rem 1rem; border-radius: 0.5rem; outline: none; transition: all 0.2s; }
            .forge-input:focus { border-color: rgba(34, 211, 238, 0.5); box-shadow: 0 0 10px rgba(34, 211, 238, 0.2); }
            .badge { padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.1em; }
            .badge-active { background: rgba(34, 211, 238, 0.1); color: #22d3ee; border: 1px solid rgba(34, 211, 238, 0.3); }
            .badge-ready { background: rgba(16, 185, 129, 0.1); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3); }
            .badge-warn { background: rgba(239, 68, 68, 0.1); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.3); }
            ::-webkit-scrollbar { display: none; }
            * { -ms-overflow-style: none; scrollbar-width: none; }
        </style>
    </head>
    <body class="p-6 md:p-12">
        <!-- Terminal Splash -->
        <div id="splash" class="fixed inset-0 z-[100] bg-[#070708] flex items-center justify-center font-mono opacity-100 transition-opacity duration-500">
            <div class="text-cyan-500 text-sm space-y-2 text-center">
                <p class="animate-pulse lowercase tracking-[0.5em]">⌬ edge_sync_active</p>
                <div class="text-[8px] opacity-40 uppercase tabular-nums border-t border-white/5 pt-2">
                    NODE: ${request.cf?.colo || 'LOCAL_EDGE'} // LATENCY: ${listLatency}ms // VIOLATION_DENSITY: ${threatScore}%
                </div>
            </div>
        </div>

        <div class="scanline"></div>
        <div class="max-w-7xl mx-auto">
            <header class="flex flex-col md:flex-row justify-between items-start md:items-center mb-12 gap-6">
                <div>
                    <h1 class="text-4xl font-extrabold tracking-tighter text-cyan-500 glow-cyan uppercase italic">⌬ ${APP_NAME} Sentinel</h1>
                    <p class="text-[10px] text-gray-500 tracking-[0.3em] font-bold mt-1">INDUSTRIAL MONITORING INFRASTRUCTURE // v${VERSION}</p>
                </div>
                <div class="flex gap-4">
                     <div class="glass px-6 py-3 rounded-lg flex items-center gap-3">
                        <div class="w-2 h-2 rounded-full ${statusPulse} ${threatScore > 50 ? 'animate-ping' : 'animate-pulse'}"></div>
                        <span class="text-xs font-bold uppercase tracking-widest ${statusColor}">GRID_STATUS: ${systemStatus}</span>
                     </div>
                </div>
            </header>
            
            <!-- Statistical Grid -->
            <div id="stats-grid" class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-12">
                <div class="glass p-5 rounded-xl border-l-2 border-cyan-500/50">
                    <p class="text-[10px] text-gray-500 uppercase tracking-widest font-bold mb-1">Grid Load</p>
                    <p class="text-2xl font-bold">${stats.total} <span class="text-[10px] text-gray-600 font-normal">NODES</span></p>
                </div>
                <div class="glass p-5 rounded-xl border-l-2 border-emerald-500/50">
                    <p class="text-[10px] text-gray-500 uppercase tracking-widest font-bold mb-1">Active Links</p>
                    <p class="text-2xl font-bold text-cyan-400">${stats.active}</p>
                </div>
                <div class="glass p-5 rounded-xl border-l-2 border-amber-500/50">
                    <p class="text-[10px] text-gray-500 uppercase tracking-widest font-bold mb-1">Ready Forge</p>
                    <p class="text-2xl font-bold text-emerald-400">${stats.unassigned}</p>
                </div>
                <div class="glass p-5 rounded-xl border-l-2 border-red-500/50">
                    <p class="text-[10px] text-gray-500 uppercase tracking-widest font-bold mb-1">Anomalies</p>
                    <p class="text-2xl font-bold text-red-500">${stats.violations}</p>
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-12">
                <!-- Tactical Forge -->
                <div class="lg:col-span-2 space-y-8">
                    <div class="glass p-8 rounded-2xl relative overflow-hidden h-full">
                        <div class="flex items-center justify-between mb-8">
                            <h3 class="text-xs font-bold uppercase tracking-[0.2em] text-cyan-500 flex items-center gap-2">
                                <span class="w-1.5 h-1.5 bg-cyan-500 rounded-full animate-ping"></span> KEY PROVISIONING ENGINE
                            </h3>
                            <button onclick="window.location.reload()" class="text-[9px] text-gray-500 hover:text-white transition-colors uppercase tracking-widest">Refresh Registry</button>
                        </div>
                        <div class="flex flex-col gap-6">
                            <div class="relative">
                                <span class="absolute left-4 top-1/2 -translate-y-1/2 text-[10px] text-gray-600 font-bold uppercase">ID PREFIX</span>
                                <input type="text" id="customKey" placeholder="OPTIONAL_CUSTOM_OVERRIDE" class="forge-input w-full pl-24 font-mono uppercase text-sm h-14">
                            </div>
                            <div class="flex gap-4">
                                <button onclick="forgeKey()" class="flex-grow bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-bold py-4 rounded-lg transition-all uppercase tracking-widest shadow-xl shadow-cyan-900/40">Forge Industrial Key</button>
                                <a href="/admin/audit?token=${token}" target="_blank" class="glass text-gray-400 hover:text-white px-8 py-4 rounded-lg transition-all text-xs font-bold uppercase tracking-widest flex items-center">Full Audit</a>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Security Monitor -->
                <div id="security-monitor" class="glass p-6 rounded-2xl border-t-2 border-red-500/20">
                    <h3 class="text-[10px] font-bold uppercase tracking-[0.2em] text-gray-500 mb-6 flex items-center gap-2">
                        <span class="w-2 h-2 bg-red-500 rounded-full shadow-[0_0_8px_rgba(239,68,68,0.5)]"></span> Security Monitor
                    </h3>
                    <div class="space-y-4 max-h-[160px] overflow-y-auto pr-2 custom-scrollbar">
                        ${auditHtml}
                    </div>
                </div>
            </div>

            <!-- Registry Console -->
            <div class="glass rounded-2xl overflow-hidden shadow-2xl border border-white/5">
                <div class="p-6 bg-white/[0.02] border-b border-white/5 flex flex-col md:flex-row justify-between items-center gap-4">
                    <div class="flex items-center gap-4 w-full md:w-auto">
                        <h2 class="text-sm font-bold uppercase tracking-widest text-cyan-500/80 italic shrink-0">⌬ Master Registry</h2>
                        <div class="h-px bg-white/10 flex-grow hidden md:block"></div>
                    </div>
                    <div class="relative w-full md:w-96">
                        <input type="text" id="registrySearch" placeholder="TACTICAL SEARCH (KEY / HWID / GEO)" class="forge-input w-full text-xs h-10 pr-10" onkeyup="filterRegistry()">
                        <svg class="absolute right-3 top-1/2 -translate-y-1/2 text-gray-600" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>
                    </div>
                </div>
                <div class="overflow-x-auto overflow-y-auto max-h-[600px] custom-scrollbar">
                    <table class="w-full text-left table-fixed min-w-[1000px]" id="registryTable">
                        <thead class="bg-black/40 border-b border-white/10 text-[9px] text-gray-500 uppercase tracking-widest font-bold sticky top-0 z-10">
                            <tr>
                                <th class="p-5 w-1/5">Activation Sector (Key)</th>
                                <th class="p-5 w-1/6">Neural Link (HWID)</th>
                                <th class="p-5 w-1/12">Protocol</th>
                                <th class="p-5 w-[8%] text-center">Trace</th>
                                <th class="p-5 w-1/4">Origin</th>
                                <th class="p-5 w-[8%] text-center">Integrity</th>
                                <th class="p-5 w-[8%] text-center">Status</th>
                                <th class="p-5 w-[8%] text-right">Action</th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-white/[0.03]">
                            ${registrationsHtml}
                        </tbody>
                    </table>
                </div>
            </div>
            
            <footer class="mt-12 flex justify-between items-center text-[9px] text-gray-700 uppercase tracking-[0.2em] font-bold">
                <span>SENTINEL_NODE // v${VERSION} // ${new Date().toISOString()}</span>
                <span class="flex items-center gap-2">AUTHENTICATION LINK: <span class="text-cyan-900">ENCRYPTED</span></span>
            </footer>
        </div>


        <script>
            const urlParams = new URL(window.location.href).searchParams;
            const token = "${token || ''}" || urlParams.get('token');

            // Industrial Initialization (Zero Simulation)
            window.addEventListener('load', () => {
                const splash = document.getElementById('splash');
                if (splash) {
                    splash.style.opacity = '0';
                    setTimeout(() => splash.remove(), 500);
                }

                // Industrial Telemetry Stream (30s partial hydration)
                setInterval(() => {
                    const params = new URLSearchParams(window.location.search);
                    fetch(window.location.pathname + '?' + params.toString())
                        .then(r => r.text())
                        .then(html => {
                            const doc = new DOMParser().parseFromString(html, 'text/html');
                            ['stats-grid', 'registryTable', 'security-monitor'].forEach(id => {
                                const target = document.getElementById(id);
                                const source = doc.getElementById(id);
                                if (target && source && target.innerHTML !== source.innerHTML) {
                                    target.innerHTML = source.innerHTML;
                                }
                            });
                        });
                }, 30000);
            });

            async function copyToClipboard(text, btn) {
                try {
                    await navigator.clipboard.writeText(text);
                    if (btn) {
                        const original = btn.innerHTML;
                        btn.innerHTML = '<span class="text-emerald-400">OK</span>';
                        setTimeout(() => btn.innerHTML = original, 2000);
                    }
                } catch (err) {
                    console.error('FAILED_TO_COPY: ', err);
                }
            }

            async function revoke(key) {
                if (!confirm('TERMINATE NEURAL LINK FOR [' + key + ']?')) return;
                try {
                    const resp = await fetch('/admin/revoke?key=' + key + '&token=' + token, { method: 'POST' });
                    if (resp.status === 204) {
                        window.location.reload();
                    } else {
                        alert("⌬ REVOCATION_FAULT: System rejected request.");
                    }
                } catch (e) {
                    alert("⌬ NETWORK_FAULT: Failed to reach Sentinel Node.");
                }
            }

            async function forgeKey() {
                const custom = document.getElementById('customKey').value.trim();
                try {
                    const resp = await fetch('/admin/generate?token=' + token + (custom ? '&key=' + custom : ''), { method: 'POST' });
                    if (resp.ok) {
                        const data = await resp.json();
                        alert('⌬ KEY_FORGED: [' + data.key + '] added to vault.');
                        window.location.reload();
                    } else {
                        const err = await resp.json();
                        alert('⌬ FORGE_FAULT: ' + err.error);
                    }
                } catch (e) {
                    alert("⌬ NETWORK_FAULT: Failed to reach Sentinel Forge.");
                }
            }

            function filterRegistry() {
                const input = document.getElementById('registrySearch');
                const filter = input.value.toUpperCase();
                const table = document.getElementById('registryTable');
                const tr = table.getElementsByTagName('tr');

                for (let i = 1; i < tr.length; i++) {
                    const txt = tr[i].textContent || tr[i].innerText;
                    tr[i].style.display = txt.toUpperCase().indexOf(filter) > -1 ? "" : "none";
                }
            }
        </script>
        <style>
            .custom-scrollbar::-webkit-scrollbar { width: 4px; height: 4px; }
            .custom-scrollbar::-webkit-scrollbar-track { background: rgba(0,0,0,0.2); }
            .custom-scrollbar::-webkit-scrollbar-thumb { background: rgba(34, 211, 238, 0.2); border-radius: 10px; }
            .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: rgba(34, 211, 238, 0.4); }
        </style>
    </body>
    </html>`;

    return new Response(html, { 
        headers: { 
            ...getSecurityHeaders(),
            'Content-Type': 'text/html',
            'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate'
        } 
    });
}

/**
 * ⌬ orchestrateRegistry (Industrial Intelligence Engine)
 * Single-pass reactor that transforms raw KV shards into normalized state.
 */
async function orchestrateRegistry(vault) {
    const registrations = [];
    const auditLogs = [];
    const stats = { total: 0, active: 0, unassigned: 0, geo: {}, violations: 0 };
    
    const list = await vault.MYTH_LICENSES.list();
    for (const item of list.keys) {
        if (!item || !item.name || item.name.startsWith('RL:')) continue;
        const raw = await vault.MYTH_LICENSES.get(item.name);
        if (raw === null) continue;

        if (item.name.startsWith('AUDIT:')) {
            try {
                const auditData = JSON.parse(raw);
                if (auditData) {
                    auditLogs.push(auditData);
                    const action = auditData.action || 'UNKNOWN';
                    if (action.includes('VIOLATION') || action.includes('BLOCK') || action.includes('UNAUTHORIZED') || action.includes('INVALID_KEY')) stats.violations++;
                }
            } catch { /* Suppress malformed audit artifacts */ }
            continue;
        }

        let data;
        try {
            data = JSON.parse(raw);
        } catch {
            data = { hwid: raw, status: raw === 'UNASSIGNED' ? 'READY' : 'ACTIVE', geo: 'LEGACY' };
        }
        
        const normalized = { 
            key: item.name, 
            hwid: data?.hwid || 'N/A', 
            status: data?.status || 'UNKNOWN',
            version: data?.version || 'v1.1.0',
            geo: data?.geo || 'N/A',
            ip: data?.ip || 'N/A',
            activated_at: data?.activated_at || 0
        };

        registrations.push(normalized);
        stats.total++;
        if (normalized.status === 'ACTIVE' || (typeof raw === 'string' && raw !== 'UNASSIGNED' && raw !== 'READY')) stats.active++;
        else stats.unassigned++;

        if (normalized.geo && typeof normalized.geo === 'object') {
            const geoLabel = (normalized.geo.city || 'Unknown') + ', ' + (normalized.geo.country || 'Unknown');
            stats.geo[geoLabel] = (stats.geo[geoLabel] || 0) + 1;
        }
    }

    registrations.sort((regA, regB) => {
        const timeA = new Date(regA.activated_at || 0).getTime();
        const timeB = new Date(regB.activated_at || 0).getTime();
        return timeB - timeA;
    });
    auditLogs.sort((logA, logB) => {
        const timeA = new Date(logA.timestamp || 0).getTime();
        const timeB = new Date(logB.timestamp || 0).getTime();
        return timeB - timeA;
    });

    return { registrations, auditLogs, stats };
}

async function handleAuditView(vault) {
    const list = await vault.MYTH_LICENSES.list({ prefix: 'AUDIT:' });
    const audits = [];
    for (const item of list.keys) {
        const raw = await vault.MYTH_LICENSES.get(item.name);
        try {
            const entry = JSON.parse(raw);
            if (entry && typeof entry === 'object') audits.push(entry);
        } catch {
            console.error(`Malformed audit log: ${item.name}`);
        }
    }
    audits.sort((logA, logB) => {
        const timeA = new Date(logA.timestamp || 0).getTime();
        const timeB = new Date(logB.timestamp || 0).getTime();
        return timeB - timeA;
    });
    return respond({ success: true, count: audits.length, logs: audits });
}

async function handleRevoke(url, env, ip) {
    const key = url.searchParams.get('key');
    if (!key) return respondError('⌬ MISSING_KEY_PARAMETER', 400);
    
    await env.MYTH_LICENSES.put(key, "UNASSIGNED");
    await logAudit(env, 'MANUAL_REVOKE', { key, ip });
    return new Response(null, { status: 204 });
}

async function handleGenerate(url, env, ip) {
    let key = url.searchParams.get('key');
    
    if (key) {
        // Custom key — single collision check, no retry
        key = key.toUpperCase();
        const existing = await env.MYTH_LICENSES.get(key);
        if (existing !== null) {
            return respondError('⌬ KEY_COLLISION_DETECTED: Key already exists in vault', 409);
        }
    } else {
        // Auto-generate with crypto-secure randomness + collision retry loop
        const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // 32 chars, no ambiguous 0/O/1/I
        const maxAttempts = 5;
        let collision = true;

        for (let attempt = 0; attempt < maxAttempts; attempt++) {
            const bytes = new Uint8Array(12);
            crypto.getRandomValues(bytes);
            const segment = (offset) => Array.from({length: 4}, (_, i) => alphabet[bytes[offset + i] % alphabet.length]).join('');
            key = `${APP_NAME}-${segment(0)}-${segment(4)}-${segment(8)}`;

            const existing = await env.MYTH_LICENSES.get(key);
            if (existing === null) {
                collision = false;
                break;
            }
            await logAudit(env, 'KEY_FORGE_COLLISION_RETRY', { key, attempt: attempt + 1, ip });
        }

        if (collision) {
            return respondError('⌬ KEY_FORGE_EXHAUSTED: Failed to generate unique key after maximum retries', 500);
        }
    }

    await env.MYTH_LICENSES.put(key, "UNASSIGNED");
    await logAudit(env, 'KEY_FORGE', { key, ip });
    return respond({ success: true, key });
}

// --- [CORE LOGIC: ACTIVATION ENGINE v3.1] ---

async function handleActivation(request, env, ip) {
    let body;
    try {
        body = await request.json();
    } catch {
        return respondError('⌬ MALFORMED_JSON_PAYLOAD', 400);
    }

    const { activation_key, device_fingerprint, app_version } = body;
    if (!activation_key || !device_fingerprint) {
        return respondError('⌬ INCOMPLETE_SPECIFICATION', 400);
    }

    const raw = await env.MYTH_LICENSES.get(activation_key);

    if (raw === null) {
        await logAudit(env, 'INVALID_KEY_ATTEMPT', { key: activation_key, ip });
        return respond({ success: false, error: 'INVALID_ACTIVATION_KEY' });
    }

    let record = { hwid: 'UNASSIGNED', status: 'READY' };
    try {
        record = JSON.parse(raw);
    } catch {
        record = { hwid: raw, status: raw === 'UNASSIGNED' ? 'READY' : 'ACTIVE' };
    }

    const geo = request.cf ? {
        city: request.cf.city,
        region: request.cf.region,
        country: request.cf.country,
        lat: request.cf.latitude,
        lon: request.cf.longitude,
        isp: request.cf.asOrganization,
        colo: request.cf.colo
    } : 'Unknown';

    if (record.hwid === "UNASSIGNED") {
        const metadata = {
            hwid: device_fingerprint,
            status: 'ACTIVE',
            geo: geo,
            ip: ip,
            version: app_version || 'v1.1.0',
            activated_at: new Date().toISOString()
        };
        await env.MYTH_LICENSES.put(activation_key, JSON.stringify(metadata));
        await logAudit(env, 'NEW_ACTIVATION', { key: activation_key, ip, geo });
        record = metadata;
    } else if (record.hwid !== device_fingerprint) {
        await logAudit(env, 'SECURITY_VIOLATION_HWID', { key: activation_key, ip, geo, claimed: device_fingerprint, stored: record.hwid });
        return respond({ success: false, error: 'HARDWARE_LOCK_VIOLATION' });
    }

    const issued_at = new Date().toISOString().split('.')[0] + "Z";
    const payload = `${activation_key}:${device_fingerprint}:${LICENSING_TIER}:${EXPIRATION}:${issued_at}`;
    
    try {
        const signature = await signWithEd25519(payload, env.MY_PRIVATE_KEY);
        return respond({
            success: true,
            certificate: {
                activation_key,
                device_fingerprint,
                license_tier: LICENSING_TIER,
                expiration: (EXPIRATION === "perpetual" ? null : EXPIRATION),
                issued_at,
                signature
            }
        });
    } catch (e) {
        console.error(`🚨 Cryptographic Fault: ${e.message}`);
        return respondError('⌬ CRYPTO_ENGINE_FAULT', 500);
    }
}

// --- [HELPERS: SECURITY & UTILS] ---

async function signWithEd25519(message, privKeyHex) {
    const rawKey = hexToUint8Array(privKeyHex);
    
    // Ed25519 PKCS#8 Header (OID 1.3.101.112)
    const pkcs8Header = new Uint8Array([
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20
    ]);
    
    const pkcs8Key = new Uint8Array(pkcs8Header.length + rawKey.length);
    pkcs8Key.set(pkcs8Header);
    pkcs8Key.set(rawKey, pkcs8Header.length);

    const key = await crypto.subtle.importKey(
        'pkcs8',
        pkcs8Key,
        'Ed25519',
        false,
        ['sign']
    );
    const signature = await crypto.subtle.sign('Ed25519', key, new TextEncoder().encode(message));
    return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

function hexToUint8Array(hex) {
    if (hex.length % 2 !== 0) throw new Error("Invalid hex string");
    const view = new Uint8Array(hex.length / 2);
    for (let i = 0; i < view.length; i++) {
        view[i] = parseInt(hex.substr(i * 2, 2), 16);
    }
    return view;
}

function timingSafeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    if (a.length !== b.length) return false;
    let result = 0;
    for (let i = 0; i < a.length; i++) {
        result |= (a.charCodeAt(i) ^ b.charCodeAt(i));
    }
    return result === 0;
}

function validateEnvironment(env) {
    if (!env.MYTH_LICENSES) throw new Error('⌬ KV_NAMESPACE_MISSING: [MYTH_LICENSES]');
    if (!env.MY_PRIVATE_KEY) throw new Error('⌬ SECRET_MISSING: [MY_PRIVATE_KEY]');
    if (!env.MASTER_ADMIN_TOKEN) throw new Error('⌬ SECRET_MISSING: [MASTER_ADMIN_TOKEN]');
}

function getCorsHeaders() {
    return {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Max-Age': '86400',
    };
}

function getSecurityHeaders() {
    return {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Content-Security-Policy': "default-src 'self' 'unsafe-inline' cdn.tailwindcss.com fonts.googleapis.com fonts.gstatic.com; img-src 'self' data: https:; upgrade-insecure-requests;",
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains; preload',
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
    };
}

function respond(data, status = 200) {
    return new Response(JSON.stringify(data), {
        status,
        headers: {
            ...getCorsHeaders(),
            ...getSecurityHeaders(),
            'Content-Type': 'application/json'
        }
    });
}

function respondError(msg, status) {
    if (status >= 500) {
        return new Response(renderSystemFault(msg, status), {
            status,
            headers: {
                ...getSecurityHeaders(),
                'Content-Type': 'text/html'
            }
        });
    }
    return respond({ success: false, error: msg }, status);
}

function renderSystemFault(msg, status) {
    return `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>CRITICAL_FAULT // ${APP_NAME}_SENTINEL</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&display=swap" rel="stylesheet">
        <style>
            body { background: #0a0a0b; color: #ef4444; font-family: 'JetBrains Mono', monospace; display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; overflow: hidden; }
            .terminal { width: 100%; max-width: 600px; padding: 2rem; border-left: 2px solid #ef4444; background: rgba(239, 68, 68, 0.02); position: relative; }
            .glitch { animation: glitch 0.3s infinite; }
            @keyframes glitch { 
                0% { transform: translate(0); }
                20% { transform: translate(-2px, 1px); }
                40% { transform: translate(2px, -1px); opacity: 0.8; }
                100% { transform: translate(0); }
            }
            .grid-bg { position: fixed; inset: 0; background-image: radial-gradient(rgba(239, 68, 68, 0.1) 1px, transparent 1px); background-size: 30px 30px; pointer-events: none; z-index: -1; }
        </style>
    </head>
    <body>
        <div class="grid-bg"></div>
        <div class="terminal">
            <h1 class="text-3xl font-bold mb-4 glitch tracking-tighter uppercase">⌬ SYSTEM_FAULT_DETECTED</h1>
            <div class="space-y-4 text-sm opacity-80">
                <p>[ STATUS ] ERROR_CODE: ${status}</p>
                <p>[ TRACE  ] ${msg}</p>
                <p>[ ACTION ] SESSION_TERMINATED // NODE_RECOVERY_PENDING</p>
            </div>
            <div class="mt-12 pt-8 border-t border-red-500/20 text-[10px] tracking-widest uppercase opacity-40">
                Sovereign Sentinel Infrastructure // Industrial Grade Recovery Required
            </div>
        </div>
    </body>
    </html>
    `;
}
