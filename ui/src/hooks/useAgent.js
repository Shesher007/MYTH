import { useState, useCallback, useEffect, useRef } from 'react';
import axios from 'axios';

// Dynamically resolve API_BASE for global deep-linking robustness
const getInitialApiBase = () => {
    if (typeof window !== 'undefined') {
        const params = new URLSearchParams(window.location.search);
        const backendParam = params.get('backend');
        if (backendParam) return backendParam;
    }
    return 'http://127.0.0.1:8890';
};

const API_BASE = getInitialApiBase();

/**
 * Custom hook to interact with the MYTH Agent FastAPI backend.
 * Handles SSE streaming for real-time tokens and tool events with high resilience.
 */
export const useAgent = () => {
    // --- 1. STATES ---
    const [messages, setMessages] = useState([]);
    const [isProcessing, setIsProcessing] = useState(false);
    const [currentStatus, setCurrentStatus] = useState('Idle');
    const [activeNode, setActiveNode] = useState(null);
    const [activeModel, setActiveModel] = useState(null);
    const [usedTools, setUsedTools] = useState([]);
    const [logs, setLogs] = useState([]);
    const [thoughts, setThoughts] = useState('');
    const [thinkingStartTime, setThinkingStartTime] = useState(null);
    const [abortController, setAbortController] = useState(null);
    const [generatedFiles, setGeneratedFiles] = useState([]);
    const [systemStatus, setSystemStatus] = useState({
        integrity: 100,
        metrics: { cpu: 0, ram: 0, disk: 0, tools: 0, latency: '0ms', network_ping: -1 },
        components: { agent: 'INIT', rag: 'INIT', mcp: 'INIT' },
        os: 'UNKNOWN', ip: '127.0.0.1', hostname: 'NODE_LOCAL_01', uptime: '0h 0m',
        identity: { name: 'MYTH', full_name: 'Multi-Yield Tactical Hub', version: '...', codename: 'LOADING...', org: 'MYTH Tools' }
    });

    const [networkConnections, setNetworkConnections] = useState([]);
    const [securityAlerts, setSecurityAlerts] = useState([]);
    const [notifications, setNotifications] = useState([]);
    const [localNotifications, setLocalNotifications] = useState([]);
    const [systemSessions, setSystemSessions] = useState([]);
    const [systemProcesses, setSystemProcesses] = useState([]);
    const [complianceReport, setComplianceReport] = useState(null);
    const [isScanning, setIsScanning] = useState(false);
    const [vpnStatus, setVpnStatus] = useState({ connected: false, active_node: null, throughput_tx: 0, throughput_rx: 0, uptime: '0h 0m', ip_virtual: '0.0.0.0' });
    const [vpnNodes, setVpnNodes] = useState([]);
    const [architectureMode, setArchitectureMode] = useState('normal');
    const [currentSessionId, setCurrentSessionId] = useState(localStorage.getItem('myth_session_id'));
    const [speakingMode, setSpeakingMode] = useState(false); // NEW: Controls VibeVoice audio streaming
    const [settingsKeys, setSettingsKeys] = useState({
        nvidia_api_key: null,
        mistral_api_key: null,
        huggingfacehub_api_token: null
    });
    const [streamStatus, setStreamStatus] = useState('IDLE'); // IDLE, CONNECTING, STREAMING, COMPLETED, ERROR
    const [indexingProgress, setIndexingProgress] = useState({ task_id: null, progress: 0, status: null });

    // --- AUDIO PLAYBACK QUEUE ---
    const audioQueue = useRef([]);
    const isPlayingAudio = useRef(false);
    const audioContext = useRef(null);
    const socketRef = useRef(null);
    const systemSocketRef = useRef(null);
    const lastUpdateRef = useRef(0);
    const lastContentRef = useRef('');
    const lastThoughtsRef = useRef('');
    const throttleTimeoutRef = useRef(null);

    // --- 2. CORE UTILITIES (NO DEPENDENCIES) ---

    const addMessage = useCallback((role, content, name = null, attachments = []) => {
        setMessages(prev => [...prev, { role, content, name, attachments, timestamp: new Date().toISOString() }]);
    }, []);



    const stopGeneration = useCallback(() => {
        if (socketRef.current) {
            socketRef.current.close();
            socketRef.current = null;
        }
        if (abortController) {
            abortController.abort(); setAbortController(null);
        }
        setIsProcessing(false); setCurrentStatus('Aborted');
        setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] 🛑 Operation Halted`]);

        // Halt audio immediately
        if (audioContext.current && audioContext.current._currentSource) {
            try {
                audioContext.current._currentSource.stop();
                audioContext.current._currentSource = null;
            } catch (e) { /* ignore */ }
        }
        audioQueue.current = [];
        isPlayingAudio.current = false;
    }, [abortController]);

    const purgeSession = useCallback(async () => {
        stopGeneration();
        setMessages([]);
        setThoughts('');
        setCurrentStatus('Idle');
        setActiveNode(null);
        setUsedTools([]);
        if (currentSessionId) {
             setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] 🧹 Session Purged: ${currentSessionId}`]);
        }
        
        // Notify backend to clear ephemeral files (Session Cleanup)
        try {
            await axios.post(`${API_BASE}/session/purge`);
        } catch (e) {
            console.error("Backend purge failed:", e);
        }
    }, [stopGeneration, currentSessionId]);

    // --- 3. FETCHERS & SYNCERS ---


    const fetchArchitecture = useCallback(async () => {
        try {
            const response = await axios.get(`${API_BASE}/settings/architecture`);
            if (response.data && response.data.mode) {
                setArchitectureMode(response.data.mode);
            }
        } catch (error) { console.error('Architecture Load Error:', error); }
    }, []);

    const fetchSettingsKeys = useCallback(async () => {
        try {
            const res = await fetch(`${API_BASE}/settings/keys`);
            if (res.ok) setSettingsKeys(await res.json());
        } catch (err) { console.error("Fetch setting keys err:", err); }
    }, []);

    const updateSettingsKeys = useCallback(async (keys) => {
        try {
            const res = await fetch(`${API_BASE}/settings/keys`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(keys)
            });
            if (res.ok) {
                await fetchSettingsKeys();
                return true;
            }
        } catch (err) { console.error("Update setting keys err:", err); }
        return false;
    }, [fetchSettingsKeys]);


    // --- 4. FUNCTIONAL UTILITIES ---



    const isolateNode = useCallback(async (enabled) => {
        try {
            await axios.post(`${API_BASE}/security/isolate`, { enabled });
            return true;
        } catch (error) { console.error('Isolation Err:', error); return false; }
    }, []);

    const clearAlerts = useCallback(async () => {
        try {
            await axios.post(`${API_BASE}/security/alerts/clear`);
            setSecurityAlerts([]);
            setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] 🧹 Security alerts purged`]);
            return true;
        } catch (error) { console.error('Clear Alerts Err:', error); return false; }
    }, []);

    const indexFolder = useCallback(async (folderPath) => {
        setIsProcessing(true); setCurrentStatus(`Scanning: ${folderPath}...`);
        try {
            const response = await axios.post(`${API_BASE}/rag/upload/folder`, { folder_path: folderPath, collection_name: 'security_docs' });
            if (response.data.success) {
                addMessage('assistant', `📁 **Folder Indexed**: \`${folderPath}\` scan complete.`);
                return true;
            }
        } catch (error) {
            addMessage('assistant', `❌ **Folder Index Failed**: ${error.message}`);
            return false;
        } finally { setIsProcessing(false); setCurrentStatus('Idle'); }
    }, [addMessage]);

    const uploadFileWithProgress = useCallback(async (file, onProgress) => {
        const formData = new FormData(); formData.append('file', file); formData.append('collection_name', 'security_docs');
        
        try {
            const config = {
                // headers: { 'Content-Type': 'multipart/form-data' }, // FIXED: Let browser set boundary!
                onUploadProgress: (progressEvent) => {
                    const percentCompleted = Math.round((progressEvent.loaded * 100) / progressEvent.total);
                    onProgress && onProgress(percentCompleted);
                }
            };
            
            const response = await axios.post(`${API_BASE}/rag/upload`, formData, config);
            return response.data; // Return full data including analysis
        } catch (error) {
            console.error('Upload Error:', error);
            throw error;
        }
    }, []);

    // Legacy support wrapper or remove if unused, keeping for compatibility if needed
    const uploadDocument = useCallback(async (file) => {
        setIsProcessing(true); setCurrentStatus(`Indexing ${file.name}...`);
        try {
           const result = await uploadFileWithProgress(file);
           if (!result.success) throw new Error(result.error || "Index failed");
           addMessage('assistant', `✅ **Asset Synced**: \`${file.name}\` processed.`);
           return true;
        } catch (error) {
            addMessage('assistant', `❌ **Asset Index Failed**: ${error.message}`);
            return false;
        } finally { setIsProcessing(false); setCurrentStatus('Idle'); }
    }, [addMessage, uploadFileWithProgress]);




    const toggleVpn = useCallback(async (nodeId = null) => {
        try {
            const response = await axios.post(`${API_BASE}/vpn/toggle`, { node_id: nodeId });
            setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ${response.data.connected ? '🔒 VPN Established' : '🔓 VPN Terminated'}`]);
            return true;
        } catch (error) { console.error('VPN Err:', error); return false; }
    }, []);

    const switchArchitecture = useCallback(async (mode) => {
        try {
            const response = await axios.post(`${API_BASE}/settings/architecture`, { mode });
            if (response.data.success) {
                setArchitectureMode(response.data.mode);
                setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] 🔄 Architecture: ${response.data.display_name}`]);
                return true;
            }
        } catch (error) { console.error('Arch Switch Err:', error); } return false;
    }, []);

    const browseFolder = useCallback(async () => {
        try {
            const response = await axios.post(`${API_BASE}/system/browse`);
            return response.data.success ? response.data.path : null;
        } catch { return null; }
    }, []);

    const getFolderSummary = useCallback(async (folderPath) => {
        try {
            const response = await axios.post(`${API_BASE}/system/folder/summary`, { folder_path: folderPath });
            return response.data.success ? response.data.summary : null;
        } catch { return null; }
    }, []);

    const deleteGeneratedFile = useCallback(async (filename) => {
        // ⚡ OPTIMISTIC UPDATE: Instant removal from UI
        setGeneratedFiles(prev => prev.filter(f => f.name !== filename));
        
        try {
            await axios.delete(`${API_BASE}/system/files/${filename}`);
        } catch (error) { 
            console.error('File Delete Err:', error);
            // Non-destructive: Telemetry will restore state if server found no change
        }
    }, []);

    const downloadFile = useCallback(async (filename) => {
        try {
            const url = `${API_BASE}/system/files/download/${filename}`;
            const response = await axios.get(url, { responseType: 'blob' });
            const blob = new Blob([response.data]); const dUrl = window.URL.createObjectURL(blob);
            const link = document.createElement('a'); link.href = dUrl; link.setAttribute('download', filename);
            document.body.appendChild(link); link.click(); link.remove();
        } catch (error) { console.error('Download Error:', error); }
    }, []);

    const renameFile = useCallback(async (filename, newName) => {
        // ⚡ OPTIMISTIC UPDATE: Instant rename in UI
        setGeneratedFiles(prev => prev.map(f => 
            f.name === filename ? { ...f, name: newName } : f
        ));

        try {
            await axios.patch(`${API_BASE}/system/files/${filename}`, { new_name: newName });
            return true;
        } catch (error) {
            console.error('Rename Error:', error);
            return false;
        }
    }, []);

    const runSystemScan = useCallback(async () => {
        setIsScanning(true);
        try {
            const response = await axios.post(`${API_BASE}/security/scan`);
            setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] 🔍 System Audit: ${response.data.summary}`]);
            return response.data;
        } catch (error) { console.error('Scan Fail:', error); } finally { setIsScanning(false); }
    }, []);

    const playNextAudio = useCallback(async () => {
        if (audioQueue.current.length === 0 || isPlayingAudio.current) return;

        if (!audioContext.current) {
            audioContext.current = new (window.AudioContext || window.webkitAudioContext)();
        }

        // Handle browser autoplay restrictions
        if (audioContext.current.state === 'suspended') {
            await audioContext.current.resume();
        }

        isPlayingAudio.current = true;
        const item = audioQueue.current.shift();
        
        try {
            let buffer;
            if (item.buffer) {
                // Already pre-decoded
                buffer = item.buffer;
            } else {
                // Legacy support or fallback: decode now
                const binaryString = window.atob(item);
                const bytes = new Uint8Array(binaryString.length);
                for (let i = 0; i < binaryString.length; i++) bytes[i] = binaryString.charCodeAt(i);
                buffer = await audioContext.current.decodeAudioData(bytes.buffer);
            }
            
            const source = audioContext.current.createBufferSource();
            source.buffer = buffer;
            source.connect(audioContext.current.destination);
            
            // Store current source so we can stop it if user halts generation
            audioContext.current._currentSource = source;

            source.onended = () => {
                isPlayingAudio.current = false;
                audioContext.current._currentSource = null;
                playNextAudio();
            };
            source.start(0);

            // PRE-DECODE NEXT CHUNK IN QUEUE FOR ZERO-LATENCY TRANSITION
            if (audioQueue.current.length > 0 && !audioQueue.current[0].buffer) {
                const nextItem = audioQueue.current[0];
                if (typeof nextItem === 'string') {
                    const bStr = window.atob(nextItem);
                    const bts = new Uint8Array(bStr.length);
                    for (let i = 0; i < bStr.length; i++) bts[i] = bStr.charCodeAt(i);
                    audioContext.current.decodeAudioData(bts.buffer).then(decoded => {
                        audioQueue.current[0] = { buffer: decoded };
                    }).catch(err => console.error("Pre-decode failed:", err));
                }
            }

        } catch (e) {
            console.error('Audio Playback Error:', e);
            isPlayingAudio.current = false;
            playNextAudio();
        }
    }, [audioQueue]);

    // --- 5. STREAM LOGIC ---

    const sendMessage = useCallback(async (text, attachments = [], sessionId = null) => {
        if (!text.trim() && attachments.length === 0) return;
        
        // Halt any existing audio and previous sockets immediately
        if (socketRef.current) {
            socketRef.current.close();
            socketRef.current = null;
        }
        
        if (audioContext.current && audioContext.current._currentSource) {
            try {
                audioContext.current._currentSource.stop();
                audioContext.current._currentSource = null;
            } catch (e) { /* ignore */ }
        }
        audioQueue.current = [];
        isPlayingAudio.current = false;

        const activeSessionId = currentSessionId;
        const isInitialMessage = messages.length === 0;

        setIsProcessing(true); setCurrentStatus('Preparing...'); setThoughts(''); setThinkingStartTime(Date.now());
        setActiveNode(null);
        setActiveModel(null);
        setUsedTools([]);
        setStreamStatus('CONNECTING');
        lastUpdateRef.current = 0;
        lastContentRef.current = '';
        lastThoughtsRef.current = '';
        const controller = new AbortController(); setAbortController(controller);
        
        const attachmentMetadata = [];
        if (attachments.length > 0) {
            setCurrentStatus(`Processing ${attachments.length} items...`);
            
            // ULTRA LIGHTNING: Parallelize attachment uploads
            const uploadTasks = attachments.map(async (item) => {
                try {
                    if (item.type === 'folder') {
                        const success = await indexFolder(item.content);
                        if (success) return `Folder: ${item.content}`;
                    } else {
                        // Strict check to avoid redundant uploads
                        if (item.status === 'success' || item.status === 'parsing' || item.status === 'uploading') {
                            if (item.status !== 'success') {
                                console.warn(`⚠️ [AGENT] Skipping re-upload for file in progress: ${item.name} (${item.status})`);
                            }
                            return `File: ${item.name}`;
                        }
                        
                        console.log(`📤 [AGENT] Uploading unstaged attachment: ${item.name}`);
                        const file = item.content || item;
                        const result = await uploadFileWithProgress(file);
                        if (!result.success) throw new Error(`Upload failed for ${file.name}: ${result.error || 'Server error'}`);
                        return `File: ${file.name}`;
                    }
                } catch (error) { 
                    console.error('Attach Err:', error); 
                    throw error; // Re-throw to fail the entire sendMessage operation
                }
            });

            const results = await Promise.all(uploadTasks);
            attachmentMetadata.push(...results.filter(Boolean));
        }

        let enrichedText = text;
        if (attachmentMetadata.length > 0) enrichedText += `\n\n[Attached: ${attachmentMetadata.join(', ')}]`;

        addMessage('user', text || `[Attached ${attachments.length} items]`, null, attachments.map(a => ({ name: a.name || 'item', type: a.type, preview: a.preview })));
        setMessages(prev => [...prev, { role: 'assistant', content: '', timestamp: new Date().toISOString() }]);

        try {
            const wsUrl = `${API_BASE.replace('http', 'ws')}/chat/ws`;
            const socket = new WebSocket(wsUrl);
            socketRef.current = socket;
            socket.binaryType = 'arraybuffer'; // Enable binary for fast audio

            let rawAssistantContent = '';

            socket.onopen = () => {
                console.log("🔌 [WS] Connected to Synapse Hub");
                setStreamStatus('STREAMING');
                // Initial hand-shake pulse
                socket.send(JSON.stringify({ 
                    message: enrichedText, 
                    session_id: activeSessionId, 
                    speaking_mode: speakingMode 
                }));
            };

            socket.onmessage = async (event) => {
                // 1. Binary Audio Handling (Zero-Overhead)
                if (event.data instanceof ArrayBuffer) {
                    audioQueue.current.push({ buffer: await audioContext.current.decodeAudioData(event.data) });
                    playNextAudio();
                    return;
                }

                // 2. JSON Telemetry Handling
                try {
                    const data = JSON.parse(event.data);
                    
                    if (data.type === 'on_thought_stream' || data.type === 'on_chat_model_stream' || data.type === 'on_chat_model_end') {
                        const now = Date.now();
                        const throttleMs = 60; // 60ms = ~16fps refresh rate for text
                        
                        if (data.type === 'on_thought_stream') {
                            lastThoughtsRef.current += (data.content || '');
                            if (!currentStatus || currentStatus === 'Preparing...') {
                                setCurrentStatus('Reasoning...');
                            }
                        } else {
                            const token = data.content || '';
                            if (data.type === 'on_chat_model_end' && !rawAssistantContent) {
                                rawAssistantContent = token;
                            } else {
                                rawAssistantContent += token;
                            }

                            // Robust tag parsing for internal thinking tags
                            const thoughtMatches = [...rawAssistantContent.matchAll(/<think>([\s\S]*?)(?:<\/think>|$)/g)];
                            const totalThoughts = thoughtMatches.map(m => m[1]).join('');
                            if (totalThoughts) lastThoughtsRef.current = totalThoughts;

                            lastContentRef.current = rawAssistantContent
                                .replace(/<think>[\s\S]*?(?:<\/think>|think>)/g, '')
                                .replace(/<think>[\s\S]*$/g, '')
                                .replace(/<[^>]*$/g, '')
                                .trim();
                            
                            if (!lastContentRef.current && rawAssistantContent && !rawAssistantContent.includes('<think>')) {
                                lastContentRef.current = rawAssistantContent.trim();
                            }
                        }

                        const triggerUpdate = (isFinal = false) => {
                            setMessages(prev => {
                                const next = [...prev];
                                for (let i = next.length - 1; i >= 0; i--) {
                                    if (next[i].role === 'assistant' && !next[i].is_finalized) {
                                        next[i].content = lastContentRef.current;
                                        if (isFinal) next[i].is_finalized = true;
                                        break;
                                    }
                                }
                                return next;
                            });
                            setThoughts(lastThoughtsRef.current);
                            lastUpdateRef.current = Date.now();
                        };

                        if (throttleTimeoutRef.current) clearTimeout(throttleTimeoutRef.current);

                        if (data.type === 'on_chat_model_end' || data.type === 'stream_complete') {
                            triggerUpdate(true);
                        } else if (now - lastUpdateRef.current > throttleMs) {
                            triggerUpdate(false);
                        } else {
                            throttleTimeoutRef.current = setTimeout(() => triggerUpdate(false), throttleMs);
                        }
                    } else if (data.type === 'on_node_transition') {
                        setActiveNode(data.node_name || data.content);
                        if (data.model_name) setActiveModel(data.model_name);
                        if (data.architecture_mode) setArchitectureMode(data.architecture_mode);
                        setIsProcessing(true);
                    } else if (data.type === 'on_tool_execution') {
                        setCurrentStatus(data.content);
                        setIsProcessing(true);
                    } else if (data.type === 'on_tool_start') {
                        console.log("📥 [WS] Received on_tool_start:", data.name);
                        setCurrentStatus(`Executing: ${data.name}`);
                        setUsedTools(prev => [...new Set([...prev, data.name])]);
                    } else if (data.type === 'on_tool_end') {
                        addMessage('tool', data.output, data.name);
                    } else if (data.type === 'stream_complete') {
                        setStreamStatus('COMPLETED');
                        socket.close();
                    } else if (data.type === 'error') {
                        setCurrentStatus('Error');
                        addMessage('assistant', `⚠️ **Mission Interrupted**: ${data.content}`);
                        socket.close();
                    }
                } catch (e) {
                    console.error("WS Parse Error:", e);
                }
            };

            socket.onclose = () => {
                console.log("🔌 [WS] Nodal Link Severed");
                setIsProcessing(false);
                setCurrentStatus('Idle');
                socketRef.current = null;
                // Files now sync reactively via Telemetry stream
                if (isInitialMessage) {
                    setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] 💾 Transient Session State Active`]);
                }
            };

            socket.onerror = (err) => {
                console.error("🔌 [WS] Socket Pulse Failure:", err);
                setStreamStatus('ERROR');
                setIsProcessing(false);
                setCurrentStatus('Error');
            };

        } catch (error) {
           console.error('Stream Err:', error);
           setIsProcessing(false);
           setCurrentStatus('Idle');
        }
    }, [currentSessionId, messages.length, addMessage, indexFolder, speakingMode]);

    // --- 6. LIFECYCLE ---

    // --- 6. LIFECYCLE ---

    useEffect(() => {
        const params = new URLSearchParams(window.location.search);
        const sessionFromUrl = params.get('session');
        
        // Only trigger if URL has a session AND it's different from current
        if (sessionFromUrl && sessionFromUrl !== currentSessionId) {
            setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] 🌐 Incoming Deep-Link Detected: ${sessionFromUrl}`]);
            // loadSession(sessionFromUrl); // Feature disabled
        } else if (!currentSessionId && !sessionFromUrl) {
            // Only create new session if NO session ID exists anywhere
            const newId = `session_${Math.random().toString(36).substring(2, 10)}`;
            setCurrentSessionId(newId); localStorage.setItem('myth_session_id', newId);
        }
    }, [currentSessionId]);

    useEffect(() => {
        // --- UNIFIED TELEMETRY STREAM (PHASE 2) ---
        const connectSystemTelemetry = () => {
            const wsUrl = `${API_BASE.replace('http', 'ws')}/telemetry/ws`;
            const socket = new WebSocket(wsUrl);
            systemSocketRef.current = socket;

            socket.onopen = () => {
                console.log("📊 [TELEMETRY] System link established");
                setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] 📊 Telemetry Link: SECURE`]);
                
                // Industrial Heartbeat: Measured RTT via socket ping/pong
                const pingInterval = setInterval(() => {
                    if (socket.readyState === WebSocket.OPEN) {
                        socket.send(JSON.stringify({ type: 'PING', timestamp: Date.now() }));
                    }
                }, 5000); // Optimized Heartbeat (5s)
                socket._pingInterval = pingInterval;
            };

            socket.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    if (data.type === 'SYSTEM_TELEMETRY_V2') {
                        // 1. Map Health & Metrics
                        const h = data.health;
                        if (h.status === 'online') {
                            setSystemStatus({
                                integrity: h.integrity,
                                ready: h.ready,
                                metrics: { 
                                    ...h.metrics, 
                                    network_ping: data.network_ping_ms,
                                    network_speed: data.network_speed 
                                },
                                components: h.components,
                                os: h.os,
                                ip: h.ip,
                                hostname: h.hostname,
                                uptime: h.uptime,
                                identity: h.identity
                            });
                            

                            if (h.identity?.name) {
                                document.title = `⌬ ${h.identity.name} | ${h.identity.org}`;
                            }
                        }

                        // 2. Map Sessions (Reactive Sync Disabled or Handled elsewhere)

                        // 3. Map Generated Files (Reactive Sync - Phase 4)
                        if (data.files) setGeneratedFiles(data.files);

                        // 3. Map Security
                        const s = data.security;
                        setSecurityAlerts(s.alerts || []);

                        // 4. Map Notifications (Industrial UI Feedback)
                        if (data.notifications) {
                            setNotifications(prev => {
                                // Mirror NEW notifications to logs for persistent history
                                const prevIds = new Set(prev.map(n => n.id));
                                data.notifications.forEach(notif => {
                                    if (!prevIds.has(notif.id)) {
                                        const ts = new Date(notif.timestamp).toLocaleTimeString();
                                        setLogs(l => [...l, `[${ts}] 🔔 [${notif.type}] ${notif.title}: ${notif.message}`]);
                                    }
                                });
                                return data.notifications;
                            });
                        }


                        // 4. Map Heavy Forensics (Phase 3)
                        if (data.forensics) {
                            const f = data.forensics;
                            if (f.network) setNetworkConnections(f.network);
                            if (f.sessions) setSystemSessions(f.sessions);
                            if (f.processes) {
                                const sortedProcs = [...f.processes].sort((a, b) => (b.cpu || 0) - (a.cpu || 0));
                                setSystemProcesses(sortedProcs);
                            }
                        }
                    } else if (data.type === 'PROGRESS_UPDATE') {
                        setIndexingProgress({
                            task_id: data.task_id,
                            progress: data.progress,
                            status: data.status
                        });
                        if (data.progress === 100) {
                            setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] ✅ Task Complete: ${data.task_id}`]);
                            setTimeout(() => setIndexingProgress({ task_id: null, progress: 0, status: null }), 3000);
                        }
                    } else if (data.type === 'PONG') {
                        // Calculate high-fidelity RTT
                        const rtt = Date.now() - data.client_ts;
                        setSystemStatus(prev => ({
                            ...prev,
                            metrics: { ...prev.metrics, latency: `${rtt}ms` }
                        }));
                    }
                } catch (e) {
                    console.warn("Telemetry Parse Error:", e);
                }
            };

            socket.onclose = () => {
                console.warn("📊 [TELEMETRY] Link severed. Reconnecting in 5s...");
                if (socket._pingInterval) clearInterval(socket._pingInterval);
                systemSocketRef.current = null;
                setTimeout(connectSystemTelemetry, 5000);
            };

            socket.onerror = (err) => {
                console.error("📊 [TELEMETRY] Pulse Failure:", err);
                socket.close();
            };
        };

        // Initial connection
        connectSystemTelemetry();

        // Initial full fetch for heavy/staggered data not in rapid telemetry
        fetchArchitecture(); fetchSettingsKeys();
        
        return () => {
            if (systemSocketRef.current) {
                systemSocketRef.current.onclose = null; // Prevent reconnect loop on unmount
                systemSocketRef.current.close();
            }
        };
    }, [fetchArchitecture, fetchSettingsKeys]);

    // --- Notification Management ---
    const addNotification = useCallback((type, title, message) => {
        const id = `local-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
        setLocalNotifications(prev => [...prev, {
            id,
            type: type || 'INFO',
            title: title || 'System Notification',
            message: message || '',
            timestamp: new Date().toISOString(),
            read: false,
            count: 1
        }]);
        return id;
    }, []);
    const dismissNotification = useCallback(async (notificationId) => {
        // Handle local notifications
        if (typeof notificationId === 'string' && notificationId.startsWith('local-')) {
            setLocalNotifications(prev => prev.filter(n => n.id !== notificationId));
            return;
        }

        // Optimistic UI update
        setNotifications(prev => prev.filter(n => n.id !== notificationId));
        try {
            await axios.post(`${API_BASE}/notifications/dismiss`, { id: notificationId });
        } catch (error) {
            console.error('Dismiss Notification Error:', error);
        }
    }, []);

    const clearAllNotifications = useCallback(async () => {
        // Optimistic UI update
        setLocalNotifications([]);
        setNotifications([]);
        try {
            await axios.post(`${API_BASE}/notifications/clear`);
            setLogs(l => [...l, `[${new Date().toLocaleTimeString()}] 🧹 Notification Matrix Cleared.`]);
        } catch (error) {
            console.error('Clear Notifications Error:', error);
        }
    }, []);

    // Merge notifications for display (Backend + Local), sorted by time
    const allNotifications = [...notifications, ...localNotifications].sort((a, b) => 
        new Date(a.timestamp) - new Date(b.timestamp)
    );


    return {
        messages, sendMessage, isProcessing, currentStatus, activeNode, activeModel, usedTools, logs, setLogs, thoughts, thinkingStartTime,
        stopGeneration, uploadDocument, generatedFiles, downloadFile, deleteGeneratedFile, renameFile,
        indexFolder, browseFolder, getFolderSummary, setMessages, systemStatus, networkConnections, securityAlerts,
        clearAlerts, isolateNode, systemSessions, complianceReport, isScanning, runSystemScan,
        vpnStatus, vpnNodes, toggleVpn, architectureMode, switchArchitecture, fetchArchitecture,
        speakingMode, setSpeakingMode, settingsKeys, fetchSettingsKeys, updateSettingsKeys, uploadFileWithProgress,
        streamStatus, indexingProgress, systemProcesses, purgeSession,
        notifications: allNotifications, dismissNotification, clearAllNotifications, addNotification
    };
};

