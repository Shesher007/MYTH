import React from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Terminal, Activity, Cpu, Trash2, Download, RefreshCw, Settings, AlertCircle, ShieldAlert, ChevronLeft, ChevronRight, Eye, Edit3, Book } from 'lucide-react';
import FileIcon, { getFileIconDetails } from './FileIcon';
import { useSoundscape } from '../hooks/useSoundscape';
import VpnController from './VpnController';

const getInitialApiBase = () => {
    if (typeof window !== 'undefined') {
        const params = new URLSearchParams(window.location.search);
        const backendParam = params.get('backend');
        if (backendParam) return backendParam;
    }
    return 'http://127.0.0.1:8890';
};

const API_BASE = getInitialApiBase();






const SectionHeader = ({ label, isOpen, onToggle, hasChevron = true, action }) => (
    <div
        className={`px-4 py-3 cursor-pointer transition-all duration-300 border-y border-white/[0.02] bg-white/[0.01] hover:bg-white/[0.03] flex items-center justify-between group/header`}
        onClick={onToggle}
    >
        <div className="flex items-center gap-3">
            <div className={`w-1 h-4 rounded-sm transition-all duration-500 ${isOpen ? 'bg-teal-500 shadow-[0_0_10px_rgba(20,184,166,0.8)]' : 'bg-slate-800'}`}></div>
            <div className="flex flex-col">
                <span className={`text-[10px] font-black uppercase tracking-[0.25em] transition-colors ${isOpen ? 'text-slate-100' : 'text-slate-500 group-hover/header:text-slate-300'}`}>
                    {label}
                </span>
                <span className="text-[6px] font-mono text-teal-900 uppercase tracking-widest mt-0.5 opacity-50">NODE_PROTOCOL_RX_{label.slice(0, 3).toUpperCase()}</span>
            </div>
        </div>
        <div className="flex items-center gap-3" onClick={(e) => e.stopPropagation()}>
            {action}
            {hasChevron && (
                <div className={`p-1 rounded bg-black/40 border border-white/5 transition-all ${isOpen ? 'border-teal-500/30' : ''}`}>
                    <ChevronRight
                        size={10}
                        className={`text-slate-600 transition-transform duration-300 ${isOpen ? 'rotate-90 text-teal-400' : ''}`}
                    />
                </div>
            )}
        </div>
    </div>
);

const StatusItem = ({ label, status, icon: Icon, children }) => (
    <div className="flex items-center justify-between py-2 group/item border-b border-white/[0.01] last:border-0 hover:bg-white/[0.02] px-2 transition-all">
        <div className="flex items-center gap-3">
            <div className="w-5 h-5 rounded bg-black/40 border border-white/5 flex items-center justify-center relative shrink-0">
                {Icon && <Icon size={10} className="text-slate-600 group-hover/item:text-teal-400 transition-colors" />}
                <div className="absolute top-0 right-0 w-1 h-1 bg-teal-500/20 rounded-full"></div>
            </div>
            <div className="flex flex-col">
                <span className="text-[9px] font-black text-slate-500 group-hover/item:text-slate-300 transition-colors uppercase tracking-wider">{label}</span>
                <span className="text-[6px] font-mono text-slate-700 uppercase">SYS_LINK_OK</span>
            </div>
        </div>
        <div className="flex items-center gap-3">
            {children}
            <div className="flex items-center gap-1.5 px-2 py-0.5 rounded-sm bg-teal-500/5 border border-teal-500/10">
                <span className="text-[8px] font-mono text-teal-500 tracking-tighter uppercase font-black">{status}</span>
                <div className="w-1 h-1 rounded-full bg-teal-500 shadow-[0_0_5px_rgba(20,184,166,0.5)] animate-pulse"></div>
            </div>
        </div>
    </div>
);

const HealthGauge = ({ value, label }) => {
    const radius = 30;
    const circumference = 2 * Math.PI * radius;
    const offset = circumference - (value / 100) * circumference;

    return (
        <div className="health-gauge-container group/gauge relative">
            <div className="gauge-svg-wrapper relative">
                <div className="absolute inset-0 border border-teal-500/5 rounded-full rotate-45 scale-110"></div>
                <div className="absolute inset-0 border border-teal-500/5 rounded-full -rotate-45 scale-95"></div>

                {/* Tactical HUD Crosshairs */}
                <div className="absolute top-1/2 left-0 w-full h-[1px] bg-teal-500/10 -translate-y-1/2"></div>
                <div className="absolute top-0 left-1/2 w-[1px] h-full bg-teal-500/10 -translate-x-1/2"></div>

                <svg className="gauge-svg hologram-flicker" width="80" height="80">
                    <circle className="gauge-bg" cx="40" cy="40" r={radius} />
                    <circle
                        className="gauge-fill !stroke-[url(#teal-grad)]"
                        cx="40"
                        cy="40"
                        r={radius}
                        strokeDasharray={circumference}
                        strokeDashoffset={offset}
                        style={{ filter: 'drop-shadow(0 0 8px rgba(20,184,166,0.4))' }}
                    />
                    <defs>
                        <linearGradient id="teal-grad" x1="0%" y1="0%" x2="100%" y2="100%">
                            <stop offset="0%" stopColor="#14b8a6" />
                            <stop offset="100%" stopColor="#0ea5e9" />
                        </linearGradient>
                    </defs>
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <span className="text-[16px] font-black text-white font-mono leading-none drop-shadow-sm">{value}%</span>
                    <span className="text-[7px] text-teal-400 font-black uppercase tracking-[0.2em] mt-1 opacity-80">STATUS</span>
                </div>
            </div>
            <div className="flex flex-col items-center mt-2">
                <span className="text-[10px] font-black text-slate-400 group-hover/gauge:text-slate-200 transition-colors uppercase tracking-[0.3em]">{label}</span>
                <div className="flex gap-1 mt-4">
                    {[...Array(10)].map((_, i) => (
                        <div
                            key={i}
                            className={`h-0.5 w-2 transition-all duration-500 ${i < (value / 10) ? 'bg-teal-500 shadow-[0_0_8px_rgba(20,184,166,0.6)]' : 'bg-white/5'}`}
                        />
                    ))}
                </div>
            </div>
        </div>
    );
};

const ResourceBar = ({ label, value, colorClass = "bg-teal-500" }) => (
    <div className="space-y-2 group/resource">
        <div className="flex justify-between text-[9px] font-mono font-black uppercase tracking-widest px-1">
            <div className="flex items-center gap-2">
                <span className="text-slate-500 group-hover/resource:text-teal-500 transition-colors">{label}</span>
                <span className="text-[7px] text-slate-800 opacity-0 group-hover/resource:opacity-100 transition-opacity">CHAN_LNK_0{Math.floor(Math.random() * 9)}</span>
            </div>
            <span className="text-slate-200 font-black">{value}%</span>
        </div>
        <div className="h-2 bg-black/60 rounded-sm overflow-hidden border border-white/5 relative p-[1px]">
            <div
                className={`h-full ${colorClass} transition-all duration-1000 ease-out segmented-track`}
                style={{ width: `${value}%`, '--progress': `${value}%` }}
            ></div>
            {/* Notches */}
            <div className="absolute inset-0 pointer-events-none opacity-20 bg-[linear-gradient(90deg,transparent_90.9%,rgba(255,255,255,0.1)_9.1%)] bg-[length:10%_100%]"></div>
        </div>
    </div>
);

const Sidebar = ({
    isCollapsed,
    onToggleCollapse,
    logs = [],
    onClearMessages,
    generatedFiles = [],
    onDownloadFile,
    onDeleteFile,
    onRefreshFiles,
    stats,
    securityAlerts = [],
    onClearAlerts,
    isolateNode,
    systemSessions = [],
    complianceReport,
    isScanning,
    runSystemScan,
    vpnStatus,
    vpnNodes,
    toggleVpn,
    onOpenSettings,
    onPreviewFile,
    onRenameFile
}) => {
    const { playTick, playChirp, playSuccess } = useSoundscape();
    const [isIsolated, setIsIsolated] = React.useState(false);
    const [editingFile, setEditingFile] = React.useState(null);
    const [newName, setNewName] = React.useState('');
    const [openSections, setOpenSections] = React.useState({
        vpn: true,
        posture: true,
        audit: false,
        sessions: false,
        alerts: true,
        assets: true,
        telemetry: false
    });

    const toggleSection = (section) => {
        playTick();
        setOpenSections(prev => ({ ...prev, [section]: !prev[section] }));
    };

    const handleIsolationToggle = async () => {
        const nextState = !isIsolated;
        const success = await isolateNode(nextState);
        if (success) {
            setIsIsolated(nextState);
            playChirp();
        }
    };

    const handleRunScan = async () => {
        playChirp();
        await runSystemScan();
        playSuccess();
    };

    // Default status if data is missing
    const statsData = stats || {
        integrity: 100,
        metrics: { cpu: 0, ram: 0, disk: 0, tools: 0 },
        components: { agent: 'INIT', rag: 'INIT', mcp: 'INIT' },
        os: 'UNKNOWN',
        ip: '127.0.0.1',
        uptime: '0h 0m',
        identity: {
            name: 'MYTH',
            full_name: 'Multi-Yield Tactical Hub',
            version: '...',
            codename: 'LOADING...',
            org: 'MYTH'
        }
    };

    // Unified logic for file icons and size formatting
    const getFileIcon = (name, type) => {
        return <FileIcon name={name} type={type} size={12} />;
    };

    const formatSize = (bytes) => {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    };

    const handleRefresh = () => {
        playChirp();
        onRefreshFiles();
    };

    const handleDownload = (name) => {
        playTick();
        onDownloadFile(name);
    };

    const handleDelete = (name) => {
        console.log(`[SIDEBAR] Deleting target: ${name}`);
        playTick();
        onDeleteFile(name);
    };

    const handleRenameStart = (file) => {
        playTick();
        setEditingFile(file.name);
        setNewName(file.name);
    };

    const handleRenameSubmit = async (oldName) => {
        if (!newName || newName === oldName) {
            setEditingFile(null);
            return;
        }
        const success = await onRenameFile(oldName, newName);
        if (success) {
            playSuccess();
            setEditingFile(null);
        } else {
            alert("Rename failed. Check for duplicate names or restricted characters.");
        }
    };

    const handlePreview = async (file) => {
        playTick();
        const isImage = file.name.match(/\.(jpg|jpeg|png|gif|webp|svg|jfif|avif|apng|pjpeg|pjp|ico|bmp|heif)$/i);
        const isAudio = file.name.match(/\.(wav|mp3|ogg|flac|m4a|aac|opus|wma)$/i);

        const downloadUrl = `${API_BASE}/system/files/download/${file.name}`;

        let previewData = {
            name: file.name,
            type: file.type,
            size: formatSize(file.size),
            preview: (isImage || isAudio) ? downloadUrl : null,
        };

        try {
            const response = await fetch(`${API_BASE}/system/files/preview/${file.name}`);
            const data = await response.json();
            previewData.hex_dump = data.hex_dump;
            previewData.contentSnippet = data.content_text;
            previewData.mime_type = data.mime_type;
            previewData.is_binary = data.is_binary;
        } catch (err) {
            console.error("Forensic fetch err:", err);
            // Fallback for network issues
            previewData.contentSnippet = "FORENSIC_LINK_OFFLINE";
        }

        onPreviewFile(previewData);
    };


    return (
        <aside className={`sidebar relative bg-[#010103] selection:bg-teal-500/30 transition-all duration-500 overflow-hidden h-full ${isCollapsed ? 'collapsed w-0' : 'w-[var(--sidebar-width)]'}`}>
            {/* Industrial Edge Protocol */}
            <div className="absolute inset-0 pointer-events-none z-[100]">
                {/* Right Edge Track */}
                {!isCollapsed && (
                    <>
                        <div className="sidebar-edge-track"></div>

                        {/* Vertical Edge Telemetry */}
                        <div className="absolute top-1/4 -right-1 side-label-vertical opacity-20">CHASSIS_SIDE_A // PORT_8890</div>
                        <div className="absolute bottom-1/4 -right-1 side-label-vertical opacity-20">NODE_AUTH_SIG // RATING_S</div>

                        {/* Corner Decorative HUDs */}
                        <div className="absolute top-0 right-0 w-8 h-8 border-t-2 border-r-2 border-teal-500/20 opacity-40"></div>
                        <div className="absolute top-0 right-0 w-2 h-2 bg-teal-500/40"></div>
                        <div className="absolute bottom-0 right-0 w-8 h-8 border-b-2 border-r-2 border-teal-500/10 opacity-20"></div>
                    </>
                )}
            </div>

            {/* Scanning Grid Background */}
            <div className="absolute inset-0 opacity-[0.02] pointer-events-none z-0 bg-[linear-gradient(rgba(20,184,166,0.1)_1px,transparent_1px),linear-gradient(90deg,rgba(20,184,166,0.1)_1px,transparent_1px)] bg-[length:40px_40px]"></div>

            <div className={`w-full h-full flex flex-col min-h-0 transition-opacity duration-300 ${isCollapsed ? 'opacity-0' : 'opacity-100'}`}>
                {/* Header */}
                <div className="sidebar-header border-b border-white/5 bg-black/60 backdrop-blur-3xl py-4 px-4 relative overflow-hidden flex items-center justify-between shrink-0">
                    <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-teal-500/40 to-transparent"></div>
                    <div className="absolute bottom-0 left-0 w-full h-[1px] bg-white/[0.02]"></div>

                    <div className={`flex items-center gap-4 transition-opacity duration-300 ${isCollapsed ? 'opacity-0 w-0 overflow-hidden' : 'opacity-100'}`}>
                        <div className="relative shrink-0 group/logo">
                            <div className="w-12 h-12 rounded-sm bg-black border border-white/10 flex items-center justify-center relative overflow-hidden cyber-card-hud" onMouseEnter={playTick}>
                                <div className="absolute inset-0 bg-teal-500/5 hologram-flicker"></div>
                                <Shield size={24} className="text-teal-500 drop-shadow-[0_0_15px_rgba(20,184,166,0.5)] z-10" />
                                <div className="corner-tl !border-teal-500/40"></div>
                                <div className="corner-br !border-teal-500/40"></div>
                                <div className="absolute inset-0 bg-gradient-to-t from-teal-500/10 to-transparent opacity-0 group-hover/logo:opacity-100 transition-opacity"></div>
                            </div>
                            <div className="absolute -bottom-1 -right-1 w-4 h-4 bg-teal-500 rounded-full border-2 border-[#050508] shadow-[0_0_10px_rgba(20,184,166,0.6)] z-20 flex items-center justify-center animate-pulse">
                                <div className="w-1.5 h-1.5 bg-white rounded-full"></div>
                            </div>
                        </div>
                        <div className="overflow-hidden">
                            <h1 className="text-xl font-black tracking-[0.25em] text-white leading-none uppercase flex items-center gap-2">
                                {statsData.identity.name}
                                <span className="text-[7px] px-1 py-0.5 rounded-sm bg-white/5 border border-white/10 text-slate-500 font-mono">SYS_CORE</span>
                            </h1>
                            <div className="flex items-center gap-2 mt-2">
                                <div className="w-1 h-2 bg-teal-500/30"></div>
                                <p className="text-[8px] text-teal-500 font-extrabold uppercase tracking-[0.4em] opacity-90 whitespace-nowrap">
                                    V1.1.6 // {statsData.identity.org.toUpperCase()}
                                </p>
                            </div>
                        </div>
                    </div>

                    {/* Tactical Collapse Switch */}
                    <motion.button
                        whileHover={{ scale: 1.05 }}
                        whileTap={{ scale: 0.95 }}
                        onClick={onToggleCollapse}
                        className="relative flex items-center justify-center w-8 h-8 rounded-sm bg-black border border-white/10 hover:border-teal-500/50 hover:bg-teal-500/5 transition-all group/collapse notched-border"
                        title="Collapse Neural Matrix"
                    >
                        <div className="absolute inset-0 bg-teal-500/5 opacity-0 group-hover/collapse:opacity-100 transition-opacity"></div>
                        <ChevronLeft
                            size={14}
                            className={`text-slate-500 group-hover/collapse:text-teal-400 transition-all duration-500 ${isCollapsed ? 'rotate-180' : ''}`}
                        />
                        {/* Status Marker */}
                        <div className="absolute -top-0.5 -right-0.5 w-1.5 h-1.5 bg-teal-500/40 rounded-full border border-teal-500/60 shadow-[0_0_5px_rgba(20,184,166,0.5)]"></div>

                        {/* Industrial Label HUD (Tooltip-ish) */}
                        <div className="absolute left-[-110px] opacity-0 group-hover/collapse:opacity-100 transition-opacity pointer-events-none hidden xl:block">
                            <span className="text-[7px] font-black text-teal-500/60 uppercase tracking-[0.2em] whitespace-nowrap bg-black/80 px-2 py-1 border border-teal-500/20 notched-border">
                                [ NODE_SWITCH_A ]
                            </span>
                        </div>
                    </motion.button>
                </div>

                <div className="flex-1 sidebar-content custom-scrollbar-minimal overflow-x-hidden overflow-y-auto min-h-0 pb-10">
                    <div className="section-container border-b border-white/[0.03]">
                        <SectionHeader
                            label="Neural Tunnel"
                            isOpen={openSections.vpn}
                            onToggle={() => toggleSection('vpn')}
                        />
                        <AnimatePresence>
                            {openSections.vpn && (
                                <motion.div
                                    initial={{ height: 0, opacity: 0 }}
                                    animate={{ height: 'auto', opacity: 1 }}
                                    exit={{ height: 0, opacity: 0 }}
                                    className="overflow-hidden"
                                >
                                    <div className="px-4 pb-2 space-y-4">
                                        <VpnController
                                            vpnStatus={vpnStatus}
                                            vpnNodes={vpnNodes}
                                            onToggle={toggleVpn}
                                        />


                                    </div>
                                </motion.div>
                            )}
                        </AnimatePresence>
                    </div>

                    <div className="section-container border-b border-white/[0.03]">
                        <SectionHeader
                            label="Security Posture"
                            isOpen={openSections.posture}
                            onToggle={() => toggleSection('posture')}
                        />
                        <AnimatePresence>
                            {openSections.posture && (
                                <motion.div
                                    initial={{ height: 0, opacity: 0 }}
                                    animate={{ height: 'auto', opacity: 1 }}
                                    exit={{ height: 0, opacity: 0 }}
                                    className="overflow-hidden px-4 pb-6"
                                >
                                    <div className="space-y-4">
                                        <div className="flex justify-center scale-90 origin-top -mb-4">
                                            <HealthGauge value={statsData.integrity} label="System Integrity" />
                                        </div>
                                        <div className="space-y-2 pt-2 border-t border-white/[0.05]">
                                            <ResourceBar label="Neural CPU" value={statsData.metrics.cpu} />
                                            <ResourceBar label="Buffer RAM" value={statsData.metrics.ram} colorClass="bg-purple-500/60" />
                                            <ResourceBar label="Storage Disk" value={statsData.metrics.disk || 0} colorClass="bg-amber-600/60" />
                                        </div>

                                        <div className="pt-2 space-y-1.5 opacity-60">
                                            <div className="flex items-center justify-between text-[8px] font-mono leading-none">
                                                <span className="text-slate-600">KERN:</span>
                                                <span className="text-slate-400 truncate max-w-[120px]">{statsData.os}</span>
                                            </div>
                                            <div className="flex items-center justify-between text-[8px] font-mono leading-none">
                                                <span className="text-slate-600">ADDR:</span>
                                                <span className="text-teal-500/80">{statsData.ip}</span>
                                            </div>
                                            <div className="flex items-center justify-between text-[8px] font-mono leading-none">
                                                <span className="text-slate-600">UP:</span>
                                                <span className="text-slate-400">{statsData.uptime}</span>
                                            </div>
                                        </div>
                                    </div>
                                </motion.div>
                            )}
                        </AnimatePresence>
                    </div>

                    <div className="section-container border-b border-white/[0.03]">
                        <SectionHeader
                            label="Component Audit"
                            isOpen={openSections.audit}
                            onToggle={() => toggleSection('audit')}
                        />
                        <AnimatePresence>
                            {openSections.audit && (
                                <motion.div
                                    initial={{ height: 0, opacity: 0 }}
                                    animate={{ height: 'auto', opacity: 1 }}
                                    exit={{ height: 0, opacity: 0 }}
                                    className="overflow-hidden px-4 pb-3"
                                >
                                    <div className="space-y-4">
                                        <div className="space-y-0.5">
                                            <StatusItem label="Neural Core" status={statsData.components.agent} icon={Cpu} />
                                            <StatusItem label="Knowledge Base" status={statsData.components.rag} icon={Shield} />
                                            <StatusItem label="I/O Protocol" status={statsData.components.mcp} icon={Terminal}>
                                                <button
                                                    onClick={handleRunScan}
                                                    disabled={isScanning}
                                                    className={`p-1 rounded bg-teal-500/10 border border-teal-500/20 text-teal-500 transition-all ${isScanning ? 'animate-spin opacity-50' : 'hover:bg-teal-500/20'}`}
                                                >
                                                    <RefreshCw size={8} />
                                                </button>
                                            </StatusItem>
                                        </div>

                                        <div className="bg-white/[0.02] border border-white/5 p-3 rounded-lg space-y-2">
                                            <div className="flex justify-between items-center px-1">
                                                <span className="text-[7px] font-mono text-slate-500 uppercase tracking-widest">COMPLIANCE_SYNC</span>
                                                <div className={`px-2 py-0.5 rounded-full text-[8px] font-black ${complianceReport?.score > 80 ? 'bg-teal-500/10 text-teal-400' : 'bg-red-500/10 text-red-500'}`}>
                                                    {complianceReport?.score || 0}%
                                                </div>
                                            </div>
                                            <div className="flex justify-between items-center text-[8px] font-mono">
                                                <span className="text-slate-600">TIER:</span>
                                                <span className="text-slate-300 font-extrabold">{complianceReport?.tier || 'UNKNOWN'}</span>
                                            </div>
                                            <button className="w-full py-1.5 mt-1 bg-white/[0.03] border border-white/5 hover:border-teal-500/30 text-[8px] font-black text-slate-500 hover:text-teal-400 uppercase tracking-[0.2em] transition-all rounded">
                                                GENERATE_ISO_LOG
                                            </button>
                                        </div>
                                    </div>
                                </motion.div>
                            )}
                        </AnimatePresence>
                    </div>

                    <div className="section-container border-b border-white/[0.03]">
                        <SectionHeader
                            label="Shadow Sessions"
                            isOpen={openSections.sessions}
                            onToggle={() => toggleSection('sessions')}
                        />
                        <AnimatePresence>
                            {openSections.sessions && (
                                <motion.div
                                    initial={{ height: 0, opacity: 0 }}
                                    animate={{ height: 'auto', opacity: 1 }}
                                    exit={{ height: 0, opacity: 0 }}
                                    className="overflow-hidden px-4 pb-3"
                                >
                                    <div className="space-y-1.5 pr-1">
                                        {systemSessions.length > 0 ? (
                                            systemSessions.map((s, i) => (
                                                <div key={i} className="flex items-center justify-between py-2 px-2.5 rounded bg-white/[0.02] border border-white/[0.03] hover:border-purple-500/20 transition-colors">
                                                    <div className="flex items-center gap-2.5">
                                                        <div className="w-1.5 h-1.5 rounded-full bg-purple-500/50"></div>
                                                        <span className="text-[9px] font-bold text-slate-400 uppercase">{s.user}</span>
                                                    </div>
                                                    <span className="text-[8px] font-mono text-slate-600 truncate max-w-[80px]">{s.host || s.terminal}</span>
                                                </div>
                                            ))
                                        ) : (
                                            <p className="text-[8px] text-center text-slate-600 uppercase py-4 border border-dashed border-white/5 rounded-lg">Isolated</p>
                                        )}
                                    </div>
                                </motion.div>
                            )}
                        </AnimatePresence>
                    </div>

                    <div className="section-container border-b border-white/[0.03]">
                        <SectionHeader
                            label="Active Alerts"
                            isOpen={openSections.alerts}
                            onToggle={() => toggleSection('alerts')}
                            action={
                                securityAlerts.length > 0 && (
                                    <button
                                        id="purge-alerts-btn"
                                        onClick={(e) => {
                                            e.stopPropagation();
                                            console.log('[SIDEBAR] Purge requested via UI');
                                            playChirp();
                                            onClearAlerts();
                                        }}
                                        className="relative z-[100] px-3 py-1.5 rounded-sm bg-red-500/10 border border-red-500/30 text-red-500 hover:bg-red-500/20 hover:border-red-500/50 transition-all group-hover/header:opacity-100 opacity-80 flex items-center gap-2 notched-border"
                                        title="Purge Intelligence Logs"
                                    >
                                        <Trash2 size={10} />
                                        <span className="text-[8px] font-black uppercase tracking-[0.2em]">PURGE_INTEL</span>
                                    </button>
                                )
                            }
                        />
                        <AnimatePresence>
                            {openSections.alerts && (
                                <motion.div
                                    initial={{ height: 0, opacity: 0 }}
                                    animate={{ height: 'auto', opacity: 1 }}
                                    exit={{ height: 0, opacity: 0 }}
                                    className="overflow-hidden px-4 pb-3"
                                >
                                    <div className="space-y-2 pr-1">
                                        {securityAlerts.length > 0 ? (
                                            securityAlerts.map((alert, i) => (
                                                <div key={alert.id || i} className="p-2.5 rounded border border-red-500/10 bg-red-500/[0.02]">
                                                    <div className="flex items-start gap-2.5">
                                                        <AlertCircle size={10} className="text-red-500 mt-0.5" />
                                                        <div className="space-y-0.5">
                                                            <p className="text-[9px] font-bold text-red-400 uppercase leading-snug">{alert.message}</p>
                                                            <p className="text-[7px] font-mono text-slate-600 uppercase">{new Date(alert.timestamp).toLocaleTimeString()}</p>
                                                        </div>
                                                    </div>
                                                </div>
                                            ))
                                        ) : (
                                            <div className="py-4 text-center border border-dashed border-white/5 rounded bg-black/10">
                                                <span className="text-[8px] text-slate-700 font-black uppercase tracking-widest">Clear</span>
                                            </div>
                                        )}
                                        <button
                                            onClick={handleIsolationToggle}
                                            className={`w-full group relative overflow-hidden flex items-center justify-center gap-3 py-3 mt-4 rounded-sm border transition-all duration-500 notched-border ${isIsolated
                                                ? 'bg-red-500/20 border-red-500 text-red-500 shadow-[0_0_20px_rgba(239,68,68,0.2)]'
                                                : 'bg-teal-500/5 border-teal-500/20 text-teal-600 hover:border-teal-500/50 hover:bg-teal-500/10'
                                                }`}
                                        >
                                            <ShieldAlert size={12} className={isIsolated ? 'animate-pulse' : ''} />
                                            <span className="text-[9px] font-black uppercase tracking-[0.4em]">
                                                {isIsolated ? '[ ISOLATED ]' : '[ LOCKDOWN_NODE ]'}
                                            </span>
                                            <div className="absolute inset-0 bg-white/5 opacity-0 group-hover:opacity-100 transition-opacity"></div>
                                        </button>
                                    </div>
                                </motion.div>
                            )}
                        </AnimatePresence>
                    </div>

                    <div className="section-container border-b border-white/[0.03]">
                        <SectionHeader
                            label="Asset Inventory"
                            isOpen={openSections.assets}
                            onToggle={() => toggleSection('assets')}
                        />
                        <AnimatePresence>
                            {openSections.assets && (
                                <motion.div
                                    initial={{ height: 0, opacity: 0 }}
                                    animate={{ height: 'auto', opacity: 1 }}
                                    exit={{ height: 0, opacity: 0 }}
                                    className="overflow-hidden px-4 pb-3"
                                >
                                    <div className="flex items-center justify-between mb-4 px-1">
                                        <div className="text-[7px] font-mono text-slate-600 uppercase tracking-widest">ASSET_VAULT</div>
                                        <button
                                            onClick={handleRefresh}
                                            className="px-2 py-0.5 hover:bg-teal-500/10 rounded border border-white/5 hover:border-teal-500/20 transition-all text-slate-600 hover:text-teal-400 text-[8px] font-black tracking-widest uppercase"
                                        >
                                            SYNC_NODE
                                        </button>
                                    </div>

                                    <div className="space-y-2 pr-1">
                                        {generatedFiles.length > 0 ? (
                                            generatedFiles.map((file, i) => (
                                                <div key={i} className="group flex items-center justify-between px-2.5 py-2 rounded border border-white/[0.03] hover:border-teal-500/20 bg-white/[0.01] transition-all duration-300">
                                                    <div className="flex items-center gap-2.5 overflow-hidden flex-1">
                                                        {getFileIcon(file.name, file.type)}
                                                        <div className="flex flex-col overflow-hidden flex-1">
                                                            {editingFile === file.name ? (
                                                                <input
                                                                    autoFocus
                                                                    className="bg-black/40 border border-teal-500/50 text-[9px] text-white px-1 py-0.5 rounded outline-none font-bold uppercase"
                                                                    value={newName}
                                                                    onChange={(e) => setNewName(e.target.value)}
                                                                    onBlur={() => handleRenameSubmit(file.name)}
                                                                    onKeyDown={(e) => {
                                                                        if (e.key === 'Enter') handleRenameSubmit(file.name);
                                                                        if (e.key === 'Escape') setEditingFile(null);
                                                                    }}
                                                                />
                                                            ) : (
                                                                <span
                                                                    className="text-[9px] text-slate-400 truncate font-bold uppercase cursor-pointer hover:text-teal-400 transition-colors"
                                                                    title={file.name}
                                                                    onClick={() => handlePreview(file)}
                                                                >
                                                                    {file.name}
                                                                </span>
                                                            )}
                                                            <span className="text-[7px] text-slate-600 font-mono tracking-tighter">
                                                                {formatSize(file.size)} // {getFileIconDetails(file.name, file.type).label}
                                                            </span>
                                                        </div>
                                                    </div>
                                                    <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-all shrink-0">
                                                        <button
                                                            onClick={(e) => { e.stopPropagation(); handlePreview(file); }}
                                                            className="p-1 hover:bg-teal-500/20 rounded text-slate-600 hover:text-teal-400"
                                                            title="Preview Asset"
                                                        >
                                                            <Eye size={12} />
                                                        </button>
                                                        <button
                                                            onClick={(e) => { e.stopPropagation(); handleRenameStart(file); }}
                                                            className="p-1 hover:bg-teal-500/20 rounded text-slate-600 hover:text-teal-400"
                                                            title="Rename Asset"
                                                        >
                                                            <Edit3 size={12} />
                                                        </button>
                                                        <button
                                                            onClick={(e) => { e.stopPropagation(); handleDownload(file.name); }}
                                                            className="p-1 hover:bg-teal-500/20 rounded text-slate-600 hover:text-teal-400"
                                                            title="Download Link"
                                                        >
                                                            <Download size={12} />
                                                        </button>
                                                        <button
                                                            onClick={(e) => { e.stopPropagation(); handleDelete(file.name); }}
                                                            className="p-1 hover:bg-red-500/20 rounded text-slate-600 hover:text-red-400"
                                                            title="Erase Asset"
                                                        >
                                                            <Trash2 size={12} />
                                                        </button>
                                                    </div>
                                                </div>
                                            ))
                                        ) : (
                                            <div className="py-8 flex flex-col items-center justify-center border border-dashed border-white/5 rounded-lg bg-black/10">
                                                <Activity size={12} className="text-slate-800 mb-2 opacity-30" />
                                                <span className="text-[8px] text-slate-800 font-bold uppercase tracking-[0.2em]">VAULT_VACANT</span>
                                            </div>
                                        )}
                                    </div>
                                </motion.div>
                            )}
                        </AnimatePresence>
                    </div>

                    <div className="section-container border-b border-white/[0.03]">
                        <SectionHeader
                            label="Telemetry Flux"
                            isOpen={openSections.telemetry}
                            onToggle={() => toggleSection('telemetry')}
                        />
                        <AnimatePresence>
                            {openSections.telemetry && (
                                <motion.div
                                    initial={{ height: 0, opacity: 0 }}
                                    animate={{ height: 'auto', opacity: 1 }}
                                    exit={{ height: 0, opacity: 0 }}
                                    className="overflow-hidden px-4 pb-3"
                                >
                                    <div className="glitch-logs bg-black/40 border border-white/5 rounded-lg p-3 select-none overflow-hidden">
                                        {logs.length > 0 ? (
                                            <div className="space-y-1.5">
                                                {logs.slice(-10).map((log, i) => (
                                                    <div key={i} className="flex gap-2 group/log border-b border-white/[0.01] pb-1 last:border-0">
                                                        <span className="text-[7px] text-teal-900 font-mono opacity-50">
                                                            {new Date().toLocaleTimeString([], { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                                                        </span>
                                                        <p className="text-[8px] text-teal-500/70 font-mono truncate group-hover/log:text-teal-400 transition-colors">
                                                            {log.toUpperCase()}
                                                        </p>
                                                    </div>
                                                ))}
                                            </div>
                                        ) : (
                                            <div className="text-[8px] text-slate-800 font-black tracking-widest uppercase text-center py-4">FLUX_IDLE</div>
                                        )}
                                    </div>
                                </motion.div>
                            )}
                        </AnimatePresence>
                    </div>
                </div>

                {/* Footer */}
                <div className="sidebar-footer p-4 bg-black/80 border-t border-white/5 space-y-2 shrink-0 relative">
                    <div className="absolute top-0 left-0 w-full h-[1px] bg-white/[0.02]"></div>
                    <div className="flex flex-col gap-2">
                        <button
                            onClick={() => onOpenSettings('documentation')}
                            onMouseEnter={playTick}
                            className="w-full flex items-center justify-center gap-2 py-3 rounded-sm border border-teal-500/20 bg-teal-500/5 hover:bg-teal-500/10 text-[9px] font-black uppercase tracking-[0.3em] text-teal-500 transition-all notched-border group/btn"
                            title="System Documentation"
                        >
                            <Book size={12} className="group-hover/btn:scale-110 transition-transform" />
                            DOCUMENTATION
                        </button>
                        <div className="flex gap-2">
                            <button
                                onClick={onOpenSettings}
                                onMouseEnter={playTick}
                                className="flex-1 flex items-center justify-center gap-2 py-3 rounded-sm border border-white/5 hover:border-teal-500/40 bg-white/[0.01] hover:bg-teal-500/[0.05] text-[9px] font-black uppercase tracking-[0.3em] text-slate-600 hover:text-teal-400 transition-all notched-border group/btn"
                                title="Configure API Keys"
                            >
                                <Settings size={12} className="group-hover/btn:rotate-90 transition-transform" />
                                SETTINGS
                            </button>
                            <button
                                onClick={() => {
                                    console.log('[SIDEBAR] Neural reset requested');
                                    onClearMessages();
                                }}
                                onMouseEnter={playTick}
                                className="flex-1 flex items-center justify-center gap-2 py-3 rounded-sm border border-white/5 hover:border-red-500/40 bg-white/[0.01] hover:bg-red-500/[0.05] text-[9px] font-black uppercase tracking-[0.3em] text-slate-600 hover:text-red-500 transition-all notched-border group/btn"
                                title="Reset Neural History"
                            >
                                <Trash2 size={12} className="group-hover/btn:scale-110 transition-transform" />
                                PURGE
                            </button>
                        </div>
                    </div>
                </div>
            </div>
        </aside >
    );
};

export default React.memo(Sidebar);
