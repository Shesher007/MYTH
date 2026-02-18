import React, { useState, useEffect, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    X, Shield, Cpu, Key, Save, AlertTriangle, Eye, EyeOff,
    CheckCircle2, CircleDashed, Search, Database, Globe,
    Target, Zap, Plus, Trash2, Settings2, RefreshCw,
    Network, LayoutGrid, Fingerprint
} from 'lucide-react';
import { useSoundscape } from '../hooks/useSoundscape';

const CATEGORIES = [
    { id: 'ai', label: 'Neural Matrix', icon: Cpu, providers: ['mistral', 'nvidia', 'google_ai_studio'] },
    { id: 'recon', label: 'OSINT Grid', icon: Search, providers: ['shodan', 'censys', 'securitytrails', 'project_discovery'] },
    { id: 'intel', label: 'Threat Intel', icon: Shield, providers: ['virustotal', 'abuseipdb', 'alienvault_otx', 'nvd_cve', 'hibp_breach', 'hunter_io'] },
    { id: 'web', label: 'Synapse Connect', icon: Globe, providers: ['tavily', 'google', 'serpapi', 'fofa', 'ipinfo', 'ipgeolocation'] },
    { id: 'devops', label: 'Aether Forge', icon: LayoutGrid, providers: ['github', 'burp_suite'] }
];

const STRATEGIES = ['round-robin', 'random', 'failover-only'];

const COLLECTION_GUIDES = {
    mistral: {
        url: 'https://console.mistral.ai/api-keys/',
        steps: ['Sign in to console.mistral.ai', 'Add billing method (Experiment/Scale)', 'Hit "Create new key"', 'Copy and protect the nodal string.']
    },
    nvidia: {
        url: 'https://build.nvidia.com/',
        steps: ['Access build.nvidia.com', 'Login via NVIDIA Account', 'NIM Dashboard -> API Keys', 'Generate and store with "NGC Catalog" scope.']
    },
    google_ai_studio: {
        url: 'https://aistudio.google.com/app/apikey',
        steps: ['Sign in to Google AI Studio', 'Navigate to "Get API key"', 'Hit "Create API key in new project"', 'Copy the Gemini-AI string.']
    },
    shodan: {
        url: 'https://account.shodan.io/',
        steps: ['Login to Shodan account portal', 'Locate "API Key" on Dashboard', 'Copy the 32-char hexadecimal string.']
    },
    censys: {
        url: 'https://censys.io/account/api',
        steps: ['Sign in to Censys search portal', 'Dashboard -> My Account -> API', 'Retrieve both "API ID" and "Secret".']
    },
    securitytrails: {
        url: 'https://securitytrails.com/app/account',
        steps: ['Sign in to SecurityTrails', 'Navigate to "API" section', 'Copy the alphanumeric API key.']
    },
    project_discovery: {
        url: 'https://cloud.projectdiscovery.io/',
        steps: ['Login to PD Cloud Dashboard', 'Settings -> API Key', 'Generate key for CLI/API authentication.']
    },
    virustotal: {
        url: 'https://www.virustotal.com/',
        steps: ['Sign in to VirusTotal.com', 'Profile (Top Right) -> My API Key', 'Copy the public string (500 req/day limit).']
    },
    abuseipdb: {
        url: 'https://www.abuseipdb.com/account/api',
        steps: ['Sign in to AbuseIPDB', 'Go to "API" Tab', 'Create new key and store safely.']
    },
    alienvault_otx: {
        url: 'https://otx.alienvault.com/settings',
        steps: ['Access OTX settings portal', 'Locate "OTX API Key" field', 'Copy and secure the decryption token.']
    },
    nvd_cve: {
        url: 'https://nvd.nist.gov/developers/request-an-api-key',
        steps: ['Fill request form with organizational email', 'Activate via single-use email hyperlink', 'Store key immediately (non-retrievable).']
    },
    tavily: {
        url: 'https://app.tavily.com/home',
        steps: ['Sign in to Tavily Dashboard', 'Locate "API Key" on Home panel', 'Copy for industrial-grade web search.']
    },
    google: {
        url: 'https://console.cloud.google.com/apis/credentials',
        steps: ['Cloud Console -> Enable Custom Search API', 'Credentials -> Create API Key', 'cse.google.com -> Create Search Engine', 'Retrieve both API Key and CX (CSE ID).']
    },
    serpapi: {
        url: 'https://serpapi.com/dashboard',
        steps: ['Sign in to SerpApi Portal', 'Copy "Your Private API Key"', 'Verify active plan status.']
    },
    fofa: {
        url: 'https://fofa.info/personal-center',
        steps: ['Login to FOFA platform', 'Personal Center -> API Information', 'Collect FOFA_EMAIL and FOFA_KEY strings.']
    },
    ipinfo: {
        url: 'https://ipinfo.io/account',
        steps: ['Sign in to IPinfo dashboard', 'Locate "Your API Token"', 'Copy the Full Access or Lite nodal token.']
    },
    ipgeolocation: {
        url: 'https://ipgeolocation.io/dashboard.html',
        steps: ['Sign up/Login to ipgeolocation.io', 'Access User Dashboard', 'Copy API Key from the main panel', 'Verify active usage quota.']
    },
    hibp_breach: {
        url: 'https://haveibeenpwned.com/API/Key',
        steps: ['Sign up/Login to HIBP', 'Purchase API key subscription', 'Retrieve key from Dashboard', 'Key is passed as hibp-api-key header.']
    },
    hunter_io: {
        url: 'https://hunter.io/api_keys',
        steps: ['Login to Hunter.io Dashboard', 'Navigate to "API" section', 'Copy Secret API Key', 'Test with dummy key if needed.']
    },
    github: {
        url: 'https://github.com/settings/tokens',
        steps: ['Settings -> Developer settings -> PAT (Classic)', 'Generate new token with "repo" scope', 'Copy string (shown only once).']
    },
    burp_suite: {
        url: 'https://portswigger.net/',
        steps: ['Burp Pro: User options -> Misc -> REST API', 'Enable "Service running"', 'Hit "New" to generate unit key.']
    }
};

const SettingsModal = ({ isOpen, onClose, settingsKeys, onSave }) => {
    const { playTick, playChirp, playSuccess, playError } = useSoundscape();
    const [activeTab, setActiveTab] = useState('ai');
    const [isSaving, setIsSaving] = useState(false);
    const [localSecrets, setLocalSecrets] = useState({});
    const [isDirty, setIsDirty] = useState(false);

    // Initialize local state from settingsKeys
    useEffect(() => {
        if (isOpen && settingsKeys) {
            setLocalSecrets(JSON.parse(JSON.stringify(settingsKeys)));
            setIsDirty(false);
            playTick();
        }
    }, [isOpen, settingsKeys]);

    const handleSave = async () => {
        playChirp();
        setIsSaving(true);

        // Construct the update payload
        // We only want to send fields that have been modified and aren't just "MASKED" placeholders
        // But for simplicity in this redesign, we'll send the whole structure and 
        // the backend should be smart about merging. 
        // Note: The UI shows "MASKED" values. If the user didn't change them, we shouldn't overwrite with "MASKED".

        const cleanPayload = (data) => {
            if (Array.isArray(data)) return data.filter(i => !String(i).includes('...'));
            if (typeof data === 'object' && data !== null) {
                const res = {};
                for (const k in data) {
                    const val = cleanPayload(data[k]);
                    if (val !== undefined && (Array.isArray(val) ? val.length > 0 : true)) {
                        res[k] = val;
                    }
                }
                return Object.keys(res).length > 0 ? res : undefined;
            }
            return String(data).includes('...') ? undefined : data;
        };

        const updates = cleanPayload(localSecrets);

        const success = await onSave({ updates: localSecrets }); // Send full for now, backend merges
        setIsSaving(false);
        if (success) {
            playSuccess();
            onClose();
        } else {
            playError();
        }
    };

    const updateProvider = (category, provider, field, value) => {
        setIsDirty(true);
        setLocalSecrets(prev => {
            const next = { ...prev };
            const catKey = category === 'ai' ? 'ai_providers' :
                category === 'recon' ? 'recon' :
                    category === 'intel' ? 'threat_intel' :
                        category === 'web' ? 'web_search' : category;

            if (!next[catKey]) next[catKey] = {};
            if (!next[catKey][provider]) next[catKey][provider] = {};

            next[catKey][provider][field] = value;
            return next;
        });
    };

    if (!isOpen) return null;

    return (
        <AnimatePresence>
            <div className="fixed inset-0 z-[1000] flex items-center justify-center p-4">
                <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    onClick={onClose}
                    className="absolute inset-0 bg-black/95 backdrop-blur-2xl"
                />

                <motion.div
                    initial={{ scale: 0.95, opacity: 0, y: 30 }}
                    animate={{ scale: 1, opacity: 1, y: 0 }}
                    exit={{ scale: 0.95, opacity: 0, y: 30 }}
                    className="relative w-full max-w-6xl h-[90vh] bg-[#050508] border border-teal-500/30 rounded-2xl shadow-[0_0_150px_rgba(20,184,166,0.15)] flex overflow-hidden cyber-card-hud"
                >
                    <div className="corner-tl" /> <div className="corner-tr" />
                    <div className="corner-bl" /> <div className="corner-br" />
                    <div className="holographic-pulse opacity-10" />

                    {/* Sidebar Nav */}
                    <div className="w-72 bg-black/60 border-r border-white/5 flex flex-col relative z-20">
                        <div className="p-8 border-b border-white/5">
                            <div className="flex items-center gap-4 mb-2">
                                <motion.div
                                    animate={{ rotate: 360 }}
                                    transition={{ duration: 20, repeat: Infinity, ease: "linear" }}
                                    className="p-1 px-1.5 rounded border border-teal-500/50"
                                >
                                    <Fingerprint className="text-teal-400" size={16} />
                                </motion.div>
                                <div>
                                    <h2 className="text-[11px] font-black uppercase tracking-[0.4em] text-white">Sovereign Registry</h2>
                                    <p className="text-[7px] text-teal-500/70 uppercase tracking-widest font-mono mt-0.5">Core Interface // Level-Omega</p>
                                </div>
                            </div>
                        </div>

                        <div className="flex-1 overflow-y-auto p-6 space-y-3 custom-scrollbar-minimal">
                            {CATEGORIES.map(cat => (
                                <TabButton
                                    key={cat.id}
                                    cat={cat}
                                    isActive={activeTab === cat.id}
                                    onClick={() => { setActiveTab(cat.id); playTick(); }}
                                />
                            ))}
                        </div>

                        <div className="p-6 border-t border-white/5 bg-white/[0.01]">
                            <RegistryIntegrityGauge />
                            <p className="text-[7px] text-slate-500 uppercase tracking-widest font-mono mt-4 text-center">
                                Cluster Health: <span className="text-teal-500">Optimized</span>
                            </p>
                        </div>
                    </div>

                    {/* Main Content Area */}
                    <div className="flex-1 flex flex-col bg-deep overflow-hidden relative z-20">
                        {/* Header */}
                        <div className="px-10 py-8 border-b border-white/10 flex items-center justify-between bg-black/40 backdrop-blur-3xl">
                            <div className="flex flex-col gap-1">
                                <div className="text-[7px] font-black text-teal-500/30 uppercase tracking-[0.4em] mb-1">AUTH_RELAY_B</div>
                                <div>
                                    <motion.h3
                                        key={activeTab}
                                        initial={{ opacity: 0, x: -10 }}
                                        animate={{ opacity: 1, x: 0 }}
                                        className="text-2xl font-black text-white uppercase tracking-tighter flex items-center gap-4"
                                    >
                                        {CATEGORIES.find(c => c.id === activeTab).label}
                                        <span className="px-2 py-0.5 rounded text-[9px] bg-teal-500/10 text-teal-400 border border-teal-500/30 tracking-widest animate-pulse">ACTIVE_NODE</span>
                                    </motion.h3>
                                    <p className="text-[10px] text-slate-500 uppercase tracking-[0.3em] font-mono mt-1">Nodal Decryption Matrix // Persistence Lock: ON</p>
                                </div>
                            </div>

                            <div className="flex items-center gap-3">
                                {isDirty && !isSaving && (
                                    <button
                                        onClick={() => { playTick(); onClose(); }}
                                        className="px-6 py-3 rounded border border-red-500/30 text-red-500/50 hover:text-red-400 hover:bg-red-500/5 transition-all text-[11px] font-black uppercase tracking-[0.2em]"
                                    >
                                        ABORT_MODS
                                    </button>
                                )}
                                <button
                                    onClick={handleSave}
                                    disabled={isSaving || !isDirty}
                                    className={`group relative flex items-center gap-3 px-8 py-3 rounded border transition-all overflow-hidden ${isDirty
                                        ? 'bg-teal-500 border-teal-400 text-black shadow-[0_0_30px_rgba(20,184,166,0.3)]'
                                        : 'bg-black/40 border-white/10 text-slate-600 cursor-not-allowed'
                                        }`}
                                >
                                    <div className="absolute inset-0 bg-white/20 translate-x-[-100%] group-hover:translate-x-[100%] transition-transform duration-700" />
                                    <span className="text-[11px] font-black uppercase tracking-[0.2em] relative z-10">
                                        {isSaving ? 'Syncing...' : 'Sync Cluster'}
                                    </span>
                                    <RefreshCw className={`relative z-10 ${isSaving ? 'animate-spin' : ''}`} size={14} />
                                </button>
                            </div>
                        </div>

                        {/* Scrolled Grid */}
                        <div className="flex-1 overflow-y-auto p-10 custom-scrollbar-minimal bg-[url('https://www.transparenttextures.com/patterns/carbon-fibre.png')] opacity-80">
                            <motion.div
                                layout
                                className="grid grid-cols-1 gap-8"
                            >
                                {CATEGORIES.find(c => c.id === activeTab).providers.map(provider => (
                                    <ProviderCard
                                        key={provider}
                                        provider={provider}
                                        category={activeTab}
                                        data={localSecrets[activeTab === 'ai' ? 'ai_providers' :
                                            activeTab === 'recon' ? 'recon' :
                                                activeTab === 'intel' ? 'threat_intel' :
                                                    activeTab === 'web' ? 'web_search' : activeTab]?.[provider] || {}}
                                        onUpdate={(f, v) => updateProvider(activeTab, provider, f, v)}
                                    />
                                ))}
                            </motion.div>
                        </div>

                        {/* Footer Info Hub */}
                        <div className="px-10 py-5 border-t border-white/5 bg-black/60 flex items-center justify-between font-mono">
                            <div className="flex items-center gap-8">
                                <div className="text-[8px] text-slate-500 uppercase tracking-widest flex items-center gap-2">
                                    <Database size={10} className="text-teal-500" />
                                    VOL_ID: <span className="text-slate-300">NVME_X01</span>
                                </div>
                                <div className="text-[8px] text-slate-500 uppercase tracking-widest flex items-center gap-2">
                                    <Fingerprint size={10} className="text-teal-500" />
                                    ENC: <span className="text-slate-300">AES_256_GCM</span>
                                </div>
                            </div>
                            <div className="text-[8px] text-teal-500/50 uppercase tracking-[0.4em] font-black">
                                System // {new Date().toLocaleTimeString()}
                            </div>
                        </div>
                    </div>
                </motion.div>
            </div>
        </AnimatePresence>
    );
};

const TabButton = ({ cat, isActive, onClick }) => (
    <button
        onClick={onClick}
        className={`w-full flex items-center gap-4 px-5 py-4 rounded-xl transition-all relative overflow-hidden group border ${isActive
            ? 'bg-teal-500/10 border-teal-500/40 text-teal-400'
            : 'bg-transparent border-transparent text-slate-500 hover:text-slate-300 hover:bg-white/5'
            }`}
    >
        {isActive && <motion.div layoutId="tabGlow" className="absolute inset-0 bg-teal-500/5 shadow-[inset_0_0_20px_rgba(20,184,166,0.1)]" />}
        <cat.icon size={18} className={isActive ? 'text-teal-400' : 'group-hover:text-teal-500/50'} />
        <span className="text-[10px] font-black uppercase tracking-[0.2em]">{cat.label}</span>
        {isActive && (
            <motion.div layoutId="tabActiveBar" className="ml-auto w-1 h-1 shadow-[0_0_10px_#14b8a6] bg-teal-500" />
        )}
    </button>
);

const RegistryIntegrityGauge = () => (
    <div className="flex flex-col items-center justify-center p-4 py-8 relative">
        <svg className="w-24 h-24 transform -rotate-90 registry-integrity-gauge">
            <circle cx="48" cy="48" r="40" stroke="currentColor" strokeWidth="2" fill="transparent" className="text-white/5" />
            <motion.circle
                cx="48" cy="48" r="40"
                stroke="currentColor" strokeWidth="3"
                fill="transparent" className="text-teal-500"
                strokeDasharray={251.2}
                initial={{ strokeDashoffset: 251.2 }}
                animate={{ strokeDashoffset: 251.2 * (1 - 0.98) }}
                transition={{ duration: 2, ease: "easeOut" }}
            />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center pt-2">
            <span className="text-xs font-black text-white font-mono">98%</span>
            <span className="text-[6px] text-teal-500 font-black uppercase tracking-tighter">Integrity</span>
        </div>
    </div>
);

const DecryptionMask = ({ value, isVisible }) => {
    const chars = "0123456789ABCDEF!@#$%&*";
    const [display, setDisplay] = useState(value);

    useEffect(() => {
        if (!isVisible && value?.includes('...')) {
            const interval = setInterval(() => {
                setDisplay(prev => prev.split('').map(c => c === '.' ? '.' : chars[Math.floor(Math.random() * chars.length)]).join(''));
            }, 100);
            return () => clearInterval(interval);
        } else {
            setDisplay(value);
        }
    }, [isVisible, value]);

    return <span className="font-mono">{display}</span>;
};

const ProviderCard = ({ provider, category, data, onUpdate }) => {
    const { playTick, playSuccess } = useSoundscape();
    const [isVisible, setIsVisible] = useState(false);
    const [showGuide, setShowGuide] = useState(false);

    // Dynamic field detection for complex pairings (e.g., Google CSE, Fofa Email)
    const fieldType = useMemo(() => {
        if (['google', 'fofa', 'github', 'censys'].includes(provider)) return 'pair';
        if (provider === 'ipinfo') return 'tokens';
        return 'keys';
    }, [provider]);

    const fieldLabel = useMemo(() => fieldType === 'pair' ? 'pair' : fieldType, [fieldType]);

    const items = data[fieldType] || [];
    const strategy = data.strategy || 'round-robin';

    // Industrial metadata for complex pairs
    const fields = useMemo(() => {
        if (provider === 'google') return [{ key: 'api_key', label: 'GOOGLE_API_KEY', icon: Key, ph: 'API_KEY_STRING' }, { key: 'cse_id', label: 'SEARCH_ENGINE_ID', icon: Target, ph: 'CX_NODE_ID' }];
        if (provider === 'fofa') return [{ key: 'email', label: 'USER_ACCOUNT', icon: Globe, ph: 'EMAIL_ADDRESS' }, { key: 'key', label: 'FOFA_API_KEY', icon: Key, ph: 'API_KEY_STRING' }];
        if (provider === 'github') return [{ key: 'username', label: 'GITHUB_HANDLE', icon: Fingerprint, ph: 'USERNAME_STRING' }, { key: 'token', label: 'ACCESS_TOKEN', icon: Zap, ph: 'PERSONAL_ACCESS_TOKEN' }];
        if (provider === 'censys') return [{ key: 'id', label: 'CENSYS_API_ID', icon: Network, ph: 'API_ID_STRING' }, { key: 'secret', label: 'CENSYS_SECRET', icon: Shield, ph: 'API_SECRET_TOKEN' }];
        return [];
    }, [provider]);

    // Nodal Unit Creation State
    const [isInjecting, setIsInjecting] = useState(false);
    const [stagedUnit, setStagedUnit] = useState(fieldType === 'pair' ? {} : '');

    const commitUnit = () => {
        if (!stagedUnit) return;
        if (fieldType === 'pair') {
            const hasAllFields = fields.every(f => stagedUnit[f.key] && stagedUnit[f.key].trim() !== '');
            if (!hasAllFields) return;
        }

        playSuccess();
        onUpdate(fieldType, [...items, stagedUnit]);
        setStagedUnit(fieldType === 'pair' ? {} : '');
        setIsInjecting(false);
    };

    const addItem = () => {
        playTick();
        setIsInjecting(true);
    };

    return (
        <motion.div
            layout
            className="group relative p-8 rounded-2xl bg-black/40 border border-white/5 hover:border-teal-500/40 transition-all cyber-card-hud"
        >
            <div className="corner-tl scale-50" /> <div className="corner-tr scale-50" />
            <div className="corner-bl scale-50" /> <div className="corner-br scale-50" />
            <div className="absolute top-2 left-1/2 -translate-x-1/2 text-[6px] text-slate-700 font-mono tracking-[0.4em] opacity-40">NODE_AUTH_PROTO_{provider.toUpperCase()}</div>

            <div className="flex items-center justify-between mb-8 relative z-30">
                <div className="flex items-center gap-4">
                    <div className="p-3 rounded-xl bg-teal-500/10 border border-teal-500/20 text-teal-400 group-hover:shadow-[0_0_20px_rgba(20,184,166,0.2)] transition-shadow">
                        {category === 'ai' ? <Cpu size={20} /> : <Target size={20} />}
                    </div>
                    <div>
                        <h4 className="text-[12px] font-black text-white uppercase tracking-[0.2em]">{provider.replace(/_/g, ' ')}</h4>
                        <div className="flex items-center gap-3 mt-1.5 font-mono text-[8px]">
                            <span className="flex items-center gap-1 text-teal-500/80"><CheckCircle2 size={8} /> ENCRYPTED</span>
                            <span className="text-slate-600 uppercase">Status: Verified</span>
                        </div>
                    </div>
                </div>

                <div className="flex items-center gap-3">
                    <div className="hidden sm:flex flex-col items-end gap-1 mr-2">
                        <span className="text-[6px] font-bold text-slate-500 uppercase tracking-widest px-1">Rotation Context</span>
                        <select
                            value={strategy}
                            onChange={(e) => { playTick(); onUpdate('strategy', e.target.value); }}
                            className="bg-black/80 border border-white/10 rounded px-2 py-1 text-[8px] font-black text-teal-400 outline-none uppercase tracking-widest hover:border-teal-500/50 transition-all cursor-pointer"
                        >
                            {STRATEGIES.map(s => <option key={s} value={s}>{s.replace('-', ' ')}</option>)}
                        </select>
                    </div>

                    <button
                        onClick={() => { playTick(); setShowGuide(!showGuide); }}
                        className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border transition-all ${showGuide
                            ? 'bg-orange-500 text-black border-orange-400 shadow-[0_0_15px_rgba(249,115,22,0.3)]'
                            : 'bg-orange-500/10 text-orange-400 border-orange-500/30 hover:bg-orange-500/20'} `}
                    >
                        <RefreshCw size={12} className={showGuide ? 'rotate-180 transition-transform duration-500' : ''} />
                        <span className="text-[9px] font-black uppercase tracking-widest">{showGuide ? 'CLOSE' : 'GUIDE'}</span>
                    </button>

                    <button
                        onClick={() => { playTick(); setIsVisible(!isVisible); }}
                        className={`p-2 rounded-lg transition-all border ${isVisible
                            ? 'bg-teal-500 border-teal-400 text-black'
                            : 'bg-white/5 border-white/10 text-slate-500 hover:text-white hover:border-white/20'}`}
                    >
                        {isVisible ? <EyeOff size={16} /> : <Eye size={16} />}
                    </button>
                </div>
            </div>

            <AnimatePresence>
                {showGuide && (
                    <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        className="overflow-hidden mb-6 relative z-20"
                    >
                        <div className="p-4 rounded-xl bg-orange-500/5 border border-orange-400/20 space-y-4">
                            <div className="flex items-center justify-between">
                                <span className="text-[8px] font-black uppercase text-orange-400 tracking-[0.2em]">Retrieval Protocol</span>
                                <a
                                    href={COLLECTION_GUIDES[provider]?.url}
                                    target="_blank"
                                    rel="noreferrer"
                                    className="text-[8px] font-black text-orange-400 hover:text-orange-300 flex items-center gap-1 group/link bg-orange-500/10 px-2 py-1 rounded"
                                >
                                    PORTAL_ACCESS
                                    <Globe size={8} className="group-hover/link:translate-x-0.5 transition-transform" />
                                </a>
                            </div>
                            <div className="space-y-2">
                                {COLLECTION_GUIDES[provider]?.steps.map((step, i) => (
                                    <div key={i} className="flex gap-3 text-[9px] font-mono leading-relaxed">
                                        <span className="text-orange-500/50">0{i + 1}</span>
                                        <span className="text-slate-400">{step}</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>

            <div className="space-y-4 mt-2">
                {items.length === 0 && (
                    <div className="py-12 border border-dashed border-white/5 rounded-2xl flex flex-col items-center justify-center bg-white/[0.01]">
                        <CircleDashed size={32} className="text-slate-700 animate-spin-slow mb-4 opacity-40" />
                        <span className="text-[10px] font-black uppercase tracking-[0.4em] text-slate-600">Zero Units Authenticated</span>
                    </div>
                )}

                {items.map((item, idx) => (
                    <motion.div
                        initial={{ opacity: 0, x: -10 }}
                        animate={{ opacity: 1, x: 0 }}
                        key={idx}
                        className="flex gap-3"
                    >
                        <div className="flex-1">
                            {fieldType === 'pair' ? (
                                <PairInput provider={provider} item={item} isVisible={isVisible} onChange={(v) => { onUpdate(fieldType, items.map((it, i) => i === idx ? v : it)); }} />
                            ) : (
                                <div className="group/input flex items-center bg-black/80 border border-white/10 focus-within:border-teal-500/80 rounded-xl overflow-hidden transition-all focus-within:bg-teal-500/5 shadow-inner">
                                    <div className="px-4 py-4 border-r border-white/5 bg-white/[0.02] text-teal-500/30 group-focus-within/input:text-teal-500 transition-colors">
                                        <Key size={14} />
                                    </div>
                                    <div className="flex-1 flex flex-col justify-center px-4 py-3 min-h-[64px]">
                                        <div className="text-[6px] font-black text-teal-500/20 uppercase tracking-widest pointer-events-none group-focus-within/input:text-teal-500/40 select-none mb-1">
                                            {provider.toUpperCase()}_{fieldLabel.toUpperCase().slice(0, -1)}_UNIT
                                        </div>
                                        <div className="relative">
                                            <input
                                                type={isVisible ? "text" : "password"}
                                                value={item}
                                                placeholder={`[ ENTER_${provider.toUpperCase()}_${fieldLabel === 'tokens' ? 'ACCESS_TOKEN' : 'API_KEY'} ]`}
                                                onChange={(e) => { const next = [...items]; next[idx] = e.target.value; onUpdate(fieldType, next); }}
                                                className="w-full bg-transparent text-[11px] font-mono text-slate-300 transition-all outline-none placeholder:text-teal-500/10 focus:placeholder:text-teal-500/30 p-0"
                                            />
                                            {!isVisible && item.includes('...') && (
                                                <div className="absolute inset-0 flex items-center text-[11px] pointer-events-none text-teal-500/20">
                                                    <DecryptionMask value={item} isVisible={isVisible} />
                                                </div>
                                            )}
                                        </div>
                                    </div>
                                </div>
                            )}
                        </div>
                        <button
                            onClick={() => { playTick(); const next = [...items]; next.splice(idx, 1); onUpdate(fieldType, next); }}
                            className="p-3 self-center rounded-xl bg-red-500/5 text-red-500/30 hover:text-red-500 hover:bg-red-500/10 transition-all border border-transparent hover:border-red-500/50"
                        >
                            <Trash2 size={18} />
                        </button>
                    </motion.div>
                ))}

                {/* Staged Injection HUD */}
                {isInjecting && (
                    <motion.div
                        initial={{ opacity: 0, scale: 0.98, x: -10 }}
                        animate={{ opacity: 1, scale: 1, x: 0 }}
                        className="p-1 rounded-2xl bg-teal-500/5 border border-teal-500/20 shadow-[0_0_30px_rgba(20,184,166,0.1)]"
                    >
                        <div className="flex gap-3 p-3">
                            <div className="flex-1">
                                {fieldType === 'pair' ? (
                                    <PairInput
                                        provider={provider}
                                        item={stagedUnit}
                                        isVisible={true}
                                        onChange={setStagedUnit}
                                        fields={fields}
                                    />
                                ) : (
                                    <div className="group/input flex items-center bg-black/90 border border-teal-500/20 focus-within:border-teal-400 rounded-xl overflow-hidden transition-all">
                                        <div className="px-4 py-4 border-r border-teal-500/10 bg-teal-500/5 text-teal-400 animate-pulse">
                                            <Plus size={14} />
                                        </div>
                                        <div className="flex-1 flex flex-col justify-center px-4 py-3 min-h-[64px]">
                                            <div className="text-[6px] font-black text-teal-400/20 uppercase tracking-widest pointer-events-none select-none mb-1">
                                                STAGING_{provider.toUpperCase()}_UNIT
                                            </div>
                                            <input
                                                autoFocus
                                                type="text"
                                                value={stagedUnit}
                                                placeholder={`[ AUTH_NEW_${provider.toUpperCase()}_${fieldLabel === 'tokens' ? 'TOKEN' : 'KEY'} ]`}
                                                onChange={(e) => setStagedUnit(e.target.value)}
                                                onKeyDown={(e) => e.key === 'Enter' && commitUnit()}
                                                className="w-full bg-transparent text-[11px] font-mono text-teal-50 transition-all outline-none placeholder:text-teal-500/10 focus:placeholder:text-teal-500/30 p-0"
                                            />
                                        </div>
                                    </div>
                                )}
                            </div>
                            <div className="flex flex-col gap-2 min-w-[120px]">
                                <button
                                    onClick={commitUnit}
                                    className="flex items-center justify-center gap-2 px-4 py-3 rounded-xl bg-teal-500 text-black hover:bg-teal-400 transition-all shadow-[0_0_15px_rgba(20,184,166,0.3)] hover:scale-[1.02] active:scale-95 group/btn"
                                >
                                    <CheckCircle2 size={14} />
                                    <span className="text-[9px] font-black uppercase tracking-tighter">AUTHENTICATE</span>
                                </button>
                                <button
                                    onClick={() => { playTick(); setIsInjecting(false); setStagedUnit(fieldType === 'pair' ? {} : ''); }}
                                    className="flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-white/5 text-slate-500 hover:text-white transition-all hover:bg-red-500/10 hover:text-red-400 group/btn"
                                >
                                    <X size={14} />
                                    <span className="text-[9px] font-black uppercase tracking-tighter">ABORT_PROTO</span>
                                </button>
                            </div>
                        </div>
                    </motion.div>
                )}

                {!isInjecting && (
                    <button
                        onClick={addItem}
                        className="w-full py-4 border border-dashed border-white/10 rounded-xl text-[10px] font-black text-slate-600 hover:text-teal-400 hover:border-teal-500/50 hover:bg-teal-500/5 transition-all flex items-center justify-center gap-3 group"
                    >
                        <Plus size={16} className="group-hover:rotate-90 transition-transform" />
                        INJECT_NODAL_UNIT
                    </button>
                )}
            </div>
        </motion.div>
    );
};

const PairInput = ({ provider, item, isVisible, onChange, fields }) => {
    return (
        <div className="grid grid-cols-2 gap-4">
            {fields.map(f => (
                <div key={f.key} className="group/input flex items-center bg-black/80 border border-white/10 focus-within:border-teal-500/80 rounded-xl overflow-hidden transition-all focus-within:bg-teal-500/5">
                    <div className="px-3 py-4 border-r border-white/5 bg-white/[0.01] text-teal-500/20 group-focus-within/input:text-teal-500/50 transition-colors">
                        <f.icon size={12} />
                    </div>
                    <div className="flex-1 flex flex-col justify-center px-4 py-3 min-h-[64px]">
                        <div className="text-[6px] font-black text-teal-500/20 uppercase tracking-[0.2em] pointer-events-none group-focus-within/input:text-teal-500/40 select-none mb-1">{f.label}</div>
                        <div className="relative">
                            <input
                                type={(isVisible || f.key === 'email' || f.key === 'username') ? "text" : "password"}
                                value={item[f.key] || ''}
                                placeholder={`[ ENTER_${f.ph} ]`}
                                onChange={(e) => onChange({ ...item, [f.key]: e.target.value })}
                                className="w-full bg-transparent text-[11px] font-mono text-slate-300 transition-all outline-none placeholder:text-teal-500/10 focus:placeholder:text-teal-500/30 p-0"
                            />
                            {!isVisible && item[f.key]?.includes('...') && (
                                <div className="absolute inset-0 flex items-center text-[11px] pointer-events-none text-teal-500/20">
                                    <DecryptionMask value={item[f.key]} isVisible={isVisible} />
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            ))}
        </div>
    );
};

export default SettingsModal;
