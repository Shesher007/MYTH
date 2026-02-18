import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Shield, Globe, Zap, Lock, Power, ChevronDown, Activity, ArrowUpRight, ArrowDownLeft } from 'lucide-react';
import { useSoundscape } from '../hooks/useSoundscape';

const VpnController = ({ vpnStatus, vpnNodes, onToggle }) => {
    const { playTick, playChirp, playSuccess } = useSoundscape();
    const [isExpanded, setIsExpanded] = useState(false);
    const [selectedNodeId, setSelectedNodeId] = useState(null);

    // Safety: ensure arrays are always valid
    const safeNodes = Array.isArray(vpnNodes) ? vpnNodes : [];
    const safeStatus = vpnStatus || { connected: false, throughput_tx: 0, throughput_rx: 0, uptime: '0h 0m' };

    const handleToggle = async () => {
        playChirp();
        const success = await onToggle(selectedNodeId);
        if (success) playSuccess();
    };

    const activeNode = safeStatus.active_node || safeNodes.find(n => n.id === (selectedNodeId || (safeNodes[0]?.id))) || safeNodes[0] || null;

    return (
        <div className="px-4 py-3">
            <div className={`relative group/vpn transition-all duration-500 rounded-none border border-teal-500/10 bg-[#020205] overflow-hidden notched-border ${safeStatus.connected ? '!border-teal-500/40' : 'hover:border-teal-500/30'}`}>
                {/* Tactical Header Background Grid */}
                <div className="absolute inset-0 opacity-[0.03] pointer-events-none"
                    style={{ backgroundImage: 'radial-gradient(circle at 2px 2px, #14b8a6 1px, transparent 0)', backgroundSize: '12px 12px' }}></div>

                {/* Header / Quick Toggle */}
                <div className="relative p-3 flex items-center justify-between z-10">
                    <div className="flex items-center gap-3">
                        <div className={`relative w-8 h-8 flex items-center justify-center transition-all duration-500 rounded-none border notched-border ${safeStatus.connected ? 'border-teal-500/50 bg-teal-500/10 shadow-[0_0_15px_rgba(20,184,166,0.15)]' : 'border-white/10 bg-black/40'}`}>
                            <Shield size={14} className={safeStatus.connected ? 'text-teal-400' : 'text-slate-600'} />
                            {safeStatus.connected && (
                                <motion.div
                                    animate={{ scale: [1, 1.2, 1], opacity: [0.3, 0.1, 0.3] }}
                                    transition={{ duration: 3, repeat: Infinity }}
                                    className="absolute inset-0 bg-teal-500/20"
                                />
                            )}
                        </div>
                        <div>
                            <div className="flex items-center gap-2">
                                <h3 className="text-[10px] font-black text-white uppercase tracking-[0.2em] leading-none">Tunnel Protocol</h3>
                                {safeStatus.connected && (
                                    <span className="flex h-1.5 w-1.5 rounded-full bg-teal-500 animate-pulse"></span>
                                )}
                            </div>
                            <p className="text-[8px] font-mono text-slate-500 uppercase tracking-widest mt-1.5 font-bold flex items-center gap-1.5">
                                <span className={safeStatus.connected ? 'text-teal-500' : 'text-slate-700'}>
                                    {safeStatus.connected ? 'SECURE_LINK' : 'NODE_OFFLINE'}
                                </span>
                                <span className="opacity-30 px-1">//</span>
                                <span className="text-slate-500">{activeNode?.name || 'STANDBY'}</span>
                            </p>
                        </div>
                    </div>

                    <motion.button
                        whileHover={{ scale: 1.05 }}
                        whileTap={{ scale: 0.95 }}
                        onClick={handleToggle}
                        onMouseEnter={playTick}
                        className={`relative w-9 h-9 flex items-center justify-center transition-all duration-500 rounded-none border notched-border ${safeStatus.connected
                            ? 'bg-teal-500/20 border-teal-500/60 text-teal-400 shadow-[0_0_20px_rgba(20,184,166,0.2)]'
                            : 'bg-white/5 border-white/10 text-slate-600 hover:border-teal-500/30 hover:text-teal-500'}`}
                    >
                        <Power size={18} className={safeStatus.connected ? 'drop-shadow-[0_0_5px_rgba(20,184,166,0.8)]' : ''} />
                    </motion.button>
                </div>

                {/* Metrics Bar - Industrial Track Style */}
                <AnimatePresence>
                    {safeStatus.connected && (
                        <motion.div
                            initial={{ height: 0, opacity: 0 }}
                            animate={{ height: 'auto', opacity: 1 }}
                            exit={{ height: 0, opacity: 0 }}
                            className="relative border-t border-teal-500/10 bg-[#050508] p-3 overflow-hidden"
                        >
                            {/* Throughput Scanning Trace */}
                            <motion.div
                                animate={{ x: ['-100%', '100%'] }}
                                transition={{ duration: 2, repeat: Infinity, ease: "linear" }}
                                className="absolute top-0 left-0 w-32 h-[1px] bg-gradient-to-r from-transparent via-teal-500/40 to-transparent"
                            />

                            <div className="grid grid-cols-3 gap-0 divide-x divide-teal-500/10">
                                <div className="flex flex-col items-center px-1">
                                    <div className="flex items-center gap-1 mb-1.5">
                                        <ArrowUpRight size={10} className="text-teal-500" />
                                        <span className="text-[7px] font-mono text-slate-500 uppercase tracking-tighter">TX_FLUX</span>
                                    </div>
                                    <div className="font-mono text-[9px] font-bold text-teal-400/90 tabular-nums">
                                        {safeStatus.throughput_tx.toFixed(2)}<span className="text-[6px] ml-0.5 opacity-40">M/S</span>
                                    </div>
                                </div>
                                <div className="flex flex-col items-center px-1">
                                    <div className="flex items-center gap-1 mb-1.5">
                                        <ArrowDownLeft size={10} className="text-purple-500" />
                                        <span className="text-[7px] font-mono text-slate-500 uppercase tracking-tighter">RX_FLUX</span>
                                    </div>
                                    <div className="font-mono text-[9px] font-bold text-purple-400/90 tabular-nums">
                                        {safeStatus.throughput_rx.toFixed(2)}<span className="text-[6px] ml-0.5 opacity-40">M/S</span>
                                    </div>
                                </div>
                                <div className="flex flex-col items-center px-1">
                                    <div className="flex items-center gap-1 mb-1.5">
                                        <Activity size={10} className="text-amber-500" />
                                        <span className="text-[7px] font-mono text-slate-500 uppercase tracking-tighter">NODE_UP</span>
                                    </div>
                                    <div className="font-mono text-[9px] font-bold text-amber-400/90 whitespace-nowrap">
                                        {safeStatus.uptime}
                                    </div>
                                </div>
                            </div>

                            {/* Tactical HUD Data Point */}
                            <div className="mt-3 pt-2 border-t border-teal-500/5 flex items-center justify-between">
                                <span className="text-[6px] font-mono text-slate-700 tracking-[0.3em]">SECURE_ID: {activeNode?.id?.toUpperCase() || 'NULL'}</span>
                                <span className="text-[6px] font-mono text-teal-500/40 tracking-[0.3em]">CH_A: SIG_VERIFIED</span>
                            </div>
                        </motion.div>
                    )}
                </AnimatePresence>

                {/* Node Selector Expansion Toggle */}
                <div
                    className="relative px-3 py-2 border-t border-teal-500/10 bg-[#08080c] flex items-center justify-between cursor-pointer group/toggle transition-colors hover:bg-teal-500/5"
                    onClick={() => { setIsExpanded(!isExpanded); playTick(); }}
                >
                    <div className="flex items-center gap-2">
                        <Globe size={10} className={`transition-colors duration-500 ${isExpanded ? 'text-teal-400' : 'text-slate-600'}`} />
                        <span className={`text-[8px] font-black uppercase tracking-[0.2em] transition-colors duration-500 ${isExpanded ? 'text-slate-200' : 'text-slate-500'}`}>Endpoint Matrix</span>
                    </div>
                    <div className="flex items-center gap-3">
                        <div className="flex gap-0.5">
                            <div className={`w-1 h-3 rounded-none ${isExpanded ? 'bg-teal-500/40' : 'bg-slate-800'}`}></div>
                            <div className={`w-1 h-3 rounded-none ${isExpanded ? 'bg-teal-500/20' : 'bg-slate-800'}`}></div>
                        </div>
                        <ChevronDown size={12} className={`text-slate-700 transition-transform duration-500 ${isExpanded ? 'rotate-180 text-teal-500/50' : ''}`} />
                    </div>
                </div>

                <AnimatePresence>
                    {isExpanded && (
                        <motion.div
                            initial={{ height: 0 }}
                            animate={{ height: 'auto' }}
                            exit={{ height: 0 }}
                            className="overflow-hidden bg-[#0a0a0f]"
                        >
                            <div className="p-1 space-y-0.5 max-h-[180px] overflow-y-auto scrollbar-tactical">
                                {safeNodes.map((node) => {
                                    const isActive = safeStatus.active_node?.id === node.id;
                                    const isSelected = selectedNodeId === node.id || (!selectedNodeId && safeNodes[0]?.id === node.id);

                                    return (
                                        <button
                                            key={node.id}
                                            onClick={() => { setSelectedNodeId(node.id); playTick(); }}
                                            className={`relative w-full flex items-center justify-between p-2 transition-all border ${isActive
                                                ? 'bg-teal-500/10 border-teal-500/40'
                                                : isSelected
                                                    ? 'bg-white/5 border-white/10'
                                                    : 'hover:bg-white/[0.02] border-transparent'
                                                }`}
                                        >
                                            <div className="flex items-center gap-2.5">
                                                <div className={`w-1 h-4 ${node.load < 30 ? 'bg-teal-500' : node.load < 60 ? 'bg-amber-500' : 'bg-red-500'} opacity-60`}></div>
                                                <div className="flex flex-col items-start">
                                                    <div className="flex items-center gap-1.5">
                                                        <span className={`text-[8px] font-black uppercase tracking-widest ${isActive ? 'text-teal-400' : 'text-slate-300'}`}>{node.name}</span>
                                                        {isActive && <div className="w-1 h-1 rounded-full bg-teal-500 animate-ping"></div>}
                                                    </div>
                                                    <span className="text-[6px] font-mono text-slate-600 uppercase tracking-[0.2em]">{node.region} <span className="opacity-20">//</span> {node.latency}</span>
                                                </div>
                                            </div>
                                            <div className="flex items-center gap-2">
                                                <div className="text-[7px] font-mono text-slate-700 font-bold">{node.load}%</div>
                                                {node.secure && <Lock size={8} className={isActive ? 'text-teal-400/40' : 'text-slate-800'} />}
                                            </div>

                                            {/* Hover HUD Mark */}
                                            {isSelected && !isActive && (
                                                <div className="absolute top-0 right-0 w-1 h-1 border-t border-r border-teal-500/40"></div>
                                            )}
                                        </button>
                                    );
                                })}
                            </div>

                            {/* Tactical Protocol Footer */}
                            <div className="p-2 border-t border-teal-500/5 bg-[#0d0d12]">
                                <div className="flex items-center justify-between mb-1.5 px-1">
                                    <div className="flex items-center gap-1.5">
                                        <Zap size={8} className="text-amber-500/60" />
                                        <span className="text-[7px] font-mono text-slate-600 uppercase tracking-widest">CIPHER: AES-256-GCM</span>
                                    </div>
                                    <span className="text-[6px] font-mono text-slate-800">WIRE_GUARD_2.4</span>
                                </div>
                                <div className="h-[2px] bg-white/5 overflow-hidden">
                                    <motion.div
                                        className="h-full bg-teal-500/30"
                                        animate={{ x: ['-100%', '100%'] }}
                                        transition={{ duration: 4, repeat: Infinity, ease: "linear" }}
                                    />
                                </div>
                            </div>
                        </motion.div>
                    )}
                </AnimatePresence>
            </div>
        </div>
    );
};

export default VpnController;
