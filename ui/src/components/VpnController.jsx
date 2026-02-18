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

    const activeNode = safeStatus.active_node || safeNodes.find(n => n.id === selectedNodeId) || safeNodes[0] || null;

    return (
        <div className="px-4 py-2">
            <div className="bg-black/20 border border-white/5 rounded-lg overflow-hidden transition-all duration-500 hover:border-teal-500/30">
                {/* Header / Quick Toggle */}
                <div className="p-3 flex items-center justify-between">
                    <div className="flex items-center gap-3">
                        <div className={`relative p-2 rounded bg-black/40 border ${safeStatus.connected ? 'border-teal-500/50 shadow-[0_0_15px_rgba(20,184,166,0.2)]' : 'border-white/5'}`}>
                            <Shield size={16} className={safeStatus.connected ? 'text-teal-400' : 'text-slate-600'} />
                            {safeStatus.connected && (
                                <motion.div
                                    animate={{ scale: [1, 1.5, 1], opacity: [0.5, 0, 0.5] }}
                                    transition={{ duration: 2, repeat: Infinity }}
                                    className="absolute inset-0 bg-teal-500/20 rounded-full"
                                />
                            )}
                        </div>
                        <div>
                            <h3 className="text-[11px] font-black text-white uppercase tracking-[0.2em] leading-none">Neural Tunnel</h3>
                            <p className="text-[8px] font-mono text-slate-500 uppercase tracking-widest mt-1.5 font-bold">
                                {safeStatus.connected ? `SECURE: ${activeNode?.name || 'LOCAL'}` : 'DISCONNECTED // CLEAR_NET'}
                            </p>
                        </div>
                    </div>

                    <button
                        onClick={handleToggle}
                        onMouseEnter={playTick}
                        className={`p-2.5 rounded-full border transition-all duration-500 ${safeStatus.connected
                            ? 'bg-teal-500/20 border-teal-500/50 text-teal-400 shadow-[0_0_20px_rgba(20,184,166,0.3)]'
                            : 'bg-white/5 border-white/10 text-slate-600 hover:border-teal-500/30 hover:text-teal-500'}`}
                    >
                        <Power size={18} className={safeStatus.connected ? 'animate-pulse' : ''} />
                    </button>
                </div>

                {/* Metrics Bar */}
                <AnimatePresence>
                    {safeStatus.connected && (
                        <motion.div
                            initial={{ height: 0, opacity: 0 }}
                            animate={{ height: 'auto', opacity: 1 }}
                            exit={{ height: 0, opacity: 0 }}
                            className="px-4 py-3 border-t border-white/5 bg-teal-500/5 grid grid-cols-1 sm:grid-cols-3 items-center gap-4"
                        >
                            <div className="flex flex-col items-center border-b sm:border-b-0 sm:border-r border-white/5 pb-2 sm:pb-0">
                                <div className="flex items-center gap-1.5 mb-1">
                                    <ArrowUpRight size={10} className="text-teal-500" />
                                    <span className="text-[8px] font-mono text-slate-500 uppercase">UL</span>
                                </div>
                                <span className="text-[10px] font-black text-white font-mono">{safeStatus.throughput_tx} <span className="text-[7px] text-slate-600">MB/s</span></span>
                            </div>
                            <div className="flex flex-col items-center border-b sm:border-b-0 sm:border-r border-white/5 pb-2 sm:pb-0">
                                <div className="flex items-center gap-1.5 mb-1">
                                    <ArrowDownLeft size={10} className="text-purple-500" />
                                    <span className="text-[8px] font-mono text-slate-500 uppercase">DL</span>
                                </div>
                                <span className="text-[10px] font-black text-white font-mono">{safeStatus.throughput_rx} <span className="text-[7px] text-slate-600">MB/s</span></span>
                            </div>
                            <div className="flex flex-col items-center">
                                <div className="flex items-center gap-1.5 mb-1">
                                    <Activity size={10} className="text-amber-500" />
                                    <span className="text-[8px] font-mono text-slate-500 uppercase">UP</span>
                                </div>
                                <span className="text-[10px] font-black text-white font-mono uppercase">{safeStatus.uptime}</span>
                            </div>
                        </motion.div>
                    )}
                </AnimatePresence>

                {/* Node Selector Expansion */}
                <div
                    className="px-4 py-2 border-t border-white/5 bg-black/40 flex items-center justify-between cursor-pointer group"
                    onClick={() => { setIsExpanded(!isExpanded); playTick(); }}
                >
                    <div className="flex items-center gap-2">
                        <Globe size={12} className="text-slate-500 group-hover:text-teal-500 transition-colors" />
                        <span className="text-[9px] font-black text-slate-500 uppercase tracking-widest group-hover:text-slate-300 transition-colors">Endpoint Matrix</span>
                    </div>
                    <ChevronDown size={14} className={`text-slate-700 transition-transform duration-500 ${isExpanded ? 'rotate-180' : ''}`} />
                </div>

                <AnimatePresence>
                    {isExpanded && (
                        <motion.div
                            initial={{ height: 0 }}
                            animate={{ height: 'auto' }}
                            exit={{ height: 0 }}
                            className="overflow-hidden bg-black/60"
                        >
                            <div className="p-2 space-y-1">
                                {safeNodes.map((node) => (
                                    <button
                                        key={node.id}
                                        onClick={() => { setSelectedNodeId(node.id); playTick(); }}
                                        className={`w-full flex items-center justify-between p-2 rounded transition-all ${selectedNodeId === node.id || safeStatus.active_node?.id === node.id ? 'bg-teal-500/10 border border-teal-500/20' : 'hover:bg-white/5 border border-transparent'}`}
                                    >
                                        <div className="flex items-center gap-3">
                                            <div className={`w-1.5 h-1.5 rounded-full ${node.load < 30 ? 'bg-teal-500' : node.load < 60 ? 'bg-amber-500' : 'bg-red-500'}`}></div>
                                            <div className="flex flex-col items-start">
                                                <span className="text-[9px] font-black text-slate-300 uppercase">{node.name}</span>
                                                <span className="text-[7px] font-mono text-slate-600 uppercase tracking-widest">{node.region} // {node.latency}</span>
                                            </div>
                                        </div>
                                        {node.secure && <Lock size={10} className="text-teal-500/50" />}
                                    </button>
                                ))}
                            </div>
                            <div className="p-3 border-t border-white/5 bg-black/40">
                                <div className="flex items-center gap-2 mb-2">
                                    <Zap size={10} className="text-amber-500" />
                                    <span className="text-[8px] font-black text-slate-600 uppercase tracking-widest">Protocol: WireGuard v2.4</span>
                                </div>
                                <div className="h-1 bg-white/5 rounded-full overflow-hidden">
                                    <motion.div
                                        className="h-full bg-teal-500/50"
                                        animate={{ width: ['20%', '100%', '20%'] }}
                                        transition={{ duration: 3, repeat: Infinity, ease: "linear" }}
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
