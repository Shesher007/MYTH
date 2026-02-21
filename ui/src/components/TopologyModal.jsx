import React, { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Activity, Server, Database, Globe, Shield } from 'lucide-react';
import SecurityMap from './SecurityMap';

const TopologyModal = ({ isOpen, onClose, systemStatus: _systemStatus, networkConnections = [] }) => {
    const [activeTab, setActiveTab] = useState('logical'); // 'logical' or 'spatial'
    const [selectedNode, setSelectedNode] = useState(null);

    // Dynamic node generation logic
    const nodes = useMemo(() => {
        const baseNodes = [
            { id: 'host', label: _systemStatus?.hostname || 'LOCAL_HOST', type: 'shield', x: 250, y: 250, status: 'secure', isHost: true },
        ];

        // Group connections by process name to create individual process nodes
        const processGroups = {};
        networkConnections.forEach(conn => {
            if (!processGroups[conn.name]) {
                processGroups[conn.name] = {
                    id: conn.name,
                    label: conn.name.toUpperCase(),
                    type: 'server',
                    status: 'active',
                    count: 0,
                    remotes: []
                };
            }
            processGroups[conn.name].count++;
            processGroups[conn.name].remotes.push(conn.remote);
        });

        const dynamicNodes = Object.values(processGroups).map((proc, idx) => {
            // Distribute around the host
            const angle = (idx / Object.keys(processGroups).length) * Math.PI * 2;
            const radius = 150;
            return {
                ...proc,
                x: 250 + Math.cos(angle) * radius,
                y: 250 + Math.sin(angle) * radius,
            };
        });

        return [...baseNodes, ...dynamicNodes];
    }, [networkConnections, _systemStatus]);

    const links = useMemo(() => {
        return nodes.filter(n => !n.isHost).map(n => ({
            source: 'host',
            target: n.id
        }));
    }, [nodes]);

    const getIcon = (type) => {
        switch (type) {
            case 'globe': return <Globe size={16} className="text-blue-400" />;
            case 'database': return <Database size={16} className="text-amber-500" />;
            case 'server': return <Server size={16} className="text-teal-400" />;
            case 'shield': return <Shield size={16} className="text-purple-400" />;
            default: return <Activity size={16} />;
        }
    };

    return (
        <AnimatePresence>
            {isOpen && (
                <div className="fixed inset-0 z-[1100] flex items-center justify-center p-4">
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="absolute inset-0 bg-black/95 backdrop-blur-2xl"
                        onClick={onClose}
                    />

                    <motion.div
                        initial={{ scale: 0.9, opacity: 0 }}
                        animate={{ scale: 1, opacity: 1 }}
                        exit={{ scale: 0.9, opacity: 0 }}
                        className="relative w-[min(95vw,75rem)] h-[min(90vh,60rem)] bg-[#020205] border border-white/10 rounded-lg shadow-[0_0_50px_rgba(0,0,0,0.5)] overflow-hidden flex flex-col"
                    >
                        <header className="px-4 md:px-6 py-4 border-b border-white/5 bg-black/40 flex flex-col sm:flex-row items-center justify-between gap-4">
                            <div className="flex items-center gap-3 w-full sm:w-auto">
                                <Activity size={18} className="text-teal-500 animate-pulse shrink-0" />
                                <div className="overflow-hidden">
                                    <h2 className="text-xs md:text-sm font-black text-white uppercase tracking-[0.2em] truncate">{activeTab === 'logical' ? 'Traffic Analyzer' : 'Signal Intel'}</h2>
                                    <p className="text-[7px] md:text-[9px] text-slate-500 font-mono tracking-widest mt-0.5 truncate">NODES: {networkConnections.length + nodes.length} // LATENCY: NATIVE</p>
                                </div>
                            </div>

                            <div className="flex bg-black/40 p-1 rounded border border-white/10 w-full sm:w-auto justify-center">
                                <button
                                    onClick={() => setActiveTab('logical')}
                                    className={`flex-1 sm:flex-initial px-3 md:px-4 py-1.5 rounded text-[8px] md:text-[9px] font-black uppercase tracking-widest transition-all ${activeTab === 'logical' ? 'bg-teal-500/20 text-teal-400 border border-teal-500/20' : 'text-slate-500 hover:text-slate-300'}`}
                                >
                                    Logical
                                </button>
                                <button
                                    onClick={() => setActiveTab('spatial')}
                                    className={`flex-1 sm:flex-initial px-3 md:px-4 py-1.5 rounded text-[8px] md:text-[9px] font-black uppercase tracking-widest transition-all ${activeTab === 'spatial' ? 'bg-purple-500/20 text-purple-400 border border-purple-500/20' : 'text-slate-500 hover:text-slate-300'}`}
                                >
                                    Spatial
                                </button>
                            </div>

                            <button onClick={onClose} className="absolute sm:relative top-4 right-4 sm:top-0 sm:right-0 p-2 hover:bg-white/5 rounded-full transition-colors">
                                <X size={20} className="text-slate-500" />
                            </button>
                        </header>

                        <div className="flex-1 flex flex-col lg:flex-row overflow-hidden">
                            {/* Main Display Area */}
                            <div className="flex-[2] relative overflow-hidden bg-[radial-gradient(circle_at_center,rgba(20,184,166,0.03)_0%,transparent_70%)] border-b lg:border-b-0 lg:border-r border-white/5 min-h-[300px]">
                                <AnimatePresence>
                                    {selectedNode && (
                                        <motion.div
                                            initial={{ x: -300, opacity: 0 }}
                                            animate={{ x: 0, opacity: 1 }}
                                            exit={{ x: -300, opacity: 0 }}
                                            className="absolute top-4 left-4 w-[min(calc(100%-2rem),16rem)] bg-black/80 backdrop-blur-xl border border-white/10 rounded-lg p-5 z-40 shadow-2xl"
                                        >
                                            <div className="flex items-center justify-between mb-4">
                                                <span className="text-[10px] font-black text-teal-400 uppercase tracking-widest">Node Inspection</span>
                                                <button onClick={() => setSelectedNode(null)} className="text-slate-500 hover:text-white">
                                                    <X size={14} />
                                                </button>
                                            </div>
                                            <div className="space-y-4">
                                                <div>
                                                    <div className="text-[8px] text-slate-500 uppercase font-mono mb-1">Process Identifier</div>
                                                    <div className="text-sm font-black text-white truncate">{selectedNode.label}</div>
                                                </div>
                                                {!selectedNode.isHost && (
                                                    <>
                                                        <div>
                                                            <div className="text-[8px] text-slate-500 uppercase font-mono mb-1">Active Endpoints</div>
                                                            <div className="space-y-1 mt-2 max-h-40 overflow-y-auto custom-scrollbar-minimal pr-2">
                                                                {selectedNode.remotes.map((remote, idx) => (
                                                                    <div key={idx} className="text-[9px] font-mono text-slate-400 bg-white/5 px-2 py-1 rounded border border-white/5 truncate">
                                                                        {remote}
                                                                    </div>
                                                                ))}
                                                            </div>
                                                        </div>
                                                        <button
                                                            className="w-full py-2 bg-red-500/10 border border-red-500/30 text-red-500 text-[9px] font-black uppercase tracking-widest hover:bg-red-500/20 transition-all"
                                                            onClick={() => { /* Kill logic could go here */ }}
                                                        >
                                                            Isolate Process
                                                        </button>
                                                    </>
                                                )}
                                                {selectedNode.isHost && (
                                                    <div className="p-3 bg-teal-500/5 border border-teal-500/20 rounded">
                                                        <p className="text-[9px] text-teal-400/80 font-mono leading-relaxed">
                                                            Primary host node. Managing {networkConnections.length} active neural links. Integrity status optimal.
                                                        </p>
                                                    </div>
                                                )}
                                            </div>
                                        </motion.div>
                                    )}
                                </AnimatePresence>

                                {activeTab === 'logical' ? (
                                    <svg width="100%" height="100%" viewBox="0 0 500 500" preserveAspectRatio="xMidYMid meet" className="opacity-90">
                                        <defs>
                                            <filter id="glow">
                                                <feGaussianBlur stdDeviation="2.5" result="coloredBlur" />
                                                <feMerge>
                                                    <feMergeNode in="coloredBlur" />
                                                    <feMergeNode in="SourceGraphic" />
                                                </feMerge>
                                            </filter>
                                        </defs>

                                        {links.map((link, i) => {
                                            const sourceNode = nodes.find(n => n.id === link.source);
                                            const targetNode = nodes.find(n => n.id === link.target);
                                            return (
                                                <g key={`link-${i}`}>
                                                    <motion.line
                                                        x1={sourceNode.x} y1={sourceNode.y}
                                                        x2={targetNode.x} y2={targetNode.y}
                                                        stroke="rgba(20, 184, 166, 0.2)"
                                                        strokeWidth="1"
                                                        initial={{ pathLength: 0 }}
                                                        animate={{ pathLength: 1 }}
                                                        transition={{ duration: 1, delay: i * 0.1 }}
                                                    />
                                                    {/* Traffic Pulse Dot */}
                                                    <motion.circle
                                                        r="2"
                                                        fill="#14b8a6"
                                                        filter="url(#glow)"
                                                        initial={{ offset: 0 }}
                                                        animate={{
                                                            cx: [sourceNode.x, targetNode.x],
                                                            cy: [sourceNode.y, targetNode.y]
                                                        }}
                                                        transition={{
                                                            repeat: Infinity,
                                                            duration: 2 + Math.random() * 2,
                                                            delay: Math.random() * 2
                                                        }}
                                                    />
                                                </g>
                                            );
                                        })}

                                        {nodes.map((node) => (
                                            <motion.g
                                                key={node.id}
                                                whileHover={{ scale: 1.1 }}
                                                className="cursor-pointer"
                                                onClick={() => setSelectedNode(node)}
                                            >
                                                <circle
                                                    cx={node.x} cy={node.y} r={node.isHost ? "35" : "22"}
                                                    fill="rgba(0,0,0,0.8)"
                                                    stroke={node.isHost ? 'rgba(20, 184, 166, 0.8)' : 'rgba(168, 85, 247, 0.5)'}
                                                    strokeWidth="2"
                                                    filter="url(#glow)"
                                                />
                                                <foreignObject x={node.x - 12} y={node.y - 12} width="24" height="24" className="overflow-visible">
                                                    <div className="flex items-center justify-center w-full h-full">
                                                        {getIcon(node.type)}
                                                    </div>
                                                </foreignObject>
                                                <text
                                                    x={node.x} y={node.y + (node.isHost ? 50 : 38)}
                                                    textAnchor="middle"
                                                    className={`text-[9px] fill-slate-400 font-mono font-black uppercase tracking-widest pointer-events-none ${node.isHost ? 'fill-teal-400' : ''}`}
                                                >
                                                    {node.label}
                                                </text>
                                                {!node.isHost && (
                                                    <text x={node.x} y={node.y + 48} textAnchor="middle" className="text-[7px] fill-slate-600 font-mono pointer-events-none">
                                                        {node.count}_CONVERSE
                                                    </text>
                                                )}
                                            </motion.g>
                                        ))}
                                    </svg>
                                ) : (
                                    <div className="p-4 h-full flex flex-col">
                                        <div className="flex-1 w-full overflow-hidden rounded bg-black/40">
                                            <SecurityMap connections={networkConnections} />
                                        </div>
                                        <div className="mt-4 p-4 border border-white/5 bg-black/40 rounded">
                                            <div className="flex items-center gap-3 mb-2">
                                                <Globe size={14} className="text-purple-400" />
                                                <span className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Geolocation Forensics</span>
                                            </div>
                                            <p className="text-[9px] text-slate-600 font-mono leading-relaxed truncate lg:whitespace-normal">
                                                Real-time IPv4/v6 endpoint mapping to telemetry data centers. Spatial intelligence correlation enabled.
                                            </p>
                                        </div>
                                    </div>
                                )}

                                <div className="absolute bottom-4 left-4 flex flex-col gap-2">
                                    <div className="flex items-center gap-2">
                                        <div className="w-1.5 h-1.5 rounded-full bg-teal-500 shadow-[0_0_8px_rgba(20,184,166,0.5)]"></div>
                                        <span className="text-[8px] font-black text-slate-600 uppercase tracking-widest">Secure Link Established</span>
                                    </div>
                                    <div className="flex items-center gap-2">
                                        <div className="w-1.5 h-1.5 rounded-full bg-amber-500 animate-pulse"></div>
                                        <span className="text-[8px] font-black text-slate-600 uppercase tracking-widest">Active Analysis</span>
                                    </div>
                                </div>
                            </div>

                            {/* Right Panel: Table */}
                            <div className="flex-1 flex flex-col bg-black/20 overflow-hidden">
                                <div className="px-4 py-3 border-b border-white/5 bg-white/5 flex items-center justify-between sticky top-0 z-10">
                                    <span className="text-[10px] font-black text-slate-400 uppercase tracking-widest">Neural Streams</span>
                                    <div className="flex items-center gap-2">
                                        <div className="w-1.5 h-1.5 rounded-full bg-teal-500 animate-pulse"></div>
                                        <span className="text-[8px] font-mono text-teal-500 uppercase">Live Trace</span>
                                    </div>
                                </div>
                                <div className="flex-1 overflow-y-auto custom-scrollbar-minimal">
                                    <table className="w-full text-left border-collapse">
                                        <thead className="sticky top-0 bg-[#0d0d16] z-10">
                                            <tr className="border-b border-white/5">
                                                <th className="px-4 py-2 text-[8px] font-mono text-slate-600 uppercase">Process</th>
                                                <th className="px-4 py-2 text-[8px] font-mono text-slate-600 uppercase">Address</th>
                                                <th className="px-4 py-2 text-[8px] font-mono text-slate-600 uppercase">GEO</th>
                                            </tr>
                                        </thead>
                                        <tbody className="divide-y divide-white/5">
                                            {networkConnections.length > 0 ? (
                                                networkConnections.map((conn, i) => (
                                                    <tr key={i} className="hover:bg-white/5 transition-colors group">
                                                        <td className="px-4 py-3 text-[9px] font-black text-teal-400/80 group-hover:text-teal-400 uppercase tracking-tighter truncate max-w-[100px]">{conn.name}</td>
                                                        <td className="px-4 py-3 text-[9px] font-mono text-slate-400 truncate max-w-[120px]">{conn.remote}</td>
                                                        <td className="px-4 py-3">
                                                            <span className="text-[8px] text-slate-500 font-black uppercase">
                                                                {conn.geo?.country || 'LOC'}
                                                            </span>
                                                        </td>
                                                    </tr>
                                                ))
                                            ) : (
                                                <tr>
                                                    <td colSpan="3" className="px-4 py-12 text-center">
                                                        <span className="text-[10px] text-slate-700 font-black uppercase tracking-[0.2em]">STANDBY...</span>
                                                    </td>
                                                </tr>
                                            )}
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>

                        <footer className="px-4 md:px-6 py-3 border-t border-white/5 bg-black/40 flex flex-col sm:flex-row items-center justify-between gap-4">
                            <div className="flex items-center gap-4 md:gap-6">
                                <span className="text-[8px] md:text-[9px] font-mono text-slate-600 uppercase tracking-widest truncate">MAP: INFRA_0X42</span>
                                <span className="text-[8px] md:text-[9px] font-mono text-slate-600 uppercase tracking-widest truncate">STAT: ACTIVE</span>
                            </div>
                            <div className="flex gap-4 w-full sm:w-auto justify-end">
                                <button className="text-[8px] md:text-[9px] font-black text-teal-500 uppercase tracking-widest hover:text-teal-400 transition-colors">Export</button>
                                <button className="text-[8px] md:text-[9px] font-black text-slate-500 uppercase tracking-widest hover:text-white transition-colors">Purge</button>
                            </div>
                        </footer>
                    </motion.div>
                </div>
            )}
        </AnimatePresence>
    );
};

export default TopologyModal;
