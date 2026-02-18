import React, { useMemo } from 'react';
import { motion } from 'framer-motion';

const SecurityMap = ({ connections = [] }) => {
    // Simple SVG Map projection with markers
    // Real industry maps use complex projections; we use a stylized industrial grid-map

    const hostX = 500; // Center or based on local IP geo if available
    const hostY = 250;

    const markers = useMemo(() => {
        return connections
            .filter(c => c.geo && c.geo.lat !== 0)
            .map((c, i) => {
                const x = ((c.geo.lon + 180) / 360) * 1000;
                const y = ((90 - c.geo.lat) / 180) * 500;
                return { x, y, name: c.name, country: c.geo.country, id: `${c.remote}-${i}` };
            });
    }, [connections]);

    const signalArcs = useMemo(() => {
        return markers.map(m => {
            // Calculate a midpoint with offset for the arc
            const midX = (hostX + m.x) / 2;
            const midY = (hostY + m.y) / 2 - 50; // Curve upwards
            return {
                id: `arc-${m.id}`,
                path: `M ${hostX} ${hostY} Q ${midX} ${midY} ${m.x} ${m.y}`,
                targetX: m.x,
                targetY: m.y
            };
        });
    }, [markers]);

    return (
        <div className="relative w-full h-[400px] bg-[#020205] border border-white/5 rounded overflow-hidden group">
            <div className="absolute inset-0 opacity-20 pointer-events-none">
                <svg width="100%" height="100%" viewBox="0 0 1000 500" className="fill-slate-800">
                    {/* Stylized simple continents/grid */}
                    <rect x="0" y="0" width="1000" height="500" fill="transparent" />
                    <path d="M150,100 L300,100 L350,200 L200,250 Z" className="fill-slate-800/30" /> {/* North Am */}
                    <path d="M450,100 L600,100 L650,250 L500,300 Z" className="fill-slate-800/30" /> {/* Eurasia */}
                    <path d="M500,350 L600,350 L550,450 Z" className="fill-slate-800/30" /> {/* Africa */}
                    <circle cx="800" cy="400" r="40" className="fill-slate-800/30" /> {/* Australia */}
                </svg>
            </div>

            <div className="absolute top-4 left-4 z-10">
                <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-teal-500 animate-pulse"></div>
                    <span className="text-[10px] font-black text-slate-500 uppercase tracking-[0.2em]">Spatial Intelligence: LIVE</span>
                </div>
            </div>

            <svg width="100%" height="100%" viewBox="0 0 1000 500" className="relative z-20">
                {/* Host Marker */}
                <motion.circle
                    cx={hostX} cy={hostY} r="6"
                    className="fill-teal-500 shadow-[0_0_15px_rgba(20,184,166,0.6)]"
                />
                <motion.circle
                    cx={hostX} cy={hostY} r="12"
                    fill="none" stroke="rgba(20, 184, 166, 0.4)" strokeWidth="1"
                    animate={{ r: [12, 25], opacity: [0.5, 0] }}
                    transition={{ repeat: Infinity, duration: 3 }}
                />

                {/* Signal Arcs */}
                {signalArcs.map(arc => (
                    <g key={arc.id}>
                        <motion.path
                            d={arc.path}
                            fill="none"
                            stroke="url(#arcGradient)"
                            strokeWidth="1"
                            initial={{ pathLength: 0, opacity: 0 }}
                            animate={{ pathLength: 1, opacity: 0.4 }}
                            transition={{ duration: 1.5 }}
                        />
                        {/* Data Packet Pulse */}
                        <motion.circle
                            r="1.5"
                            fill="#ef4444"
                            initial={{ offset: 0 }}
                            animate={{ offset: 1 }}
                            transition={{ repeat: Infinity, duration: 4, ease: "linear" }}
                        >
                            <animateMotion path={arc.path} dur="4s" repeatCount="indefinite" />
                        </motion.circle>
                    </g>
                ))}

                <defs>
                    <linearGradient id="arcGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                        <stop offset="0%" stopColor="#14b8a6" stopOpacity="0.8" />
                        <stop offset="100%" stopColor="#ef4444" stopOpacity="0.4" />
                    </linearGradient>
                </defs>

                {markers.map((m, i) => (
                    <g key={i}>
                        <motion.circle
                            initial={{ r: 0, opacity: 0 }}
                            animate={{ r: 4, opacity: 1 }}
                            cx={m.x} cy={m.y}
                            className="fill-red-500 shadow-[0_0_10px_rgba(239,68,68,0.5)]"
                        />
                        <text x={m.x + 8} y={m.y + 4} className="text-[10px] fill-slate-400 font-mono pointer-events-none select-none">
                            {m.country} // {m.name}
                        </text>
                    </g>
                ))}
            </svg>

            <div className="absolute bottom-4 right-4 text-[8px] font-mono text-slate-700 bg-black/40 px-2 py-1 rounded">
                ACTIVE_NODES: {markers.length} // GRID_RESOLUTION: HIGH
            </div>
        </div>
    );
};

export default SecurityMap;
