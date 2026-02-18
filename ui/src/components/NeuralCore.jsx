import React, { useState, useEffect, useRef } from 'react';
import { ChevronDown, ChevronRight, Brain, Terminal, Activity } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

const NeuralCore = ({ thoughts, isProcessing, startTime, currentStatus, activeNode, architectureMode, activeModel, usedTools }) => {
    const [isExpanded, setIsExpanded] = useState(true);
    const [elapsed, setElapsed] = useState(0);
    const containerRef = useRef(null);
    const prevIsProcessing = useRef(isProcessing);

    // Auto-expand/collapse logic
    useEffect(() => {
        if (!prevIsProcessing.current && isProcessing) {
            setIsExpanded(true);
        }
        if (prevIsProcessing.current && !isProcessing) {
            setIsExpanded(false);
        }
        prevIsProcessing.current = isProcessing;
    }, [isProcessing]);

    // Update timer
    useEffect(() => {
        let interval;
        if (isProcessing && startTime) {
            interval = setInterval(() => {
                setElapsed(Math.round((Date.now() - startTime) / 1000));
            }, 1000);
        } else if (!isProcessing && startTime) {
            setElapsed(Math.round((Date.now() - startTime) / 1000));
        }
        return () => clearInterval(interval);
    }, [isProcessing, startTime]);

    // Auto-scroll thoughts when expanded
    useEffect(() => {
        if (isExpanded && containerRef.current) {
            containerRef.current.scrollTop = containerRef.current.scrollHeight;
        }
    }, [thoughts, isExpanded]);

    const STATUS_MAP = {
        'ROUTER_NODE': 'Routing Tactical Request...',
        'BLUEPRINT_NODE': 'Architecting Mission Blueprints...',
        'EXECUTOR_NODE': 'Executing Commands...',
        'COMPLETE': 'Neural Processing Complete',
        'IDLE': 'System Standby'
    };

    const displayStatus = STATUS_MAP[currentStatus?.toUpperCase()] || 'Establishing Secure Handshake...';

    // Fix: Show component if tools are used, even if not processing/thinking
    const hasTools = usedTools && usedTools.length > 0;
    const shouldShow = isProcessing || thoughts || hasTools;

    if (architectureMode === 'normal' && !thoughts && !hasTools) return null;
    if (!shouldShow) return null;

    return (
        <div className="thinking-block-container group/thinking border-t border-white/5">
            {/* Cyber Border Decoration */}
            <div className="absolute top-0 left-0 w-full h-[1px] bg-gradient-to-r from-transparent via-teal-500/30 to-transparent"></div>

            <button
                onClick={() => setIsExpanded(!isExpanded)}
                className="thinking-header-toggle !px-8 !py-5 hover:bg-white/[0.02] transition-all"
            >
                <div className="flex items-center gap-8 flex-1">
                    <div className="thinking-icon-container relative">
                        <Brain size={16} className={isProcessing ? "text-teal-400 animate-pulse" : "text-slate-600"} />
                        {isProcessing && <div className="absolute inset-0 bg-teal-500/10 rounded-full animate-pulse"></div>}
                    </div>

                    <div className="flex flex-col items-start gap-1.5 min-w-0">
                        <div className="flex items-center gap-3">
                            <span className="text-[10px] font-black pointer-events-none text-slate-500 uppercase tracking-[0.25em] group-hover/thinking:text-teal-400 transition-colors">
                                {architectureMode === 'multi' ? 'NEURAL_MATRIX_CORE' : 'NORMAL_UPLINK'}
                            </span>
                            {isProcessing && (
                                <div className="flex gap-1">
                                    <div className="w-0.5 h-3 bg-teal-500/80 animate-[bounce_1s_infinite]"></div>
                                    <div className="w-0.5 h-3 bg-teal-500/40 animate-[bounce_1s_infinite_0.2s]"></div>
                                    <div className="w-0.5 h-3 bg-teal-500/20 animate-[bounce_1s_infinite_0.4s]"></div>
                                </div>
                            )}
                        </div>

                        <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
                            {/* Node Info */}
                            <div className="flex items-center gap-2">
                                <span className="text-[8px] font-mono text-slate-600 uppercase tracking-widest font-bold">Node:</span>
                                <span className="text-[11px] font-mono font-black text-slate-300 tracking-wide underline decoration-teal-500/30 underline-offset-4">
                                    {activeNode || (isProcessing ? 'COGNITIVE_REASONING' : 'LOGIC_COMMITTED')}
                                </span>
                            </div>

                            {/* Model Info */}
                            {activeModel && (
                                <div className="flex items-center gap-2 border-l border-white/10 pl-4">
                                    <span className="text-[8px] font-mono text-slate-600 uppercase tracking-widest font-bold">Interface:</span>
                                    <span className="text-[10px] font-mono font-black text-teal-400/80 tracking-widest">
                                        {activeModel.toUpperCase()}
                                    </span>
                                </div>
                            )}

                            {/* Active Tools */}
                            {usedTools && usedTools.length > 0 && (
                                <div className="flex flex-wrap items-center gap-2 border-l border-white/10 pl-4">
                                    <span className="text-[8px] font-mono text-slate-600 uppercase tracking-widest font-bold">Tools_Engagement:</span>
                                    <div className="flex gap-1.5">
                                        {usedTools.map((tool, i) => (
                                            <div key={i} className="flex items-center gap-1.5 px-2 py-0.5 bg-teal-500/5 border border-teal-500/20 rounded-md">
                                                <div className="w-1 h-1 rounded-full bg-teal-500 animate-pulse"></div>
                                                <span className="text-[9px] font-mono font-black text-teal-400/90 uppercase">{tool}</span>
                                            </div>
                                        ))}
                                    </div>
                                </div>
                            )}

                            {/* Transmission Details */}
                            {isProcessing && (
                                <div className="flex items-center gap-3 border-l border-white/10 pl-4">
                                    <div className="flex items-center gap-1">
                                        <div className="w-2 h-0.5 bg-teal-500/40"></div>
                                        <span className="text-[7px] font-mono text-teal-500/60 uppercase font-black tracking-tighter">TX</span>
                                    </div>
                                    <div className="flex gap-0.5">
                                        {[...Array(4)].map((_, i) => (
                                            <div 
                                                key={i} 
                                                className="w-1 h-2 bg-teal-500/30"
                                                style={{ 
                                                    animation: `rx-tx-pulse 0.6s infinite ${i * 0.1}s`,
                                                    clipPath: 'polygon(0 0, 100% 0, 100% 100%, 0 80%)'
                                                }}
                                            ></div>
                                        ))}
                                    </div>
                                    <div className="flex items-center gap-1">
                                        <span className="text-[7px] font-mono text-teal-500/60 uppercase font-black tracking-tighter">RX</span>
                                        <div className="w-2 h-0.5 bg-teal-500/40"></div>
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>
                </div>

                <div className="flex items-center gap-6 pr-2">
                    <div className="flex flex-col items-end">
                         <div className="flex items-center gap-2">
                            <span className="text-[8px] font-mono text-slate-600 uppercase tracking-widest font-bold">Uplink_Lock</span>
                            <span className="text-[9px] font-mono text-teal-500/80 bg-teal-500/10 px-2 py-0.5 rounded border border-teal-500/20 font-black">
                                {elapsed}s_SYNC
                            </span>
                         </div>
                        {isProcessing && (
                            <div className="flex items-center gap-2 mt-1">
                                <span className="text-[7px] font-mono text-slate-600 uppercase tracking-widest animate-pulse">Streaming_Nodal_Telemetry</span>
                                <div className="w-8 h-[1px] bg-gradient-to-r from-teal-500/50 to-transparent"></div>
                            </div>
                        )}
                    </div>

                    <div className="flex items-center justify-center w-8 h-8 rounded-full hover:bg-white/5 transition-all group-hover/thinking:border border-white/5">
                        {isExpanded ? <ChevronDown size={14} className="text-slate-500 group-hover/thinking:text-teal-400" /> : <ChevronRight size={14} className="text-slate-500 group-hover/thinking:text-teal-400" />}
                    </div>
                </div>
            </button>

            <AnimatePresence>
                {isExpanded && (
                    <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        className="thinking-content-wrapper"
                    >
                        <div className="thinking-content h-[320px] relative overflow-y-auto custom-scrollbar-minimal px-8 py-6" ref={containerRef}>
                            {/* Background Graph Decoration */}
                            <div className="absolute right-10 top-1/2 -translate-y-1/2 opacity-5 pointer-events-none">
                                <svg width="200" height="100" viewBox="0 0 200 100">
                                    <path d="M0,50 L20,50 L30,20 L40,80 L50,50 L200,50" fill="none" stroke="currentColor" strokeWidth="2" className="text-teal-500" />
                                </svg>
                            </div>

                            <div className="w-full relative z-10">
                                {thoughts ? (
                                    <div className="thinking-text">
                                        <ReactMarkdown
                                            remarkPlugins={[remarkGfm]}
                                            components={{
                                                p: ({ children }) => (
                                                    <div className="flex gap-3 mb-4 group/line">
                                                        <div className="thinking-indented-line"></div>
                                                        <p className="flex-1">{children}</p>
                                                    </div>
                                                ),
                                                code: ({ node, inline, className, children, ...props }) => (
                                                    <code className="bg-white/5 text-teal-300 px-1.5 py-0.5 rounded text-[11px] font-bold border border-white/10" {...props}>
                                                        {children}
                                                    </code>
                                                )
                                            }}
                                        >
                                            {thoughts}
                                        </ReactMarkdown>
                                    </div>
                                ) : (
                                    <div className="flex flex-col gap-6 pt-8 opacity-60">
                                        <div className="flex items-center gap-3 text-slate-500 font-mono text-xs uppercase tracking-widest pl-2 border-l-2 border-teal-500/30">
                                            <Terminal size={14} />
                                            <span className="font-bold">{displayStatus}</span>
                                        </div>
                                        <div className="w-48 h-1 bg-white/10 rounded-full overflow-hidden ml-2">
                                            <div className="w-1/3 h-full bg-teal-500/50 animate-[shimmer_2s_infinite]"></div>
                                        </div>
                                        <p className="text-[10px] font-mono text-slate-700 uppercase tracking-[0.2em] ml-2">
                                            Awaiting cognitive packet stream...
                                        </p>
                                    </div>
                                )}
                            </div>
                        </div>

                        {/* Footer Status Bar */}
                        <div className="bg-black/40 border-t border-white/5 px-6 py-2 flex justify-between items-center">
                            <span className="text-[9px] font-mono text-slate-600 uppercase tracking-widest">Mem_Pool: Active</span>
                            <div className="flex gap-1 opacity-30">
                                {[...Array(5)].map((_, i) => <div key={i} className="w-0.5 h-2 bg-teal-500"></div>)}
                            </div>
                        </div>
                    </motion.div>
                )}
            </AnimatePresence>
        </div>
    );
};


export default React.memo(NeuralCore);
