import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Search, Terminal, Zap } from 'lucide-react';

const CommandPalette = ({ isOpen, onClose, actions }) => {
    const [query, setQuery] = useState('');
    const [selectedIndex, setSelectedIndex] = useState(0);
    const inputRef = useRef(null);

    const filteredActions = actions.filter(action =>
        action.label.toLowerCase().includes(query.toLowerCase())
    );

    useEffect(() => {
        if (isOpen) {
            setQuery('');
            setSelectedIndex(0);
            setTimeout(() => inputRef.current?.focus(), 100);
        }
    }, [isOpen]);

    const handleKeyDown = (e) => {
        if (e.key === 'ArrowDown') {
            setSelectedIndex(prev => (prev + 1) % filteredActions.length);
            e.preventDefault();
        } else if (e.key === 'ArrowUp') {
            setSelectedIndex(prev => (prev - 1 + filteredActions.length) % filteredActions.length);
            e.preventDefault();
        } else if (e.key === 'Enter') {
            if (filteredActions[selectedIndex]) {
                filteredActions[selectedIndex].run();
                onClose();
            }
        } else if (e.key === 'Escape') {
            onClose();
        }
    };

    return (
        <AnimatePresence>
            {isOpen && (
                <div className="fixed inset-0 z-[1000] flex items-start justify-center pt-[15vh] px-4">
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="absolute inset-0 bg-black/80 backdrop-blur-md"
                        onClick={onClose}
                    />

                    <motion.div
                        initial={{ scale: 0.95, opacity: 0, y: -20 }}
                        animate={{ scale: 1, opacity: 1, y: 0 }}
                        exit={{ scale: 0.95, opacity: 0, y: -20 }}
                        className="relative w-[min(95vw,36rem)] bg-[#0d0d16] border border-white/10 rounded-lg shadow-2xl overflow-hidden"
                    >
                        <div className="flex items-center px-4 py-3 border-b border-white/5 bg-black/20">
                            <Search size={18} className="text-teal-500/60 mr-3" />
                            <input
                                ref={inputRef}
                                id="command-palette-input"
                                name="command-palette-query"
                                type="text"
                                value={query}
                                onChange={(e) => setQuery(e.target.value)}
                                onKeyDown={handleKeyDown}
                                placeholder="Execute command..."
                                className="w-full bg-transparent border-none outline-none text-slate-200 font-mono text-xs md:text-sm placeholder:text-slate-600"
                            />
                            <div className="flex items-center gap-1.5 px-2 py-0.5 rounded border border-white/5 bg-white/[0.02]">
                                <span className="text-[9px] font-mono text-slate-500">ESC</span>
                            </div>
                        </div>

                        <div className="max-h-[350px] overflow-y-auto py-2 custom-scrollbar-minimal">
                            {filteredActions.length > 0 ? (
                                filteredActions.map((action, idx) => (
                                    <button
                                        key={action.id}
                                        onClick={() => { action.run(); onClose(); }}
                                        onMouseEnter={() => setSelectedIndex(idx)}
                                        className={`w-full flex items-center justify-between px-4 py-3 transition-colors ${idx === selectedIndex ? 'bg-teal-500/10 text-teal-400' : 'text-slate-400 hover:text-slate-200'
                                            }`}
                                    >
                                        <div className="flex items-center gap-4">
                                            <div className={`p-2 rounded bg-black/40 ring-1 ${idx === selectedIndex ? 'ring-teal-500/40' : 'ring-white/5'}`}>
                                                {action.icon}
                                            </div>
                                            <div className="flex flex-col items-start">
                                                <span className="text-[11px] font-black uppercase tracking-wider">{action.label}</span>
                                                <span className="text-[9px] font-mono opacity-60 lowercase">{action.description}</span>
                                            </div>
                                        </div>
                                        {idx === selectedIndex && (
                                            <div className="flex items-center gap-1 text-[9px] font-mono opacity-60">
                                                <span>ENTER</span>
                                                <Zap size={10} className="fill-current" />
                                            </div>
                                        )}
                                    </button>
                                ))
                            ) : (
                                <div className="px-6 py-10 flex flex-col items-center justify-center text-slate-600">
                                    <Terminal size={32} className="mb-4 opacity-10" />
                                    <span className="text-[10px] font-black uppercase tracking-widest italic">No matches found for {query}</span>
                                </div>
                            )}
                        </div>

                        <div className="px-4 py-2 bg-black/40 border-t border-white/5 flex items-center justify-between">
                            <div className="flex items-center gap-4">
                                <span className="text-[9px] font-mono text-slate-600"><span className="text-teal-500/40">↑↓</span> NAVIGATE</span>
                                <span className="text-[9px] font-mono text-slate-600"><span className="text-teal-500/40">↵</span> EXECUTE</span>
                            </div>
                            <span className="text-[9px] font-mono text-slate-600 uppercase">SYS.CORE_HANDSHAKE: OK</span>
                        </div>
                    </motion.div>
                </div>
            )}
        </AnimatePresence>
    );
};

export default CommandPalette;
