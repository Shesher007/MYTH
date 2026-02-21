// MYTH Desktop — Hardened Product Activation Screen (v2.0)
// Industrial-grade UI with hardware fingerprinting and cyber-aesthetic chassis.

import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { invoke } from '@tauri-apps/api/core';

const CyberBackground = () => (
    <div className="absolute inset-0 overflow-hidden pointer-events-none">
        {/* Deep Field */}
        <div className="absolute inset-0 bg-[#020205]" />

        {/* Core Glow */}
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-cyan-500/5 rounded-full blur-[120px] animate-pulse" />

        {/* Industrial Grid */}
        <div className="absolute inset-0 opacity-[0.03]" style={{
            backgroundImage: `linear-gradient(rgba(20, 184, 166, 0.5) 1px, transparent 1px), linear-gradient(90deg, rgba(20, 184, 166, 0.5) 1px, transparent 1px)`,
            backgroundSize: '40px 40px'
        }} />

        {/* Binary Rain / Telemetry Pulse (Subtle) */}
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,transparent_0%,rgba(0,0,0,0.4)_100%)]" />

        {/* Scanning Beam */}
        <motion.div
            animate={{ translateY: ['-100%', '200%'] }}
            transition={{ duration: 8, repeat: Infinity, ease: "linear" }}
            className="absolute top-0 left-0 right-0 h-[300px] bg-gradient-to-b from-transparent via-cyan-500/5 to-transparent skew-y-12 pointer-events-none"
        />
    </div>
);

const HUDCorner = ({ className }) => (
    <div className={`absolute w-4 h-4 border-cyan-500/40 pointer-events-none ${className}`} />
);

export default function ActivationScreen({ onActivate }) {
    const [key, setKey] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
    const [success, setSuccess] = useState(false);
    const [machineId, setMachineId] = useState('FETCHING...');

    useEffect(() => {
        // Fetch machine ID on mount for hardware binding awareness
        const fetchId = async () => {
            try {
                const id = await invoke('get_machine_id');
                // Mask the ID for security/aesthetic: XXXX-...-XXXX
                const masked = id.length > 12 ? `${id.slice(0, 6)}...${id.slice(-6)}` : id;
                setMachineId(masked.toUpperCase());
            } catch (err) {
                console.error("Failed to fetch hardware ID:", err);
                setMachineId("UNKNOWN_HWID");
            }
        };
        fetchId();
    }, []);

    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!key.trim() || loading) return;

        setLoading(true);
        setError(null);

        try {
            const result = await onActivate(key.trim());
            if (result.success) {
                setSuccess(true);
            } else {
                setError(result.error || 'INVALID ACTIVATION SIGNATURE');
            }
        } catch {
            setError('NEURAL LINK FAILURE: SERVICE UNREACHABLE');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="fixed inset-0 flex items-center justify-center z-[9999] font-sans selection:bg-cyan-500/30">
            <CyberBackground />

            <motion.div
                initial={{ opacity: 0, scale: 0.9, rotateX: 20 }}
                animate={{ opacity: 1, scale: 1, rotateX: 0 }}
                transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
                className="relative w-full max-w-lg mx-4"
                style={{ perspective: '1000px' }}
            >
                {/* Industrial Chassis */}
                <div className="relative bg-[#0a0a0f]/80 backdrop-blur-2xl border border-white/5 p-1 rounded-2xl overflow-hidden shadow-[0_0_50px_rgba(0,0,0,0.5)]">
                    {/* Inner Notched Border */}
                    <div className="absolute inset-0 border border-cyan-500/10 rounded-2xl pointer-events-none" />

                    {/* HUD Decorative Elements */}
                    <HUDCorner className="top-0 left-0 border-t border-l" />
                    <HUDCorner className="top-0 right-0 border-t border-r" />
                    <HUDCorner className="bottom-0 left-0 border-b border-l" />
                    <HUDCorner className="bottom-0 right-0 border-b border-r" />

                    <div className="relative p-10">
                        {/* Header Section */}
                        <div className="text-center mb-10">
                            <motion.div
                                animate={{ opacity: [0.4, 1, 0.4] }}
                                transition={{ duration: 4, repeat: Infinity }}
                                className="inline-block text-5xl mb-4 text-cyan-500 drop-shadow-[0_0_15px_rgba(6,182,212,0.5)]"
                            >
                                ⌬
                            </motion.div>
                            <h1 className="text-3xl font-black text-white tracking-widest uppercase">
                                MYTH<span className="text-cyan-500">.CORE</span>
                            </h1>
                            <div className="flex items-center justify-center gap-2 mt-2">
                                <span className="w-1 h-1 bg-cyan-500 rounded-full animate-pulse" />
                                <p className="text-cyan-500/60 font-mono text-[10px] tracking-[0.3em] uppercase">Tactical Neural Interface</p>
                                <span className="w-1 h-1 bg-cyan-500 rounded-full animate-pulse" />
                            </div>
                        </div>

                        {/* Status Label */}
                        <div className="flex items-center justify-between mb-8 px-1">
                            <div className="flex flex-col">
                                <span className="text-[9px] font-bold text-gray-500 uppercase tracking-tighter">System Status</span>
                                <span className="text-xs font-mono text-cyan-400 font-bold">LOCKED_MODE</span>
                            </div>
                            <div className="text-right flex flex-col items-end">
                                <span className="text-[9px] font-bold text-gray-500 uppercase tracking-tighter">Hardware ID</span>
                                <span className="text-xs font-mono text-gray-400">{machineId}</span>
                            </div>
                        </div>

                        <AnimatePresence mode="wait">
                            {success ? (
                                <motion.div
                                    key="success"
                                    initial={{ opacity: 0, y: 10 }}
                                    animate={{ opacity: 1, y: 0 }}
                                    className="text-center py-8"
                                >
                                    <div className="w-16 h-16 bg-emerald-500/10 border border-emerald-500/30 rounded-full flex items-center justify-center mx-auto mb-6">
                                        <motion.div
                                            initial={{ scale: 0 }}
                                            animate={{ scale: 1 }}
                                            className="text-2xl text-emerald-500"
                                        >
                                            ✓
                                        </motion.div>
                                    </div>
                                    <h3 className="text-xl font-bold text-white mb-2">NEURAL LINK VERIFIED</h3>
                                    <p className="text-gray-500 text-sm">Synchronizing core modules...</p>

                                    <div className="mt-8 relative h-1 bg-white/5 rounded-full overflow-hidden">
                                        <motion.div
                                            initial={{ width: 0 }}
                                            animate={{ width: '100%' }}
                                            transition={{ duration: 1.5 }}
                                            className="absolute inset-0 bg-gradient-to-r from-cyan-500 to-emerald-500"
                                        />
                                    </div>
                                </motion.div>
                            ) : (
                                <motion.form
                                    key="form"
                                    onSubmit={handleSubmit}
                                    initial={{ opacity: 0 }}
                                    animate={{ opacity: 1 }}
                                >
                                    <div className="space-y-6">
                                        {/* Input Chassis */}
                                        <div className="relative group">
                                            <div className="absolute -inset-0.5 bg-cyan-500/20 rounded-xl blur opacity-0 group-focus-within:opacity-100 transition duration-500" />
                                            <div className="relative flex items-center">
                                                <input
                                                    type="text"
                                                    value={key}
                                                    onChange={(e) => {
                                                        setKey(e.target.value.toUpperCase());
                                                        setError(null);
                                                    }}
                                                    placeholder="MYTH-XXXX-XXXX-XXXX-XXXX"
                                                    className="w-full h-14 px-6 bg-[#050508] border border-white/10 rounded-xl text-white text-center tracking-[0.2em] font-mono text-lg placeholder:text-gray-700 placeholder:tracking-normal focus:outline-none focus:border-cyan-500/50 transition-all"
                                                    disabled={loading}
                                                    autoFocus
                                                    spellCheck={false}
                                                />
                                            </div>
                                        </div>

                                        {/* Error Alert */}
                                        <AnimatePresence>
                                            {error && (
                                                <motion.div
                                                    initial={{ opacity: 0, scale: 0.95 }}
                                                    animate={{ opacity: 1, scale: 1 }}
                                                    exit={{ opacity: 0, scale: 0.95 }}
                                                    className="p-3 bg-red-500/5 border border-red-500/20 rounded-lg flex items-center gap-3"
                                                >
                                                    <span className="text-red-500 font-bold text-xs font-mono">[!]</span>
                                                    <p className="text-red-400 text-[10px] font-bold uppercase tracking-wider">{error}</p>
                                                </motion.div>
                                            )}
                                        </AnimatePresence>

                                        {/* Action Button */}
                                        <button
                                            type="submit"
                                            disabled={!key.trim() || loading}
                                            className="relative w-full h-14 overflow-hidden group disabled:opacity-50"
                                        >
                                            <div className="absolute inset-0 bg-cyan-600 transition-transform duration-300 group-hover:scale-105" />
                                            <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/10 to-transparent -translate-x-full group-hover:translate-x-full transition-transform duration-1000" />

                                            <span className="relative flex items-center justify-center gap-3 text-white font-black text-sm uppercase tracking-[0.2em]">
                                                {loading ? (
                                                    <>
                                                        <span className="w-4 h-4 border-2 border-white/20 border-t-white rounded-full animate-spin" />
                                                        VERIFYING_KEY
                                                    </>
                                                ) : (
                                                    'INITIALIZE_CORE'
                                                )}
                                            </span>
                                        </button>
                                    </div>
                                </motion.form>
                            )}
                        </AnimatePresence>

                        {/* Industrial Footer */}
                        <div className="mt-10 flex items-center justify-between opacity-30">
                            <div className="h-[1px] flex-1 bg-gradient-to-r from-transparent to-cyan-500/30" />
                            <span className="mx-4 text-[7px] font-mono text-cyan-500 tracking-[0.4em] uppercase">Hardware_Lock_Active</span>
                            <div className="h-[1px] flex-1 bg-gradient-to-l from-transparent to-cyan-500/30" />
                        </div>

                        <p className="mt-4 text-[8px] text-center text-gray-600 uppercase tracking-widest font-medium">
                            Authorized personnel only. All access attempts are logged and monitored.
                        </p>
                    </div>
                </div>
            </motion.div>

            {/* Version Badge (Bottom Right) */}
            <div className="fixed bottom-6 right-6 font-mono text-[9px] text-gray-600 tracking-tighter">
                BUILD_SIG: <span className="text-gray-400">0xmyth_v1.1.6</span>
            </div>
        </div>
    );
}
