// MYTH Desktop — Product Activation Screen (Feature 9)
// Full-screen activation form shown before main app loads.

import React, { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';

export default function ActivationScreen({ onActivate }) {
    const [key, setKey] = useState('');
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState(null);
    const [success, setSuccess] = useState(false);

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
                setError(result.error || 'Invalid activation key');
            }
        } catch (err) {
            setError('Server unreachable. Please check your internet connection.');
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="fixed inset-0 bg-[#06060a] flex items-center justify-center z-[9999] overflow-hidden">
            {/* Animated background */}
            <div className="absolute inset-0">
                <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyan-500/5 rounded-full blur-[120px] animate-pulse" />
                <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-purple-500/5 rounded-full blur-[120px] animate-pulse" />
                <div className="absolute inset-0" style={{
                    backgroundImage: 'radial-gradient(circle at 1px 1px, rgba(255,255,255,0.03) 1px, transparent 0)',
                    backgroundSize: '40px 40px'
                }} />
            </div>

            <motion.div
                initial={{ opacity: 0, y: 20, scale: 0.95 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                transition={{ duration: 0.5, ease: 'easeOut' }}
                className="relative w-full max-w-md mx-4"
            >
                {/* Card */}
                <div className="bg-gray-900/70 backdrop-blur-xl border border-gray-700/40 rounded-2xl p-8 shadow-2xl">
                    {/* Logo */}
                    <div className="text-center mb-8">
                        <div className="text-5xl mb-3">⌬</div>
                        <h1 className="text-2xl font-bold text-white tracking-tight">MYTH</h1>
                        <p className="text-gray-500 text-sm mt-1">MYTH Tools Platform</p>
                    </div>

                    {/* Activation heading */}
                    <div className="text-center mb-6">
                        <h2 className="text-lg font-semibold text-gray-200">Product Activation</h2>
                        <p className="text-gray-500 text-xs mt-1">Enter your activation key to continue</p>
                    </div>

                    <AnimatePresence mode="wait">
                        {success ? (
                            <motion.div
                                key="success"
                                initial={{ opacity: 0, scale: 0.9 }}
                                animate={{ opacity: 1, scale: 1 }}
                                className="text-center py-6"
                            >
                                <div className="text-4xl mb-3">✓</div>
                                <p className="text-emerald-400 font-medium">License Activated Successfully</p>
                                <p className="text-gray-500 text-xs mt-2">Initializing MYTH...</p>
                                <div className="mt-4 w-32 h-1 bg-gray-800 rounded-full overflow-hidden mx-auto">
                                    <div className="h-full bg-emerald-500 rounded-full animate-[grow_1s_ease-out_forwards]"
                                        style={{ animation: 'grow 1s ease-out forwards' }} />
                                </div>
                            </motion.div>
                        ) : (
                            <motion.form key="form" onSubmit={handleSubmit}>
                                {/* Key input */}
                                <div className="mb-4">
                                    <input
                                        type="text"
                                        value={key}
                                        onChange={(e) => {
                                            setKey(e.target.value.toUpperCase());
                                            setError(null);
                                        }}
                                        placeholder="XXXX-XXXX-XXXX-XXXX"
                                        className="w-full px-4 py-3 bg-gray-800/60 border border-gray-600/40 rounded-lg text-white text-center tracking-widest font-mono text-lg placeholder:text-gray-600 placeholder:tracking-wider focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all"
                                        disabled={loading}
                                        autoFocus
                                        spellCheck={false}
                                    />
                                </div>

                                {/* Error message */}
                                <AnimatePresence>
                                    {error && (
                                        <motion.div
                                            initial={{ opacity: 0, height: 0 }}
                                            animate={{ opacity: 1, height: 'auto' }}
                                            exit={{ opacity: 0, height: 0 }}
                                            className="mb-4 px-3 py-2 bg-red-950/30 border border-red-500/20 rounded-lg"
                                        >
                                            <p className="text-red-400 text-xs text-center">{error}</p>
                                        </motion.div>
                                    )}
                                </AnimatePresence>

                                {/* Submit button */}
                                <button
                                    type="submit"
                                    disabled={!key.trim() || loading}
                                    className="w-full py-3 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 disabled:from-gray-700 disabled:to-gray-700 disabled:text-gray-500 text-white font-semibold rounded-lg transition-all duration-200 flex items-center justify-center gap-2"
                                >
                                    {loading ? (
                                        <>
                                            <svg className="w-4 h-4 animate-spin" fill="none" viewBox="0 0 24 24">
                                                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                                                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                                            </svg>
                                            Verifying...
                                        </>
                                    ) : (
                                        'Activate License'
                                    )}
                                </button>
                            </motion.form>
                        )}
                    </AnimatePresence>

                    {/* Footer */}
                    <div className="mt-6 pt-4 border-t border-gray-800/50">
                        <p className="text-gray-600 text-[10px] text-center">
                            This license is bound to your hardware. Contact support for reactivation.
                        </p>
                    </div>
                </div>
            </motion.div>
        </div>
    );
}
