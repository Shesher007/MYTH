// MYTH Desktop — Update Prompt (Features 5-6)
// Modal for available updates + forced update blocker.

import React, { useState } from 'react';
import { motion } from 'framer-motion';

export default function UpdatePrompt({ info, forced = false, onDismiss }) {
    const [restarting, setRestarting] = useState(false);

    const handleUpdate = async () => {
        setRestarting(true);
        try {
            const { relaunch } = await import('@tauri-apps/plugin-process');
            await relaunch();
        } catch (e) {
            console.error('Relaunch failed:', e);
            setRestarting(false);
        }
    };

    // Forced update — blocks usage
    if (forced) {
        return (
            <div className="fixed inset-0 bg-[#06060a] flex items-center justify-center z-[9999]">
                <motion.div
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    className="text-center max-w-lg mx-4"
                >
                    <div className="text-5xl mb-4">⬆️</div>
                    <h1 className="text-xl font-bold text-white mb-2">Update Required</h1>
                    <p className="text-gray-400 text-sm mb-6">
                        Your version (v{info?.current_version}) is below the minimum required version (v{info?.minimum_version}).
                        Please update to continue using MYTH.
                    </p>

                    <button
                        onClick={handleUpdate}
                        disabled={restarting}
                        className="px-6 py-2.5 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-medium rounded-lg transition-all"
                    >
                        {restarting ? 'Restarting...' : 'Update & Restart'}
                    </button>

                    {info?.changelog && (
                        <div className="mt-6 text-left bg-gray-900/50 border border-gray-800 rounded-lg p-4 max-h-40 overflow-y-auto">
                            <p className="text-gray-500 text-xs mb-2">What's new in v{info.latest_version}:</p>
                            <p className="text-gray-300 text-xs whitespace-pre-wrap">{info.changelog}</p>
                        </div>
                    )}
                </motion.div>
            </div>
        );
    }

    // Optional update — dismissible
    return (
        <motion.div
            initial={{ opacity: 0, y: -20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            className="fixed top-4 right-4 z-[9990] w-80 bg-gray-900/90 backdrop-blur-md border border-gray-700/50 rounded-xl p-4 shadow-2xl"
        >
            <div className="flex items-start justify-between mb-2">
                <div className="flex items-center gap-2">
                    <span className="text-lg">🆕</span>
                    <h3 className="text-sm font-semibold text-white">Update Available</h3>
                </div>
                {onDismiss && (
                    <button onClick={onDismiss} className="text-gray-500 hover:text-gray-300 text-xs">✕</button>
                )}
            </div>

            <p className="text-gray-400 text-xs mb-3">
                v{info?.current_version} → v{info?.latest_version}
            </p>

            <div className="flex gap-2">
                <button
                    onClick={handleUpdate}
                    disabled={restarting}
                    className="flex-1 py-1.5 bg-cyan-600/80 hover:bg-cyan-500 text-white text-xs font-medium rounded-lg transition-all"
                >
                    {restarting ? 'Restarting...' : 'Restart & Update'}
                </button>
                {onDismiss && (
                    <button
                        onClick={onDismiss}
                        className="py-1.5 px-3 bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs rounded-lg transition-all"
                    >
                        Later
                    </button>
                )}
            </div>
        </motion.div>
    );
}
