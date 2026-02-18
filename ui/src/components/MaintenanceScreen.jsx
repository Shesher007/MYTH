// MYTH Desktop — Maintenance Mode Screen (Feature 7)
// Shown when server signals maintenance mode.

import React from 'react';
import { motion } from 'framer-motion';

export default function MaintenanceScreen({ info }) {
    return (
        <div className="fixed inset-0 bg-[#06060a] flex items-center justify-center z-[9999]">
            {/* Background */}
            <div className="absolute inset-0">
                <div className="absolute top-1/3 left-1/2 -translate-x-1/2 w-[500px] h-[500px] bg-amber-500/3 rounded-full blur-[150px]" />
            </div>

            <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className="relative text-center max-w-lg mx-4"
            >
                <div className="text-6xl mb-6">🚧</div>
                <h1 className="text-2xl font-bold text-white mb-3">System Maintenance</h1>
                <p className="text-gray-400 mb-6">
                    {info?.message || 'MYTH is currently undergoing scheduled maintenance. Please try again later.'}
                </p>

                {info?.estimated_end && (
                    <div className="inline-flex items-center gap-2 px-4 py-2 bg-gray-900/60 border border-gray-700/40 rounded-lg">
                        <span className="text-gray-500 text-sm">Estimated return:</span>
                        <span className="text-amber-400 text-sm font-mono">{info.estimated_end}</span>
                    </div>
                )}

                <div className="mt-8">
                    <div className="flex items-center justify-center gap-2 text-gray-600 text-xs">
                        <span className="w-2 h-2 bg-amber-500/60 rounded-full animate-pulse" />
                        We'll be back shortly
                    </div>
                </div>
            </motion.div>
        </div>
    );
}
