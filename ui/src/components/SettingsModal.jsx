import React, { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Shield, Cpu, Key, Save, AlertTriangle, Eye, EyeOff, CheckCircle2, CircleDashed } from 'lucide-react';
import { useSoundscape } from '../hooks/useSoundscape';

const SettingsModal = ({ isOpen, onClose, settingsKeys, onSave }) => {
    const { playTick, playChirp, playSuccess } = useSoundscape();
    const [localKeys, setLocalKeys] = useState({
        nvidia_api_key: '',
        mistral_api_key: ''
    });
    const [visibility, setVisibility] = useState({
        nvidia: false,
        mistral: false
    });
    const [isSaving, setIsSaving] = useState(false);

    useEffect(() => {
        if (isOpen) {
            setLocalKeys({
                nvidia_api_key: '',
                mistral_api_key: ''
            });
            playTick();
        }
    }, [isOpen]);

    const handleSave = async () => {
        playChirp();
        setIsSaving(true);
        // Only send keys that were actually typed
        const payload = {};
        if (localKeys.nvidia_api_key) payload.nvidia_api_key = localKeys.nvidia_api_key;
        if (localKeys.mistral_api_key) payload.mistral_api_key = localKeys.mistral_api_key;
        
        const success = await onSave(payload);
        setIsSaving(false);
        if (success) {
            playSuccess();
            onClose();
        }
    };

    const toggleVisibility = (key) => {
        playTick();
        setVisibility(prev => ({ ...prev, [key]: !prev[key] }));
    };

    if (!isOpen) return null;

    const renderKeyField = (id, label, Icon, colorClass, value, placeholder, isVisible, onToggle) => {
        const isConfigured = !!settingsKeys[id];
        
        return (
            <div className="space-y-2">
                <div className="flex items-center justify-between px-1">
                    <label className="flex items-center gap-2 text-[10px] font-black text-slate-500 uppercase tracking-widest">
                        <Icon size={12} className={`${colorClass}/50`} />
                        {label}
                    </label>
                    <div className="flex items-center gap-2">
                        {isConfigured ? (
                            <div className="flex items-center gap-1.5 px-1.5 py-0.5 rounded bg-teal-500/10 border border-teal-500/20">
                                <CheckCircle2 size={8} className="text-teal-500" />
                                <span className="text-[7px] font-black text-teal-500 uppercase">Live</span>
                            </div>
                        ) : (
                            <div className="flex items-center gap-1.5 px-1.5 py-0.5 rounded bg-slate-800 border border-white/5">
                                <CircleDashed size={8} className="text-slate-600" />
                                <span className="text-[7px] font-black text-slate-600 uppercase">Missing</span>
                            </div>
                        )}
                    </div>
                </div>
                <div className="relative group">
                    <input
                        type={isVisible ? "text" : "password"}
                        value={value}
                        onChange={(e) => setLocalKeys({...localKeys, [id]: e.target.value})}
                        className={`w-full bg-black/40 border border-white/5 focus:border-${colorClass.split('-')[1]}-500/50 rounded-lg px-4 py-3 text-xs text-slate-200 placeholder:text-slate-800 transition-all outline-none font-mono pr-20`}
                        placeholder={isConfigured ? `Masked: ${settingsKeys[id]}` : "UNCONFIGURED"}
                    />
                    <div className="absolute right-2 top-1/2 -translate-y-1/2 flex items-center gap-1">
                        <button 
                            onClick={() => onToggle(id.split('_')[0])}
                            className="p-1.5 text-slate-700 hover:text-slate-400 hover:bg-white/5 rounded transition-all"
                            title={isVisible ? "Hide Key" : "Show Key"}
                        >
                            {isVisible ? <EyeOff size={14} /> : <Eye size={14} />}
                        </button>
                        <div className="w-[1px] h-4 bg-white/5 mx-1" />
                        <Key className="text-slate-800 group-focus-within:text-teal-500/30 transition-colors" size={14} />
                    </div>
                </div>
            </div>
        );
    };

    return (
        <AnimatePresence>
            <div className="fixed inset-0 z-[1000] flex items-center justify-center p-4">
                <motion.div
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    exit={{ opacity: 0 }}
                    onClick={onClose}
                    className="absolute inset-0 bg-black/80 backdrop-blur-md"
                />
                
                <motion.div
                    initial={{ scale: 0.9, opacity: 0, y: 20 }}
                    animate={{ scale: 1, opacity: 1, y: 0 }}
                    exit={{ scale: 0.9, opacity: 0, y: 20 }}
                    className="relative w-full max-w-lg bg-[#0a0a0f] border border-teal-500/20 rounded-xl shadow-[0_0_50px_rgba(20,184,166,0.15)] overflow-hidden"
                >
                    {/* Header */}
                    <div className="flex items-center justify-between px-6 py-4 border-b border-white/5 bg-black/40 backdrop-blur-xl">
                        <div className="flex items-center gap-3">
                            <Shield size={18} className="text-teal-500" />
                            <h2 className="text-sm font-black uppercase tracking-[0.3em] text-white">System Configuration</h2>
                        </div>
                        <button onClick={onClose} className="p-2 hover:bg-white/5 rounded-lg text-slate-500 hover:text-white transition-colors">
                            <X size={18} />
                        </button>
                    </div>

                    <div className="p-6 space-y-6">
                        <div className="p-3 bg-teal-500/5 border border-teal-500/10 rounded-lg flex gap-3">
                            <AlertTriangle size={16} className="text-teal-500 shrink-0 mt-0.5" />
                            <p className="text-[10px] text-slate-400 leading-relaxed uppercase tracking-wide">
                                <span className="text-teal-500 font-bold">Security Note:</span> User-provided keys override system defaults. Keys are persisted in the tactical core and used for all subsequent neural operations.
                            </p>
                        </div>

                        <div className="space-y-5">
                            {renderKeyField(
                                'nvidia_api_key', 
                                'NVIDIA_API_KEY', 
                                Cpu, 
                                'text-teal-500', 
                                localKeys.nvidia_api_key, 
                                settingsKeys.nvidia_api_key,
                                visibility.nvidia,
                                () => toggleVisibility('nvidia')
                            )}

                            {renderKeyField(
                                'mistral_api_key', 
                                'MISTRAL_API_KEY', 
                                Cpu, 
                                'text-purple-500', 
                                localKeys.mistral_api_key, 
                                settingsKeys.mistral_api_key,
                                visibility.mistral,
                                () => toggleVisibility('mistral')
                            )}
                        </div>
                    </div>

                    {/* Footer */}
                    <div className="p-6 bg-black/40 border-t border-white/5 flex gap-4">
                        <button
                            onClick={onClose}
                            className="flex-1 py-3 text-[10px] font-black uppercase tracking-[0.2em] text-slate-600 hover:text-slate-300 border border-white/5 hover:bg-white/5 rounded-lg transition-all"
                        >
                            Cancel
                        </button>
                        <button
                            onClick={handleSave}
                            disabled={isSaving}
                            className="flex-[2] flex items-center justify-center gap-2 bg-gradient-to-r from-teal-600 to-teal-500 hover:from-teal-500 hover:to-teal-400 disabled:from-teal-900 disabled:to-teal-900 text-black py-3 text-[10px] font-black uppercase tracking-[0.2em] rounded-lg shadow-lg shadow-teal-500/10 transition-all border border-teal-400/20 active:scale-[0.98]"
                        >
                            {isSaving ? (
                                <div className="w-4 h-4 border-2 border-black border-t-transparent rounded-full animate-spin" />
                            ) : (
                                <>
                                    <Save size={14} />
                                    Synchronize Keys
                                </>
                            )}
                        </button>
                    </div>
                </motion.div>
            </div>
        </AnimatePresence>
    );
};

export default SettingsModal;
