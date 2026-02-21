import React, { useEffect, useRef, useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Maximize2 } from 'lucide-react';
import FileIcon from './FileIcon';

// Industrial Audio Visualizer Component
const AudioVisualizer = ({ src }) => {
    const canvasRef = useRef(null);
    const audioRef = useRef(null);
    const [isPlaying, setIsPlaying] = useState(false);
    const [duration, setDuration] = useState(0);
    const [currentTime, setCurrentTime] = useState(0);

    useEffect(() => {
        const audio = audioRef.current;
        if (!audio) return;

        const updateTime = () => setCurrentTime(audio.currentTime);
        const updateDuration = () => setDuration(audio.duration);
        const onEnd = () => setIsPlaying(false);

        audio.addEventListener('timeupdate', updateTime);
        audio.addEventListener('loadedmetadata', updateDuration);
        audio.addEventListener('ended', onEnd);

        // Web Audio API Context
        let audioContext;
        let analyser;
        let source;
        let animationId;

        const initAudioContext = () => {
            if (!audioContext) {
                audioContext = new (window.AudioContext || window.webkitAudioContext)();
                analyser = audioContext.createAnalyser();
                source = audioContext.createMediaElementSource(audio);
                source.connect(analyser);
                analyser.connect(audioContext.destination);
                analyser.fftSize = 256;

                const bufferLength = analyser.frequencyBinCount;
                const dataArray = new Uint8Array(bufferLength);
                const canvas = canvasRef.current;
                const ctx = canvas.getContext('2d');

                const draw = () => {
                    animationId = requestAnimationFrame(draw);
                    analyser.getByteFrequencyData(dataArray);

                    ctx.fillStyle = '#0a0a0a'; // Match modal bg
                    ctx.fillRect(0, 0, canvas.width, canvas.height);

                    const barWidth = (canvas.width / bufferLength) * 2.5;
                    let barHeight;
                    let x = 0;

                    for (let i = 0; i < bufferLength; i++) {
                        barHeight = dataArray[i] / 2; // Scale height

                        // Gradient fill based on frequency (Teal to Purple)
                        const gradient = ctx.createLinearGradient(0, canvas.height - barHeight, 0, canvas.height);
                        gradient.addColorStop(0, '#14b8a6'); // Teal
                        gradient.addColorStop(1, '#a855f7'); // Purple

                        ctx.fillStyle = gradient;
                        ctx.fillRect(x, canvas.height - barHeight, barWidth, barHeight);

                        x += barWidth + 1;
                    }
                };
                draw();
            }
        };

        const handlePlay = () => {
            if (audioContext && audioContext.state === 'suspended') {
                audioContext.resume();
            }
            if (!audioContext) initAudioContext();
        };

        audio.addEventListener('play', handlePlay);

        return () => {
            audio.removeEventListener('timeupdate', updateTime);
            audio.removeEventListener('loadedmetadata', updateDuration);
            audio.removeEventListener('ended', onEnd);
            audio.removeEventListener('play', handlePlay);
            if (animationId) cancelAnimationFrame(animationId);
            if (audioContext) audioContext.close();
        };
    }, []);

    const togglePlay = () => {
        if (audioRef.current.paused) {
            audioRef.current.play();
            setIsPlaying(true);
        } else {
            audioRef.current.pause();
            setIsPlaying(false);
        }
    };

    const formatTime = (time) => {
        const min = Math.floor(time / 60);
        const sec = Math.floor(time % 60);
        return `${min}:${sec.toString().padStart(2, '0')}`;
    };

    return (
        <div className="w-full max-w-lg bg-black/40 border border-white/10 rounded-xl p-6 backdrop-blur-sm shadow-[0_0_30px_rgba(20,184,166,0.05)]">
            <canvas
                ref={canvasRef}
                width={460}
                height={100}
                className="w-full h-24 mb-6 rounded bg-[#0a0a0a] border border-white/5"
            />

            <audio ref={audioRef} src={src} crossOrigin="anonymous" className="hidden" />

            <div className="flex items-center gap-4">
                <button
                    onClick={togglePlay}
                    className="w-10 h-10 rounded-full bg-teal-500/10 hover:bg-teal-500/20 flex items-center justify-center text-teal-400 transition-all border border-teal-500/20 hover:scale-105 active:scale-95"
                >
                    {isPlaying ? <Pause size={18} fill="currentColor" /> : <Play size={18} fill="currentColor" className="ml-0.5" />}
                </button>

                <div className="flex-1 flex flex-col gap-1">
                    <div className="flex justify-between text-[9px] font-mono text-slate-500 font-black tracking-wider">
                        <span>{formatTime(currentTime)}</span>
                        <span>{formatTime(duration || 0)}</span>
                    </div>
                    <div className="w-full h-1.5 bg-white/5 rounded-full overflow-hidden">
                        <motion.div
                            className="h-full bg-teal-500 rounded-full"
                            style={{ width: `${(currentTime / duration) * 100}%` }}
                            transition={{ type: "tween", ease: "linear", duration: 0.1 }}
                        />
                    </div>
                </div>
            </div>

            <div className="flex justify-center mt-4">
                <span className="text-[8px] font-mono text-teal-500/40 uppercase tracking-[0.4em] animate-pulse">
                    Live Spectrogram Analysis
                </span>
            </div>
        </div>
    );
};

const PreviewModal = ({ isOpen, onClose, file }) => {
    const [viewMode, setViewMode] = useState('standard');

    useEffect(() => {
        // Automatically switch to Hex if it's binary or if no standard preview is available
        const hasStandard = file?.preview || file?.contentSnippet || (file?.type === 'folder' && file?.summary);
        if (!hasStandard && file?.hex_dump) {
            setViewMode('hex');
        } else if (file?.is_binary && !file?.preview) {
            setViewMode('hex');
        } else {
            setViewMode('standard');
        }
    }, [file]);

    if (!file) return null;

    const { name, preview, type, contentSnippet, hex_dump, size, summary, is_binary, mime_type } = file;

    const renderFullPreview = () => {
        // Check for media types using extensions and MIME
        const isAudio = name?.match(/\.(wav|mp3|ogg|flac|m4a|aac|opus|wma)$/i) ||
            file?.content?.type?.startsWith('audio/') ||
            mime_type?.startsWith('audio/');

        const isImage = name?.match(/\.(jpg|jpeg|png|gif|webp|svg|jfif|avif|apng|pjpeg|pjp|ico|bmp|heif)$/i) ||
            file?.content?.type?.startsWith('image/') ||
            mime_type?.startsWith('image/');

        if (viewMode === 'hex' && hex_dump) {
            return (
                <div className="flex-1 bg-[#050508] p-8 overflow-auto custom-scrollbar-minimal">
                    <div className="max-w-5xl mx-auto">
                        <div className="flex items-center gap-4 mb-6 border-b border-white/5 pb-4">
                            <Activity size={18} className="text-purple-500" />
                            <span className="text-xs font-mono text-slate-500 uppercase tracking-widest">Forensic Hex Dump Byte-Stream</span>
                        </div>
                        <div className="bg-black/40 p-6 rounded-lg border border-white/5 shadow-inner">
                            <pre className="text-[10px] sm:text-[11px] font-mono text-teal-500/80 leading-relaxed whitespace-pre overflow-x-auto">
                                {hex_dump}
                            </pre>
                        </div>
                        <div className="mt-8 p-4 bg-purple-500/5 border border-dashed border-purple-500/20 rounded flex items-center justify-center">
                            <span className="text-[9px] font-mono text-purple-400 uppercase tracking-widest">End of Forensic Buffer // 2048 Bytes Decoded</span>
                        </div>
                    </div>
                </div>
            );
        }

        if (isAudio && preview) {
            return (
                <div className="flex-1 flex flex-col items-center justify-center p-12 bg-[#020205]">
                    <div className="w-32 h-32 rounded-full bg-gradient-to-br from-teal-500/20 to-purple-500/20 flex items-center justify-center border border-teal-500/30 mb-8 pulse-glow">
                        <div className="w-24 h-24 rounded-full bg-black/60 flex items-center justify-center border border-white/10">
                            <div className="text-teal-400 animate-pulse">
                                <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                    <path d="M12 2a3 3 0 0 0-3 3v7a3 3 0 0 0 6 0V5a3 3 0 0 0-3-3Z" />
                                    <path d="M19 10v2a7 7 0 0 1-14 0v-2" />
                                    <line x1="12" x2="12" y1="19" y2="22" />
                                </svg>
                            </div>
                        </div>
                    </div>
                    <h3 className="text-lg font-black text-white uppercase tracking-[0.2em] mb-2">{name}</h3>
                    <p className="text-[10px] text-slate-500 font-mono tracking-widest mb-8">VOICE_INTEL_BUFFER</p>

                    <AudioVisualizer src={preview} />
                </div>
            );
        }

        if (isImage && preview) {
            return (
                <div className="flex-1 flex items-center justify-center p-8 bg-[#020205] overflow-auto">
                    <motion.img
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        transition={{ duration: 0.3 }}
                        src={preview}
                        alt={name}
                        className="max-w-full max-h-full object-contain shadow-[0_0_50px_rgba(20,184,166,0.1)] rounded"
                    />
                </div>
            );
        }

        if (contentSnippet) {
            return (
                <div className="flex-1 bg-[#050508] p-8 overflow-auto custom-scrollbar-minimal">
                    <div className="max-w-4xl mx-auto">
                        <div className="flex items-center gap-4 mb-6 border-b border-white/5 pb-4">
                            <Terminal size={18} className="text-teal-500" />
                            <span className="text-xs font-mono text-slate-500 uppercase tracking-widest">Buffer Content Preview</span>
                        </div>
                        <pre className="text-sm font-mono text-teal-400/90 leading-relaxed whitespace-pre-wrap">
                            {contentSnippet}
                        </pre>
                        {contentSnippet.length >= 1000 && (
                            <div className="mt-8 p-4 border border-dashed border-white/10 rounded flex items-center justify-center bg-white/[0.01]">
                                <span className="text-[10px] font-black text-slate-600 uppercase tracking-[0.2em]">End of Preview Buffer</span>
                            </div>
                        )}
                    </div>
                </div>
            );
        }

        if (type === 'folder' && summary) {
            return (
                <div className="flex-1 bg-[#050508] p-8 overflow-y-auto custom-scrollbar-minimal">
                    <div className="max-w-5xl mx-auto space-y-8">
                        {/* Folder Header Stats */}
                        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                            <div className="bg-white/[0.02] border border-white/5 p-4 rounded-lg">
                                <div className="flex items-center gap-3 text-slate-500 mb-2">
                                    <Files size={14} />
                                    <span className="text-[10px] font-black uppercase tracking-widest">Total Files</span>
                                </div>
                                <div className="text-2xl font-mono text-white">{summary.total_files}</div>
                            </div>
                            <div className="bg-white/[0.02] border border-white/5 p-4 rounded-lg">
                                <div className="flex items-center gap-3 text-slate-500 mb-2">
                                    <HardDrive size={14} />
                                    <span className="text-[10px] font-black uppercase tracking-widest">Storage Size</span>
                                </div>
                                <div className="text-2xl font-mono text-teal-500">{summary.size_human}</div>
                            </div>
                            <div className="bg-white/[0.02] border border-white/5 p-4 rounded-lg">
                                <div className="flex items-center gap-3 text-slate-500 mb-2">
                                    <Activity size={14} />
                                    <span className="text-[10px] font-black uppercase tracking-widest">Categories</span>
                                </div>
                                <div className="text-2xl font-mono text-purple-400">{Object.keys(summary.categories).length}</div>
                            </div>
                            <div className="bg-white/[0.02] border border-white/5 p-4 rounded-lg">
                                <div className="flex items-center gap-3 text-slate-500 mb-2">
                                    <AlertTriangle size={14} />
                                    <span className="text-[10px] font-black uppercase tracking-widest">Threats</span>
                                </div>
                                <div className={`text-2xl font-mono ${summary.security_analysis?.sensitive_files?.length > 0 ? 'text-red-500' : 'text-slate-600'}`}>
                                    {summary.security_analysis?.sensitive_files?.length || 0}
                                </div>
                            </div>
                        </div>

                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
                            {/* Type Distribution */}
                            <div className="space-y-4">
                                <h4 className="text-[10px] font-black text-slate-500 uppercase tracking-[0.3em] border-b border-white/5 pb-2">Cognitive Distribution</h4>
                                <div className="space-y-3">
                                    {Object.entries(summary.categories).map(([cat, count]) => (
                                        <div key={cat} className="space-y-1.5">
                                            <div className="flex justify-between text-[11px] font-mono uppercase">
                                                <span className="text-slate-400">{cat}</span>
                                                <span className="text-teal-500/80">{count} files</span>
                                            </div>
                                            <div className="h-1 bg-white/5 rounded-full overflow-hidden">
                                                <div
                                                    className="h-full bg-teal-500/40 rounded-full"
                                                    style={{ width: `${(count / summary.total_files) * 100}%` }}
                                                ></div>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </div>

                            {/* Security Alerts */}
                            <div className="space-y-4">
                                <h4 className="text-[10px] font-black text-slate-500 uppercase tracking-[0.3em] border-b border-white/5 pb-2">Security Perimeter Alerts</h4>
                                <div className="space-y-2">
                                    {summary.security_analysis?.sensitive_files?.length > 0 ? (
                                        summary.security_analysis.sensitive_files.slice(0, 5).map((alert, idx) => (
                                            <div key={idx} className="flex items-start gap-4 p-3 bg-red-500/5 border border-red-500/10 rounded text-[11px] font-mono">
                                                <AlertTriangle size={14} className="text-red-500 mt-0.5" />
                                                <div className="flex-1">
                                                    <div className="text-red-400 mb-1">{alert.description}</div>
                                                    <div className="text-slate-600 truncate opacity-60">{alert.file}</div>
                                                </div>
                                            </div>
                                        ))
                                    ) : (
                                        <div className="flex flex-col items-center justify-center p-8 border border-dashed border-white/5 rounded opacity-40">
                                            <Shield size={24} className="text-teal-500 mb-3" />
                                            <span className="text-[10px] font-mono uppercase tracking-widest text-slate-400">No sensitive assets detected</span>
                                        </div>
                                    )}
                                </div>
                            </div>
                        </div>

                        {/* Recent Activity */}
                        <div className="space-y-4">
                            <h4 className="text-[10px] font-black text-slate-500 uppercase tracking-[0.3em] border-b border-white/5 pb-2">Temporal Buffer (Recent Modifications)</h4>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                {summary.recent_files.map((file, idx) => (
                                    <div key={idx} className="flex items-center justify-between p-3 bg-white/[0.01] border border-white/5 rounded hover:border-white/10 transition-colors">
                                        <div className="flex items-center gap-3">
                                            <Clock size={12} className="text-slate-600" />
                                            <span className="text-[11px] font-mono text-slate-300 truncate max-w-[200px]">{file.name}</span>
                                        </div>
                                        <span className="text-[9px] font-mono text-slate-600 px-2 py-0.5 border border-white/5 rounded uppercase">{file.category}</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>
                </div>
            );
        }

        return (
            <div className="flex-1 flex flex-col items-center justify-center p-12 bg-[#020205]">
                <div className="w-24 h-24 rounded-full bg-slate-900 flex items-center justify-center border border-white/10 mb-6 pulse-glow">
                    <FileIcon name={name} type={type} size={40} />
                </div>
                <h3 className="text-xl font-black text-white uppercase tracking-widest mb-2">{name}</h3>
                <div className="flex flex-col items-center gap-2 max-w-sm text-center">
                    <p className="text-xs text-slate-500 font-mono tracking-[0.3em] uppercase">{mime_type || 'Unknown Format'}</p>
                    <p className="text-[10px] text-slate-800 font-mono tracking-widest bg-white/5 px-4 py-1 rounded-full border border-white/5">
                        {size} // {is_binary ? 'BINARY_BLOB' : 'UNSTRUCTURED'}
                    </p>
                    {hex_dump ? (
                        <div className="mt-8 flex flex-col items-center gap-4">
                            <p className="text-[11px] text-slate-600 leading-relaxed font-medium">
                                Direct visual rendering is unavailable. Manual forensic inspection is required for deep analysis.
                            </p>
                            <button
                                onClick={() => setViewMode('hex')}
                                className="px-8 py-2.5 bg-teal-500/10 border border-teal-500/30 rounded text-teal-400 text-[10px] font-black uppercase tracking-[0.2em] hover:bg-teal-500/20 transition-all shadow-lg shadow-teal-500/5 pulse-glow"
                            >
                                Execute Hex Forensics
                            </button>
                        </div>
                    ) : (
                        <p className="mt-8 text-[11px] text-red-500/60 font-mono uppercase tracking-[0.2em]">
                            Forensic Stream Offline // Inaccessible
                        </p>
                    )}
                </div>
            </div>
        );
    };

    return (
        <AnimatePresence>
            {isOpen && (
                <div className="fixed inset-0 z-[1200] flex items-center justify-center p-4 sm:p-8">
                    <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="absolute inset-0 bg-black/95 backdrop-blur-2xl"
                        onClick={onClose}
                    />

                    <motion.div
                        initial={{ scale: 0.95, opacity: 0, y: 20 }}
                        animate={{ scale: 1, opacity: 1, y: 0 }}
                        exit={{ scale: 0.95, opacity: 0, y: 20 }}
                        className="relative w-full max-w-6xl h-full bg-[#0d0d16] border border-white/10 rounded-lg shadow-2xl overflow-hidden flex flex-col"
                    >
                        <header className="px-6 py-4 border-b border-white/5 bg-black/40 flex items-center justify-between">
                            <div className="flex items-center gap-4">
                                <div className="p-2 bg-teal-500/10 rounded">
                                    <FileIcon name={name} type={type} size={20} />
                                </div>
                                <div className="flex flex-col">
                                    <h2 className="text-sm font-black text-white uppercase tracking-[0.2em]">{name}</h2>
                                    <span className="text-[9px] font-mono text-slate-500 tracking-widest">ASSET_INSPECTOR_V1.0</span>
                                </div>
                            </div>
                            <div className="flex items-center gap-2">
                                {hex_dump && (
                                    <div className="flex bg-black/40 p-1 rounded-lg border border-white/10 mr-4">
                                        <button
                                            onClick={() => setViewMode('standard')}
                                            className={`px-3 py-1 rounded text-[9px] font-black uppercase tracking-widest transition-all ${viewMode === 'standard' ? 'bg-teal-500 text-black shadow-[0_0_10px_rgba(20,184,166,0.5)]' : 'text-slate-500 hover:text-slate-300'}`}
                                            disabled={is_binary && !preview && !contentSnippet}
                                        >
                                            Standard
                                        </button>
                                        <button
                                            onClick={() => setViewMode('hex')}
                                            className={`px-3 py-1 rounded text-[9px] font-black uppercase tracking-widest transition-all ${viewMode === 'hex' ? 'bg-purple-500 text-white shadow-[0_0_10px_rgba(168,85,247,0.5)]' : 'text-slate-500 hover:text-slate-300'}`}
                                        >
                                            Hex_Forensics
                                        </button>
                                    </div>
                                )}
                                <button className="p-2 hover:bg-white/5 rounded text-slate-400 hover:text-white transition-colors" title="Full Screen">
                                    <Maximize2 size={18} />
                                </button>
                                <div className="w-px h-6 bg-white/5 mx-2"></div>
                                <button onClick={onClose} className="p-2 hover:bg-red-500/10 rounded-full text-slate-500 hover:text-red-500 transition-colors">
                                    <X size={20} />
                                </button>
                            </div>
                        </header>

                        <div className="flex-1 flex overflow-hidden">
                            {renderFullPreview()}
                        </div>

                        <footer className="px-8 py-4 border-t border-white/5 bg-black/20 flex items-center justify-between text-[10px] font-mono text-slate-600">
                            <div className="flex gap-8">
                                <span className="flex items-center gap-2">
                                    <span className="text-teal-500 opacity-50">SIZE:</span> {type === 'folder' ? summary?.size_human || 'DIR' : size}
                                </span>
                                <span className="flex items-center gap-2 text-slate-400">
                                    <span className="text-teal-500 opacity-50 uppercase leading-none mt-0.5">MIME:</span> {mime_type || type?.toUpperCase() || 'UNKNOWN'}
                                </span>
                            </div>
                            <div className="flex items-center gap-4">
                                <span className="animate-pulse flex items-center gap-2">
                                    <span className="w-1.5 h-1.5 rounded-full bg-teal-500"></span>
                                    {type === 'folder' ? 'DIRECTORY_SCAN_BUFFER_ACTIVE' : 'ENCRYPTED_LINK_ACTIVE'}
                                </span>
                            </div>
                        </footer>
                    </motion.div>
                </div>
            )}
        </AnimatePresence>
    );
};

export default PreviewModal;
