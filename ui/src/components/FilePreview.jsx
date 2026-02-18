import React from 'react';
import { FileText, Code, Settings, Eye, FileUp, Folder, File, Database, Music, Mic, Loader2, X } from 'lucide-react';
import FileIcon from './FileIcon';

const FilePreview = ({ file, onClick, onRemove, className = "" }) => {
    const { type, name, preview, contentSnippet, size, status, progress, error } = file;

    const isProcessing = status === 'uploading' || status === 'parsing';
    const isError = status === 'error';

    // DEBUG
    console.log(`[FilePreview] ${name} | Status: ${status} | IsProcessing: ${isProcessing}`);

    // Get icon using the new unified component
    const renderIcon = () => {
        return <FileIcon name={name} type={type} size={16} />;
    };

    // For folders, show 'DIR', otherwise extract extension
    const ext = type === 'folder' 
        ? 'DIR' 
        : (name?.includes('.') ? name.split('.').pop().substring(0, 4).toUpperCase() : 'FILE');

    return (
        <div
            className={`file-preview-card relative flex items-center gap-3 px-3 rounded-lg border border-white/10 bg-black/40 backdrop-blur-md transition-all hover:border-teal-500/30 hover:bg-black/60 cursor-pointer group overflow-visible ${className}`}
            onClick={onClick}
            title={error || name}
        >
            {/* Left: Icon / Spinner Container */}
            <div className="flex-shrink-0 w-8 h-8 rounded-md bg-slate-800/50 border border-white/5 flex items-center justify-center overflow-hidden relative">
                {isProcessing ? (
                     <Loader2 size={16} className="text-teal-400 animate-spin" />
                ) : isError ? (
                     <div className="text-red-500 font-bold">!</div>
                ) : (preview && (type?.startsWith('image/') || name?.match(/\.(jpg|jpeg|png|gif|webp|svg|jfif|avif|apng|pjpeg|pjp)$/i))) ? (
                     <img src={preview} alt={name} className="w-full h-full object-cover opacity-80" />
                ) : (
                    renderIcon()
                )}
                
                {/* Error Overlay Background */}
                {isError && (
                     <div className="absolute inset-0 bg-red-500/20"></div>
                )}
            </div>

            {/* Middle: Info Column */}
            <div className="flex flex-col flex-1 min-w-0 justify-center">
                 <div className="flex items-center gap-2">
                     <span className={`text-[10px] font-bold truncate leading-tight ${error ? 'text-red-400' : 'text-slate-200'}`}>
                         {name}
                     </span>
                     {status === 'success' && <div className="text-teal-500 text-[10px]"><Folder size={8} className="fill-current" /></div>}
                 </div>
                 
                 <div className="flex items-center gap-1.5 mt-0.5">
                     <span className="text-[8px] font-mono font-black text-slate-500 uppercase tracking-wider bg-slate-900/50 px-1 rounded">
                         {ext}
                     </span>
                     
                     {/* Dynamic Status Text */}
                     {isProcessing ? (
                          <span className="text-[8px] font-mono text-teal-400 animate-pulse">
                              {status === 'parsing' ? (type === 'folder' ? 'PARSING...' : 'PARSING...') : `${progress}%`}
                          </span>
                     ) : isError ? (
                          <span className="text-[8px] font-mono text-red-400 truncate max-w-[80px]">
                              FAILED
                          </span>
                     ) : type === 'folder' ? (
                        <span className="text-[8px] font-mono text-slate-500">
                             {size || 'DIR'}
                        </span>
                     ) : (
                          <span className="text-[8px] font-mono text-slate-500">
                              {size || '0 KB'}
                          </span>
                     )}
                 </div>
            </div>

            {/* Right: Remove Button - Positioned Top-Right */}
            {onRemove && (
                <div className="absolute -top-1.5 -right-1.5 z-10 opacity-0 group-hover:opacity-100 transition-opacity duration-200">
                    <button
                        type="button"
                        onClick={(e) => { e.stopPropagation(); onRemove(); }}
                        className="w-4 h-4 flex items-center justify-center rounded-full bg-white text-slate-900 shadow-lg hover:bg-slate-200 transition-all transform hover:scale-110"
                    >
                        <X size={10} strokeWidth={3} />
                    </button>
                </div>
            )}
            
            {/* Progress Bar (Bottom Line) */}
            {isProcessing && (
                <div className="absolute bottom-0 left-0 h-[2px] bg-teal-500/50 transition-all duration-300 rounded-b-lg" style={{ width: `${status === 'parsing' ? 100 : progress}%` }}></div>
            )}
        </div>
    );
};

export default FilePreview;
