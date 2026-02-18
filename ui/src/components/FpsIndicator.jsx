import React from 'react';
import { useFPS } from '../hooks/useFPS';

export default function FpsIndicator() {
  const fps = useFPS();

  return (
    <div className="flex items-center gap-2 px-3 py-1.5 rounded border border-white/5 bg-black/40 group/fps">
      <div className="flex items-center gap-1">
        <div className={`w-1 h-3 rounded-full bg-teal-500/30 transition-all duration-300 ${fps > 55 ? 'h-3 opacity-100' : 'h-1.5 opacity-40'}`}></div>
        <div className={`w-1 h-2 rounded-full bg-teal-500/30 transition-all duration-300 ${fps > 30 ? 'h-2 opacity-80' : 'h-1 opacity-30'}`}></div>
        <div className={`w-1 h-4 rounded-full bg-teal-500/30 transition-all duration-300 ${fps > 15 ? 'h-4 opacity-60' : 'h-1 opacity-20'}`}></div>
      </div>
      <span className="text-[9px] font-mono font-bold text-slate-400 uppercase tracking-wider whitespace-nowrap">
        <span className="text-teal-400">{fps}</span> <span className="opacity-40">FPS</span>
      </span>
    </div>
  );
}
