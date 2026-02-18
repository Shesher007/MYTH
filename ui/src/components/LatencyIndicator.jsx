import React from 'react';
import { Server } from 'lucide-react';

export default function LatencyIndicator({ latency }) {
  // latency is now a string like "45ms" or 0 from useAgent
  const displayVal = typeof latency === 'string' ? latency : 'LINK_DROP';

  return (
    <div className="flex items-center gap-2 px-2.5 py-1.5 rounded border border-white/5 bg-black/40 min-w-[62px] justify-between" title="Backend Core Latency">
      <Server size={10} className="text-teal-500 opacity-70" />
      <span className="text-[9px] font-mono font-bold text-slate-400 uppercase tracking-wider min-w-[30px] text-right inline-block">
        <span className="text-teal-400">{displayVal}</span>
      </span>
    </div>
  );
}
