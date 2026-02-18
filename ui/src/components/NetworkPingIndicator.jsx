import React from 'react';
import { Wifi, WifiOff } from 'lucide-react';

/**
 * NetworkPingIndicator - Displays real-time internet latency with signal strength visualization.
 * Color-coded: Teal (<50ms), Amber (50-150ms), Red (>150ms/offline)
 */
export default function NetworkPingIndicator({ networkPing, networkSpeed }) {
  const isOnline = networkPing !== -1 && networkPing !== null && networkPing !== undefined;
  const ping = isOnline ? networkPing : null;
  
  // Format speed (Down + Up)
  const totalSpeed = (networkSpeed?.down || 0) + (networkSpeed?.up || 0);
  const formatSpeed = (bytes) => {
    if (bytes < 1024) return '0 KB/s';
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB/s`;
    return `${(bytes / 1024 / 1024).toFixed(1)} MB/s`;
  };
  
  // Optimize display: If speed > 1MB/s, show speed. Else show mixed or ping.
  // Actually, user wants "Real Time Internet Speed". Let's show Speed primarily if active, or cycle?
  // Let's do a compact Layout: [ICON] [SPEED] (Latency on Hover? or small below?)
  // Actually, let's keep the bars for Signal (Latency), but replace text with Speed if > 0.
  
  const speedText = formatSpeed(totalSpeed);
  const showSpeed = totalSpeed > 1024 * 5; // Show speed if > 5KB/s traffic

  // Determine signal strength and color based on latency
  const getSignalConfig = () => {
    if (!isOnline) return { bars: 0, color: 'text-red-500', bgColor: 'bg-red-500' };
    if (ping < 50) return { bars: 4, color: 'text-teal-500', bgColor: 'bg-teal-500' };
    if (ping < 100) return { bars: 3, color: 'text-teal-400', bgColor: 'bg-teal-400' };
    if (ping < 150) return { bars: 2, color: 'text-amber-500', bgColor: 'bg-amber-500' };
    return { bars: 1, color: 'text-red-400', bgColor: 'bg-red-400' };
  };

  const { bars, color, bgColor } = getSignalConfig();

  return (
    <div className="flex items-center gap-2 px-2 py-1.5 rounded border border-white/5 bg-black/40 group/ping min-w-[70px] justify-between transition-all hover:bg-white/5" title={`Latency: ${ping?.toFixed(0)}ms | Down: ${formatSpeed(networkSpeed?.down || 0)} | Up: ${formatSpeed(networkSpeed?.up || 0)}`}>
      <div className="flex items-center gap-1.5">
        {/* Signal Strength Bars */}
        <div className="flex gap-px items-end h-3">
            {[1, 2, 3, 4].map((level) => (
            <div
                key={level}
                className={`w-[2px] rounded-sm transition-all duration-300 ${
                level <= bars 
                    ? `${bgColor} shadow-[0_0_4px_currentColor]` 
                    : 'bg-white/10'
                }`}
                style={{ height: `${level * 3}px` }}
            />
            ))}
        </div>
        
        {/* Network Icon */}
        {isOnline ? (
            <Wifi size={10} className={`${color} opacity-70`} />
        ) : (
            <WifiOff size={10} className="text-red-500 animate-pulse" />
        )}
      </div>
      
      {/* Value Display: High-Priority Speed, Low-Priority Latency */}
      <span className="text-[9px] font-mono font-bold uppercase tracking-wider min-w-[36px] text-right inline-block">
        {isOnline ? (
          <span className={showSpeed ? "text-teal-400 transition-colors" : color}>
            {showSpeed ? speedText : `${ping.toFixed(0)}ms`}
          </span>
        ) : (
          <span className="text-red-500">fail</span>
        )}
      </span>
    </div>
  );
}
