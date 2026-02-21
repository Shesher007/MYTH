import { motion } from "framer-motion"
import { useSimulatedData } from "../../hooks/useSimulatedData"
import { Activity, Shield, Cpu, Wifi } from "lucide-react"
import { cn } from "../../lib/utils"

export default function TelemetryDashboard() {
    const data = useSimulatedData()

    return (
        <div className="rounded-xl border border-white/10 bg-black/40 backdrop-blur-sm p-6 overflow-hidden relative">
            {/* Grid Overlay */}
            <div className="absolute inset-0 bg-[linear-gradient(rgba(124,58,237,0.03)_1px,transparent_1px),linear-gradient(90deg,rgba(124,58,237,0.03)_1px,transparent_1px)] bg-[size:20px_20px] pointer-events-none" />

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 relative z-10">
                {/* CPU Monitor */}
                <div className="space-y-3">
                    <div className="flex items-center gap-2 text-accent text-sm uppercase tracking-wider font-semibold">
                        <Cpu className="w-4 h-4" /> CPU Load
                    </div>
                    <div className="h-24 bg-black/50 rounded-lg border border-white/5 relative overflow-hidden flex items-end px-1 gap-[1px]">
                        {data.cpu.map((val: number, i: number) => (
                            <motion.div
                                key={i}
                                className="flex-1 bg-accent/60"
                                initial={{ height: 0 }}
                                animate={{ height: `${val}%` }}
                                transition={{ type: "spring", stiffness: 300, damping: 30 }}
                            />
                        ))}
                    </div>
                    <div className="text-right text-xs font-mono text-muted-foreground">
                        Core_0: {data.cpu[data.cpu.length - 1]}%
                    </div>
                </div>

                {/* RAM Monitor */}
                <div className="space-y-3">
                    <div className="flex items-center gap-2 text-blue-400 text-sm uppercase tracking-wider font-semibold">
                        <Activity className="w-4 h-4" /> Memory Alloc
                    </div>
                    <div className="h-24 bg-black/50 rounded-lg border border-white/5 relative overflow-hidden flex items-end px-1 gap-[1px]">
                        {data.ram.map((val: number, i: number) => (
                            <motion.div
                                key={i}
                                className="flex-1 bg-blue-500/60"
                                initial={{ height: 0 }}
                                animate={{ height: `${val}%` }}
                                transition={{ type: "spring", stiffness: 300, damping: 30 }}
                            />
                        ))}
                    </div>
                    <div className="text-right text-xs font-mono text-muted-foreground">
                        Alloc: {data.ram[data.ram.length - 1]} MB
                    </div>
                </div>

                {/* Network / Threat */}
                <div className="space-y-3">
                    <div className="flex items-center gap-2 text-green-400 text-sm uppercase tracking-wider font-semibold">
                        <Wifi className="w-4 h-4" /> Net / Threat
                    </div>
                    <div className="h-24 bg-black/50 rounded-lg border border-white/5 p-3 flex flex-col justify-between font-mono text-xs">
                        <div className="flex justify-between">
                            <span className="text-muted-foreground">Inbound:</span>
                            <span className="text-green-400">{data.networkIn} KB/s</span>
                        </div>
                        <div className="flex justify-between">
                            <span className="text-muted-foreground">Outbound:</span>
                            <span className="text-blue-400">{data.networkOut} KB/s</span>
                        </div>
                        <div className="h-[1px] bg-white/10 my-1" />
                        <div className="flex justify-between items-center">
                            <span className="text-muted-foreground">Threats:</span>
                            <span className={cn(
                                "px-1.5 py-0.5 rounded font-bold",
                                data.activeThreats > 0 ? "bg-red-500/20 text-red-500 animate-pulse" : "bg-green-500/20 text-green-500"
                            )}>
                                {data.activeThreats > 0 ? "DETECTED" : "CLEAR"}
                            </span>
                        </div>
                    </div>
                </div>

                {/* Live Log */}
                <div className="space-y-3">
                    <div className="flex items-center gap-2 text-orange-400 text-sm uppercase tracking-wider font-semibold">
                        <Shield className="w-4 h-4" /> Sentinel Log
                    </div>
                    <div className="h-24 bg-black/50 rounded-lg border border-white/5 p-2 font-mono text-[10px] overflow-hidden flex flex-col justify-end">
                        {data.logs.slice(-5).map((log: string, i: number) => (
                            <motion.div
                                key={i}
                                initial={{ opacity: 0, x: -10 }}
                                animate={{ opacity: 1, x: 0 }}
                                className="truncate text-muted-foreground/80 border-l-2 border-orange-500/30 pl-2 mb-1 last:text-orange-300 last:border-orange-500"
                            >
                                {log}
                            </motion.div>
                        ))}
                    </div>
                </div>
            </div>
        </div>
    )
}
