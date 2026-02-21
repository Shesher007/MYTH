import { cn } from "../../lib/utils"

interface GlitchTextProps {
    text: string
    className?: string
}

export default function GlitchText({ text, className }: GlitchTextProps) {
    return (
        <span className={cn("relative inline-block group", className)}>
            <span className="relative z-10">{text}</span>
            <span className="absolute top-0 left-0 -z-10 w-full h-full text-cyan-400 opacity-0 group-hover:opacity-70 group-hover:animate-glitch-1 group-hover:translate-x-[2px]">{text}</span>
            <span className="absolute top-0 left-0 -z-10 w-full h-full text-red-600 opacity-0 group-hover:opacity-70 group-hover:animate-glitch-2 group-hover:-translate-x-[2px]">{text}</span>
        </span>
    )
}
