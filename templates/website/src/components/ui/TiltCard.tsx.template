import { motion, useMotionValue, useSpring, useTransform, useMotionTemplate } from "framer-motion"
import type { ReactNode, MouseEvent } from "react"
import { cn } from "../../lib/utils"

interface TiltCardProps {
    children: ReactNode
    className?: string
}

export default function TiltCard({ children, className }: TiltCardProps) {
    const x = useMotionValue(0)
    const y = useMotionValue(0)

    const mouseX = useSpring(x, { stiffness: 500, damping: 100 })
    const mouseY = useSpring(y, { stiffness: 500, damping: 100 })

    const rotateX = useTransform(mouseY, [-0.5, 0.5], ["15deg", "-15deg"])
    const rotateY = useTransform(mouseX, [-0.5, 0.5], ["-15deg", "15deg"])

    // Holographic Sheen Gradient
    const sheenX = useTransform(mouseX, [-0.5, 0.5], ["0%", "100%"])
    const sheenY = useTransform(mouseY, [-0.5, 0.5], ["0%", "100%"])

    const handleMouseMove = (e: MouseEvent<HTMLDivElement>) => {
        const rect = e.currentTarget.getBoundingClientRect()
        const width = rect.width
        const height = rect.height
        const mouseXFromCenter = e.clientX - rect.left - width / 2
        const mouseYFromCenter = e.clientY - rect.top - height / 2
        x.set(mouseXFromCenter / width)
        y.set(mouseYFromCenter / height)
    }

    const handleMouseLeave = () => {
        x.set(0)
        y.set(0)
    }

    return (
        <motion.div
            style={{
                rotateX,
                rotateY,
                transformStyle: "preserve-3d",
            }}
            onMouseMove={handleMouseMove}
            onMouseLeave={handleMouseLeave}
            className={cn("relative transition-all duration-200 ease-linear", className)}
        >
            <div style={{ transform: "translateZ(50px)" }}>
                {children}
            </div>
            
            {/* Holographic Sheen Layer */}
            <motion.div 
                className="absolute inset-0 pointer-events-none opacity-0 group-hover:opacity-100 transition-opacity duration-500 rounded-xl"
                style={{
                    background: useMotionTemplate`radial-gradient(circle at ${sheenX} ${sheenY}, rgba(255,255,255,0.15), transparent 60%)`,
                    zIndex: 20
                }}
            />
        </motion.div>
    )
}
