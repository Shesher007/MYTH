import { useEffect, useState } from "react"

interface TextDecodeProps {
    text: string
    className?: string
}

const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@#$%&*"

export default function TextDecode({ text, className }: TextDecodeProps) {
    const [display, setDisplay] = useState("")

    useEffect(() => {
        let iteration = 0
        let interval: ReturnType<typeof setInterval> | null = null

        const startDecoding = () => {
            interval = setInterval(() => {
                setDisplay(() =>
                    text.split("")
                        .map((_, index) => {
                            if (index < iteration) {
                                return text[index]
                            }
                            return chars[Math.floor(Math.random() * chars.length)]
                        })
                        .join("")
                )

                if (iteration >= text.length) {
                    if (interval) clearInterval(interval)
                }

                iteration += 1 / 3
            }, 30)
        }

        const timeout = setTimeout(startDecoding, 500) // Delay start slightly

        return () => {
            if (interval) clearInterval(interval)
            clearTimeout(timeout)
        }
    }, [text])

    return <span className={className}>{display}</span>
}
