import { Component, type ErrorInfo, type ReactNode } from "react"
import { AlertTriangle, RefreshCcw } from "lucide-react"

interface Props {
    children?: ReactNode
}

interface State {
    hasError: boolean
}

class ErrorBoundary extends Component<Props, State> {
    public state: State = {
        hasError: false
    }

    public static getDerivedStateFromError(_: Error): State {
        return { hasError: true }
    }

    public componentDidCatch(error: Error, errorInfo: ErrorInfo) {
        console.error("Uncaught error:", error, errorInfo)
    }

    public render() {
        if (this.state.hasError) {
            return (
                <div className="min-h-screen bg-[#0c0c0c] flex items-center justify-center p-6 text-center">
                    <div className="max-w-md w-full glass-panel p-8 rounded-2xl border-red-500/20">
                        <div className="mb-6 flex justify-center">
                            <div className="p-4 bg-red-500/10 rounded-full border border-red-500/20" aria-hidden="true">
                                <AlertTriangle className="w-12 h-12 text-red-500" />
                            </div>
                        </div>
                        <h2 className="text-2xl font-bold mb-4">Neural Pathway Interrupted</h2>
                        <p className="text-muted-foreground mb-8">
                            The Titan Agent encountered a non-deterministic state. Local integrity remains secure.
                        </p>
                        <button
                            onClick={() => window.location.reload()}
                            className="w-full flex items-center justify-center gap-2 bg-primary hover:bg-primary/90 text-white px-6 py-3 rounded-xl font-bold transition-all focus:outline-none focus:ring-2 focus:ring-primary focus:ring-offset-2 focus:ring-offset-background"
                            aria-label="Restore Neural Link and reload application"
                        >
                            <RefreshCcw className="w-5 h-5" />
                            Restore Neural Link
                        </button>
                    </div>
                </div>
            )
        }

        return this.props.children
    }
}

export default ErrorBoundary
