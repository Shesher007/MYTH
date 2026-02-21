import React from 'react';

class ErrorBoundary extends React.Component {
    constructor(props) {
        super(props);
        this.state = { hasError: false, error: null, errorInfo: null };
    }

    static getDerivedStateFromError(_error) {
        return { hasError: true };
    }

    componentDidCatch(error, errorInfo) {
        this.setState({ error, errorInfo });
        console.error('ErrorBoundary caught an error:', error, errorInfo);
    }

    render() {
        if (this.state.hasError) {
            return (
                <div style={{
                    background: '#0a0a0a',
                    color: '#ef4444',
                    padding: '40px',
                    fontFamily: 'JetBrains Mono, monospace',
                    minHeight: '100vh',
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    justifyContent: 'center'
                }}>
                    <h1 style={{ color: '#14b8a6', marginBottom: '20px' }}>⚠️ MYTH CORE CRASH</h1>
                    <div style={{
                        background: '#1a1a1a',
                        border: '1px solid #ef4444',
                        borderRadius: '8px',
                        padding: '20px',
                        maxWidth: '800px',
                        width: '100%'
                    }}>
                        <h2 style={{ color: '#f59e0b', fontSize: '14px' }}>Error Message:</h2>
                        <pre style={{ color: '#ef4444', fontSize: '12px', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>
                            {this.state.error && this.state.error.toString()}
                        </pre>
                        <h2 style={{ color: '#f59e0b', fontSize: '14px', marginTop: '20px' }}>Stack Trace:</h2>
                        <pre style={{ color: '#94a3b8', fontSize: '10px', whiteSpace: 'pre-wrap', wordBreak: 'break-all', maxHeight: '300px', overflow: 'auto' }}>
                            {this.state.errorInfo && this.state.errorInfo.componentStack}
                        </pre>
                    </div>
                    <button
                        onClick={() => window.location.reload()}
                        style={{
                            marginTop: '20px',
                            padding: '10px 20px',
                            background: '#14b8a6',
                            color: '#000',
                            border: 'none',
                            borderRadius: '4px',
                            cursor: 'pointer',
                            fontWeight: 'bold'
                        }}
                    >
                        Reload Application
                    </button>
                </div>
            );
        }

        return this.props.children;
    }
}

export default ErrorBoundary;
