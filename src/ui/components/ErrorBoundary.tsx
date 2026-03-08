/**
 * VARIANT — React Error Boundary
 *
 * Catches unhandled render errors and displays a recovery UI
 * instead of a white screen. Users can retry or return to menu.
 */

import { Component } from 'react';
import type { ReactNode, ErrorInfo } from 'react';

interface ErrorBoundaryProps {
    readonly children: ReactNode;
    readonly onReset?: () => void;
}

interface ErrorBoundaryState {
    readonly hasError: boolean;
    readonly error: Error | null;
    readonly errorInfo: string | null;
}

export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
    constructor(props: ErrorBoundaryProps) {
        super(props);
        this.state = { hasError: false, error: null, errorInfo: null };
    }

    static getDerivedStateFromError(error: Error): Partial<ErrorBoundaryState> {
        return { hasError: true, error };
    }

    override componentDidCatch(error: Error, info: ErrorInfo): void {
        const componentStack = info.componentStack ?? '';
        this.setState({ errorInfo: componentStack });
        console.error('[VARIANT] Uncaught render error:', error, componentStack);
    }

    private handleRetry = (): void => {
        this.setState({ hasError: false, error: null, errorInfo: null });
    };

    private handleReset = (): void => {
        this.setState({ hasError: false, error: null, errorInfo: null });
        this.props.onReset?.();
    };

    override render(): ReactNode {
        if (!this.state.hasError) {
            return this.props.children;
        }

        return (
            <div style={{
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                justifyContent: 'center',
                height: '100vh',
                background: '#0A0A0A',
                fontFamily: '"JetBrains Mono", "Fira Code", monospace',
                color: '#E0E0E0',
                padding: '2rem',
            }}>
                <div style={{
                    fontSize: '1.5rem',
                    fontWeight: 700,
                    color: '#C75450',
                    letterSpacing: '0.1em',
                    marginBottom: '1rem',
                }}>
                    RUNTIME ERROR
                </div>

                <p style={{
                    fontSize: '0.85rem',
                    color: '#707070',
                    maxWidth: '500px',
                    textAlign: 'center',
                    lineHeight: 1.6,
                    marginBottom: '1.5rem',
                }}>
                    An unexpected error occurred. The simulation state may be corrupted.
                </p>

                <pre style={{
                    background: '#111111',
                    border: '1px solid rgba(255,255,255,0.08)',
                    borderRadius: '4px',
                    padding: '12px 16px',
                    fontSize: '0.7rem',
                    color: '#C75450',
                    maxWidth: '600px',
                    maxHeight: '200px',
                    overflow: 'auto',
                    whiteSpace: 'pre-wrap',
                    wordBreak: 'break-all',
                    marginBottom: '2rem',
                    width: '100%',
                }}>
                    {this.state.error?.message ?? 'Unknown error'}
                    {this.state.errorInfo !== null && (
                        <span style={{ color: '#505050' }}>
                            {'\n\nComponent Stack:' + this.state.errorInfo}
                        </span>
                    )}
                </pre>

                <div style={{ display: 'flex', gap: '0.75rem' }}>
                    <button
                        type="button"
                        onClick={this.handleRetry}
                        style={{
                            background: 'transparent',
                            border: '1px solid rgba(212, 160, 58, 0.4)',
                            color: '#D4A03A',
                            padding: '8px 24px',
                            fontFamily: 'inherit',
                            fontSize: '0.8rem',
                            cursor: 'pointer',
                            borderRadius: '2px',
                        }}
                    >
                        Retry
                    </button>
                    <button
                        type="button"
                        onClick={this.handleReset}
                        style={{
                            background: 'transparent',
                            border: '1px solid rgba(199, 84, 80, 0.4)',
                            color: '#C75450',
                            padding: '8px 24px',
                            fontFamily: 'inherit',
                            fontSize: '0.8rem',
                            cursor: 'pointer',
                            borderRadius: '2px',
                        }}
                    >
                        Return to Menu
                    </button>
                </div>
            </div>
        );
    }
}
