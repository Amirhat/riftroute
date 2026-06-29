import { Component, type ReactNode } from 'react'

// ErrorBoundary stops a render error in one view from blanking the entire app.
// Without it, an unexpected data shape (e.g. a real-provider field the fake one
// never emits) throws during render, React unmounts the whole tree, and the
// window goes blank. Here it degrades to a readable message with a retry.
export class ErrorBoundary extends Component<{ children: ReactNode }, { error: Error | null }> {
  state = { error: null as Error | null }

  static getDerivedStateFromError(error: Error) {
    return { error }
  }

  componentDidCatch(error: Error, info: unknown) {
    // Surfaces in the WKWebView console for debugging.
    console.error('RiftRoute UI render error:', error, info)
  }

  reset = () => this.setState({ error: null })

  render() {
    const { error } = this.state
    if (error) {
      return (
        <div className="flex h-full items-center justify-center p-8">
          <div className="max-w-md rounded-xl border border-line bg-surface p-6 text-center">
            <div className="text-base font-semibold text-danger">Couldn’t render this view</div>
            <p className="mt-2 text-sm text-muted">{error.message}</p>
            <p className="mt-1 text-xs text-muted">
              Routing is unaffected — the daemon runs independently of this window.
            </p>
            <button
              onClick={this.reset}
              className="mt-4 rounded-lg bg-accent px-3 py-1.5 text-sm font-medium text-accent-contrast hover:opacity-90"
            >
              Try again
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}
