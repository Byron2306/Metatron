import React from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';
import { Button } from './ui/button';

export default class WorkspaceErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, errorMessage: '' };
  }

  static getDerivedStateFromError(error) {
    return {
      hasError: true,
      errorMessage: error?.message || 'Unknown workspace error',
    };
  }

  componentDidCatch(error, info) {
    // eslint-disable-next-line no-console
    console.error('[WorkspaceErrorBoundary]', error, info);
  }

  handleRetry = () => {
    this.setState({ hasError: false, errorMessage: '' });
  };

  render() {
    if (this.state.hasError) {
      const title = this.props.title || 'Workspace unavailable';
      return (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-6 space-y-4">
          <div className="flex items-center gap-3 text-red-300">
            <AlertTriangle className="w-5 h-5" />
            <h2 className="text-lg font-semibold">{title}</h2>
          </div>
          <p className="text-sm text-red-100/80">
            This workspace pane failed to render. The shell is still alive so the rest of the dashboard remains usable.
          </p>
          <p className="text-xs text-red-200/70 font-mono break-all">
            {this.state.errorMessage}
          </p>
          <Button type="button" variant="outline" onClick={this.handleRetry} className="border-red-400/40">
            <RefreshCw className="w-4 h-4 mr-2" />
            Retry Pane
          </Button>
        </div>
      );
    }

    return this.props.children;
  }
}
