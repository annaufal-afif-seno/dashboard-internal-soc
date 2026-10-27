import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App.jsx';
import './index.css';

// Global error catcher to prevent white/blank screen
window.addEventListener('error', (e) => {
  console.error("Global Error Caught:", e);
  const root = document.getElementById('root');
  if (root && (!root.innerHTML || root.innerHTML.trim() === '')) {
    root.innerHTML = `
      <div style="padding: 24px; font-family: monospace; background: #fee2e2; color: #991b1b; min-height: 100vh;">
        <h2 style="font-size: 18px; font-weight: bold; margin-bottom: 8px;">⚠️ Runtime Error Detected</h2>
        <p style="font-size: 14px; margin-bottom: 12px;">${e.message || 'Unknown error'}</p>
        <pre style="background: white; padding: 12px; border-radius: 6px; border: 1px solid #fca5a5; font-size: 12px; overflow: auto;">${e.error ? e.error.stack : (e.filename + ':' + e.lineno + ':' + e.colno)}</pre>
        <div style="margin-top: 16px;">
          <button onclick="localStorage.clear(); location.reload();" style="padding: 8px 16px; background: #dc2626; color: white; border: none; border-radius: 6px; cursor: pointer; font-weight: bold;">
            Clear LocalStorage & Hard Reload
          </button>
        </div>
      </div>
    `;
  }
});

class GlobalErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error("React Component Crash:", error, errorInfo);
    this.setState({ errorInfo });
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: '24px', fontFamily: 'monospace', background: '#fee2e2', color: '#991b1b', minHeight: '100vh' }}>
          <h2 style={{ fontSize: '18px', fontWeight: 'bold', marginBottom: '8px' }}>⚠️ React Component Crash</h2>
          <p style={{ fontSize: '14px', marginBottom: '12px' }}>{this.state.error?.toString()}</p>
          <pre style={{ background: 'white', padding: '12px', borderRadius: '6px', border: '1px solid #fca5a5', fontSize: '12px', overflow: 'auto' }}>
            {this.state.error?.stack}
            {'\n\nComponent Stack:\n'}
            {this.state.errorInfo?.componentStack}
          </pre>
          <div style={{ marginTop: '16px', display: 'flex', gap: '12px' }}>
            <button 
              onClick={() => { localStorage.clear(); window.location.reload(); }}
              style={{ padding: '8px 16px', background: '#dc2626', color: 'white', border: 'none', borderRadius: '6px', cursor: 'pointer', fontWeight: 'bold' }}
            >
              Clear LocalStorage & Reload
            </button>
            <button 
              onClick={() => window.location.reload()}
              style={{ padding: '8px 16px', background: '#2563eb', color: 'white', border: 'none', borderRadius: '6px', cursor: 'pointer', fontWeight: 'bold' }}
            >
              Normal Reload
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <GlobalErrorBoundary>
      <App />
    </GlobalErrorBoundary>
  </React.StrictMode>,
);

