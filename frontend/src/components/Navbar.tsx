import React, { useEffect, useState } from 'react';
import { useLocation } from 'react-router-dom';
import { api } from '../api/client';
import { Activity, RefreshCw, Database } from 'lucide-react';

export const Navbar: React.FC = () => {
  const location = useLocation();
  const [apiStatus, setApiStatus] = useState<'ONLINE' | 'OFFLINE' | 'CHECKING'>('CHECKING');
  const [version, setVersion] = useState<string>('0.1.0');
  const [lastCheck, setLastCheck] = useState<Date>(new Date());
  const [refreshing, setRefreshing] = useState<boolean>(false);

  useEffect(() => {
    checkHealth();
    const timer = setInterval(checkHealth, 20000); // 20s health poll
    return () => clearInterval(timer);
  }, []);

  async function checkHealth() {
    try {
      const res = await api.getHealth();
      if (res.status === 'HEALTHY') {
        setApiStatus('ONLINE');
        if (res.version) setVersion(res.version);
      } else {
        setApiStatus('OFFLINE');
      }
    } catch {
      setApiStatus('OFFLINE');
    } finally {
      setLastCheck(new Date());
    }
  }

  async function handleManualRefresh() {
    setRefreshing(true);
    await checkHealth();
    setTimeout(() => setRefreshing(false), 500);
  }

  const pathSegments = location.pathname.split('/').filter(Boolean);
  const pageName = pathSegments.length === 0
    ? 'Overview'
    : pathSegments[0].charAt(0).toUpperCase() + pathSegments[0].slice(1);

  return (
    <header className="top-navbar">
      <div className="breadcrumb">
        <span>SignChain Core</span>
        <span>/</span>
        <span className="breadcrumb-active">{pageName}</span>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        {/* Database Mode */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--text-dim)', background: 'rgba(255,255,255,0.03)', padding: '4px 10px', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
          <Database size={12} color="var(--color-primary)" />
          <span>Storage: SQLite (Local)</span>
        </div>

        {/* Live API Health Status */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            fontSize: '11px',
            fontFamily: 'var(--font-mono)',
            padding: '4px 10px',
            borderRadius: '4px',
            background: apiStatus === 'ONLINE' ? 'var(--status-low-bg)' : apiStatus === 'CHECKING' ? 'var(--status-medium-bg)' : 'var(--status-critical-bg)',
            border: `1px solid ${apiStatus === 'ONLINE' ? 'var(--status-low-border)' : apiStatus === 'CHECKING' ? 'var(--status-medium-border)' : 'var(--status-critical-border)'}`,
            color: apiStatus === 'ONLINE' ? 'var(--status-low)' : apiStatus === 'CHECKING' ? 'var(--status-medium)' : 'var(--status-critical)',
            fontWeight: 700,
          }}
        >
          <Activity size={13} className={apiStatus === 'CHECKING' ? 'animate-spin' : ''} />
          <span>API: {apiStatus}</span>
          <span style={{ opacity: 0.6, fontSize: '10px' }}>v{version}</span>
        </div>

        {/* Manual Refresh Button */}
        <button
          className="btn"
          onClick={handleManualRefresh}
          title={`Last checked: ${lastCheck.toLocaleTimeString()}`}
          style={{ padding: '4px 8px', fontSize: '11px' }}
        >
          <RefreshCw size={12} className={refreshing ? 'animate-spin' : ''} />
          <span>Refresh</span>
        </button>
      </div>
    </header>
  );
};
