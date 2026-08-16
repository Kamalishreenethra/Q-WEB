import React, { useEffect, useState } from 'react';
import { api } from '../api/client';
import { Activity } from 'lucide-react';

export const Navbar: React.FC = () => {
  const [status, setStatus] = useState<string>('CONNECTING');

  useEffect(() => {
    api.getHealth()
      .then((res) => setStatus(res.status))
      .catch(() => setStatus('OFFLINE'));
  }, []);

  const isHealthy = status === 'HEALTHY';

  return (
    <header className="top-navbar">
      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontSize: '13px', color: 'var(--text-muted)' }}>
        <span>Cryptographic Supply Chain Posture</span>
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px' }}>
          <Activity size={14} color={isHealthy ? 'var(--status-low)' : 'var(--status-critical)'} />
          <span style={{ color: isHealthy ? 'var(--status-low)' : 'var(--status-critical)', fontWeight: 600 }}>
            API: {status}
          </span>
        </div>
      </div>
    </header>
  );
};
