import React from 'react';

interface StatCardProps {
  label: string;
  value: string | number;
  subtext?: string;
  icon?: React.ReactNode;
  variant?: 'default' | 'critical' | 'warning' | 'success';
}

export const StatCard: React.FC<StatCardProps> = ({ label, value, subtext, icon, variant = 'default' }) => {
  const valueColor =
    variant === 'critical' ? 'var(--status-critical)' :
    variant === 'warning' ? 'var(--status-high)' :
    variant === 'success' ? 'var(--status-low)' : '#fff';

  return (
    <div className="stat-card">
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span className="stat-label">{label}</span>
        {icon && <span style={{ color: 'var(--text-muted)' }}>{icon}</span>}
      </div>
      <div className="stat-value" style={{ color: valueColor }}>{value}</div>
      {subtext && <div className="stat-subtext">{subtext}</div>}
    </div>
  );
};
