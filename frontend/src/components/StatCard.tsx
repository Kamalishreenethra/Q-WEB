import React from 'react';

interface StatCardProps {
  label: string;
  value: number | string;
  subtext?: string;
  icon?: React.ReactNode;
  variant?: 'default' | 'critical' | 'success' | 'pqc';
  trend?: string;
}

export const StatCard: React.FC<StatCardProps> = ({
  label,
  value,
  subtext,
  icon,
  variant = 'default',
  trend,
}) => {
  return (
    <div className={`stat-card variant-${variant}`}>
      <div className="stat-header">
        <span className="stat-label">{label}</span>
        {icon && <div className="stat-icon">{icon}</div>}
      </div>
      <div className="stat-value">{typeof value === 'number' ? value.toLocaleString() : value}</div>
      {(subtext || trend) && (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: '2px' }}>
          {subtext && <span className="stat-subtext">{subtext}</span>}
          {trend && (
            <span style={{ fontSize: '11px', color: 'var(--color-primary)', fontWeight: 600 }}>
              {trend}
            </span>
          )}
        </div>
      )}
    </div>
  );
};
