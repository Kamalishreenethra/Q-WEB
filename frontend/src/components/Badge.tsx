import React from 'react';

interface BadgeProps {
  label: string;
  type?: 'critical' | 'high' | 'medium' | 'low' | 'info' | 'ready' | 'hybrid' | 'unknown';
}

export const Badge: React.FC<BadgeProps> = ({ label, type }) => {
  const normalizedType = type || getBadgeType(label);
  return <span className={`badge badge-${normalizedType}`}>{label}</span>;
};

function getBadgeType(label: string): string {
  const upper = label.toUpperCase();
  if (['CRITICAL', 'P1', 'VULNERABLE', 'NOT_READY'].includes(upper)) return 'critical';
  if (['HIGH', 'P2'].includes(upper)) return 'high';
  if (['MEDIUM', 'P3', 'PARTIALLY_READY'].includes(upper)) return 'medium';
  if (['LOW', 'P4', 'PQC_READY', 'QUANTUM_RESISTANT', 'SUCCESS', 'READY'].includes(upper)) return 'low';
  if (['HYBRID_READY'].includes(upper)) return 'hybrid';
  if (['INFO', 'ACTION_REQUIRED'].includes(upper)) return 'info';
  return 'unknown';
}
