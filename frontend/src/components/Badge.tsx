import React from 'react';

interface BadgeProps {
  label: string | null | undefined;
  variant?: 'critical' | 'high' | 'medium' | 'low' | 'pqc' | 'hybrid' | 'info' | 'unknown' | 'p1' | 'p2' | 'p3' | 'p4';
}

export const Badge: React.FC<BadgeProps> = ({ label, variant }) => {
  if (!label) return <span className="badge badge-unknown">N/A</span>;

  const normalized = label.toUpperCase().trim();

  let computedVariant = variant;
  if (!computedVariant) {
    if (normalized === 'CRITICAL' || normalized === 'VULNERABLE' || normalized === 'P1') {
      computedVariant = normalized === 'P1' ? 'p1' : 'critical';
    } else if (normalized === 'HIGH' || normalized === 'WEAK_CLASSICAL' || normalized === 'P2') {
      computedVariant = normalized === 'P2' ? 'p2' : 'high';
    } else if (normalized === 'MEDIUM' || normalized === 'PARTIALLY_READY' || normalized === 'P3') {
      computedVariant = normalized === 'P3' ? 'p3' : 'medium';
    } else if (normalized === 'LOW' || normalized === 'QUANTUM_RESISTANT' || normalized === 'PQC_READY' || normalized === 'SUCCESS' || normalized === 'P4') {
      computedVariant = normalized === 'P4' ? 'p4' : normalized === 'PQC_READY' ? 'pqc' : 'low';
    } else if (normalized === 'HYBRID_READY') {
      computedVariant = 'hybrid';
    } else if (normalized === 'NOT_READY') {
      computedVariant = 'critical';
    } else {
      computedVariant = 'unknown';
    }
  }

  return (
    <span className={`badge badge-${computedVariant}`}>
      <span className="badge-dot" />
      {label}
    </span>
  );
};
