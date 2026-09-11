import React from 'react';
import { AlertCircle, RefreshCw, Terminal, ShieldAlert } from 'lucide-react';

interface LoadingSpinnerProps {
  message?: string;
}

export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({ message = 'Aggregating cryptographic intelligence...' }) => (
  <div className="empty-state">
    <div className="radar-pulse">
      <ShieldAlert size={20} color="var(--color-primary)" />
    </div>
    <div style={{ fontSize: '14px', fontWeight: 600, color: '#fff', marginBottom: '4px' }}>
      Analyzing Cryptographic Posture
    </div>
    <p style={{ color: 'var(--text-muted)', fontSize: '12px' }}>{message}</p>
  </div>
);

interface ErrorAlertProps {
  message: string;
  onRetry?: () => void;
  endpoint?: string;
}

export const ErrorAlert: React.FC<ErrorAlertProps> = ({ message, onRetry, endpoint }) => (
  <div className="error-alert">
    <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
      <AlertCircle size={20} color="var(--status-critical)" />
      <div>
        <div style={{ fontWeight: 600, fontSize: '13px' }}>Backend Communication Notice</div>
        <div style={{ fontSize: '12px', opacity: 0.9 }}>{message}</div>
        {endpoint && (
          <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', marginTop: '2px' }}>
            Target Endpoint: {endpoint}
          </div>
        )}
      </div>
    </div>
    {onRetry && (
      <button className="btn" onClick={onRetry} style={{ borderColor: 'var(--status-critical-border)' }}>
        <RefreshCw size={13} />
        Retry Connection
      </button>
    )}
  </div>
);

interface EmptyStateProps {
  title: string;
  description: string;
  icon?: React.ReactNode;
  actionCommand?: string;
  onRefresh?: () => void;
}

export const EmptyState: React.FC<EmptyStateProps> = ({
  title,
  description,
  icon,
  actionCommand,
  onRefresh,
}) => (
  <div className="empty-state">
    <div className="empty-state-icon">
      {icon || <ShieldAlert size={28} />}
    </div>
    <div className="empty-state-title">{title}</div>
    <div className="empty-state-desc">{description}</div>
    {actionCommand && (
      <div className="terminal-box">
        <Terminal size={14} />
        <code>{actionCommand}</code>
      </div>
    )}
    {onRefresh && (
      <button className="btn" onClick={onRefresh} style={{ marginTop: '16px' }}>
        <RefreshCw size={13} />
        Refresh Data
      </button>
    )}
  </div>
);

interface PaginationProps {
  page: number;
  totalPages: number;
  totalItems: number;
  pageSize: number;
  onPageChange: (newPage: number) => void;
  onPageSizeChange?: (newSize: number) => void;
}

export const Pagination: React.FC<PaginationProps> = ({
  page,
  totalPages,
  totalItems,
  pageSize,
  onPageChange,
  onPageSizeChange,
}) => {
  const startIdx = totalItems === 0 ? 0 : (page - 1) * pageSize + 1;
  const endIdx = Math.min(page * pageSize, totalItems);

  return (
    <div className="pagination" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '16px 0', borderTop: '1px solid rgba(255,255,255,0.05)', marginTop: '8px' }}>
      <div style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
        Showing <span style={{ color: '#fff', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>{startIdx}</span> to{' '}
        <span style={{ color: '#fff', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>{endIdx}</span> of{' '}
        <span style={{ color: '#fff', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>{totalItems}</span> records
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        {onPageSizeChange && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '12px', color: 'var(--text-muted)' }}>
            <span>Page size:</span>
            <select
              className="select-input"
              value={pageSize}
              onChange={(e) => onPageSizeChange(Number(e.target.value))}
              style={{ padding: '4px 8px', fontSize: '12px' }}
            >
              <option value="10">10</option>
              <option value="20">20</option>
              <option value="50">50</option>
              <option value="100">100</option>
            </select>
          </div>
        )}

        <div style={{ display: 'flex', gap: '6px' }}>
          <button
            className="btn"
            disabled={page <= 1}
            onClick={() => onPageChange(1)}
            title="First Page"
            style={{ padding: '4px 8px', fontSize: '11px' }}
          >
            « First
          </button>
          <button
            className="btn"
            disabled={page <= 1}
            onClick={() => onPageChange(page - 1)}
            style={{ padding: '4px 10px', fontSize: '12px' }}
          >
            Prev
          </button>
          <span style={{ display: 'flex', alignItems: 'center', padding: '0 8px', fontSize: '12px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
            Page {page} / {Math.max(1, totalPages)}
          </span>
          <button
            className="btn"
            disabled={page >= totalPages}
            onClick={() => onPageChange(page + 1)}
            style={{ padding: '4px 10px', fontSize: '12px' }}
          >
            Next
          </button>
          <button
            className="btn"
            disabled={page >= totalPages}
            onClick={() => onPageChange(totalPages)}
            title="Last Page"
            style={{ padding: '4px 8px', fontSize: '11px' }}
          >
            Last »
          </button>
        </div>
      </div>
    </div>
  );
};
