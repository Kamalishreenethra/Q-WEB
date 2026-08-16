import React from 'react';

interface LoadingSpinnerProps {
  message?: string;
}

export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({ message = 'Loading cryptographic intelligence...' }) => (
  <div className="state-box">
    <div className="spinner" />
    <p>{message}</p>
  </div>
);

interface ErrorAlertProps {
  message: string;
  onRetry?: () => void;
}

export const ErrorAlert: React.FC<ErrorAlertProps> = ({ message, onRetry }) => (
  <div className="error-alert">
    <div style={{ flexGrow: 1 }}>{message}</div>
    {onRetry && (
      <button className="btn" onClick={onRetry}>
        Retry
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
}

export const Pagination: React.FC<PaginationProps> = ({
  page,
  totalPages,
  totalItems,
  pageSize,
  onPageChange,
}) => {
  const startIdx = totalItems === 0 ? 0 : (page - 1) * pageSize + 1;
  const endIdx = Math.min(page * pageSize, totalItems);

  return (
    <div className="pagination">
      <div>
        Showing <span style={{ color: '#fff', fontWeight: 600 }}>{startIdx}</span> to{' '}
        <span style={{ color: '#fff', fontWeight: 600 }}>{endIdx}</span> of{' '}
        <span style={{ color: '#fff', fontWeight: 600 }}>{totalItems}</span> records
      </div>
      <div style={{ display: 'flex', gap: '8px' }}>
        <button
          className="btn"
          disabled={page <= 1}
          onClick={() => onPageChange(page - 1)}
        >
          Previous
        </button>
        <span style={{ display: 'flex', alignItems: 'center', padding: '0 8px' }}>
          Page {page} of {Math.max(1, totalPages)}
        </span>
        <button
          className="btn"
          disabled={page >= totalPages}
          onClick={() => onPageChange(page + 1)}
        >
          Next
        </button>
      </div>
    </div>
  );
};
