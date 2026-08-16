import React from 'react';
import { NavLink } from 'react-router-dom';
import {
  ShieldAlert,
  LayoutDashboard,
  Layers,
  KeyRound,
  AlertTriangle,
  Zap,
  GitPullRequest,
  Network,
  History,
  FlaskConical,
} from 'lucide-react';

export const Sidebar: React.FC = () => {
  const navItems = [
    { to: '/', label: 'Overview', icon: <LayoutDashboard size={18} /> },
    { to: '/artifacts', label: 'Asset Inventory', icon: <Layers size={18} /> },
    { to: '/certificates', label: 'Certificates', icon: <KeyRound size={18} /> },
    { to: '/risk', label: 'Quantum Risk', icon: <AlertTriangle size={18} /> },
    { to: '/pqc', label: 'PQC Readiness', icon: <Zap size={18} /> },
    { to: '/migration', label: 'Migration Priority', icon: <GitPullRequest size={18} /> },
    { to: '/graph', label: 'Dependency Graph', icon: <Network size={18} /> },
    { to: '/scans', label: 'Scan History', icon: <History size={18} /> },
    { to: '/research', label: 'Research Evaluation', icon: <FlaskConical size={18} /> },
  ];

  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <ShieldAlert size={26} color="var(--color-primary)" />
        <div className="sidebar-logo">
          SignChain
          <span style={{ fontSize: '10px', background: 'rgba(56,189,248,0.15)', color: 'var(--color-primary)', padding: '2px 6px', borderRadius: '4px' }}>
            RESEARCH
          </span>
        </div>
      </div>
      <nav className="sidebar-nav">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
            end={item.to === '/'}
          >
            {item.icon}
            <span>{item.label}</span>
          </NavLink>
        ))}
      </nav>
      <div style={{ padding: '16px 20px', borderTop: '1px solid var(--border-color)', fontSize: '11px', color: 'var(--text-dim)' }}>
        Post-Quantum Cryptographic Migration Platform v0.1.0
      </div>
    </aside>
  );
};
