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
  const mainNav = [
    { to: '/', label: 'Overview', icon: <LayoutDashboard size={17} /> },
    { to: '/artifacts', label: 'Asset Inventory', icon: <Layers size={17} /> },
    { to: '/certificates', label: 'Certificates', icon: <KeyRound size={17} /> },
  ];

  const intelligenceNav = [
    { to: '/risk', label: 'Quantum Risk', icon: <AlertTriangle size={17} /> },
    { to: '/pqc', label: 'PQC Readiness', icon: <Zap size={17} /> },
    { to: '/migration', label: 'Migration Priority', icon: <GitPullRequest size={17} /> },
    { to: '/graph', label: 'Dependency Graph', icon: <Network size={17} /> },
  ];

  const auditNav = [
    { to: '/scans', label: 'Scan History', icon: <History size={17} /> },
    { to: '/research', label: 'Research Evaluation', icon: <FlaskConical size={17} /> },
  ];

  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <ShieldAlert size={24} color="var(--color-primary)" />
        <div className="sidebar-logo">
          SignChain
          <span className="badge-tag">PQC INTELLIGENCE</span>
        </div>
      </div>

      <nav className="sidebar-nav">
        <div className="nav-section-title">Core Posture</div>
        {mainNav.map((item) => (
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

        <div className="nav-section-title" style={{ marginTop: '10px' }}>Cryptographic Intelligence</div>
        {intelligenceNav.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          >
            {item.icon}
            <span>{item.label}</span>
          </NavLink>
        ))}

        <div className="nav-section-title" style={{ marginTop: '10px' }}>Audit & Research</div>
        {auditNav.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}
          >
            {item.icon}
            <span>{item.label}</span>
          </NavLink>
        ))}
      </nav>

      <div className="sidebar-footer">
        <div style={{ fontWeight: 600, color: 'var(--text-muted)' }}>SignChain Migration Engine</div>
        <div style={{ fontSize: '10px', color: 'var(--text-dim)' }}>
          NIST FIPS 204/205 Transition
        </div>
      </div>
    </aside>
  );
};
