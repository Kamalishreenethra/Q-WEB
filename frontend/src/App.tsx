import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { Layout } from './components/Layout';
import { OverviewPage } from './pages/OverviewPage';
import { ArtifactsPage } from './pages/ArtifactsPage';
import { ArtifactDetailPage } from './pages/ArtifactDetailPage';
import { CertificatesPage } from './pages/CertificatesPage';
import { RiskPage } from './pages/RiskPage';
import { PQCReadinessPage } from './pages/PQCReadinessPage';
import { MigrationPage } from './pages/MigrationPage';
import { GraphPage } from './pages/GraphPage';
import { ScansPage } from './pages/ScansPage';
import { ResearchPage } from './pages/ResearchPage';

export const App: React.FC = () => {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<OverviewPage />} />
          <Route path="artifacts" element={<ArtifactsPage />} />
          <Route path="artifacts/:id" element={<ArtifactDetailPage />} />
          <Route path="certificates" element={<CertificatesPage />} />
          <Route path="risk" element={<RiskPage />} />
          <Route path="pqc" element={<PQCReadinessPage />} />
          <Route path="migration" element={<MigrationPage />} />
          <Route path="graph" element={<GraphPage />} />
          <Route path="scans" element={<ScansPage />} />
          <Route path="research" element={<ResearchPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
};

export default App;
