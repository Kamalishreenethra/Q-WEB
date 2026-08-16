/**
 * Typed REST API Client for SignChain Backend.
 */
import {
  PaginatedResponse,
  StatusMessage,
  ScanResponse,
  ArtifactResponse,
  ArtifactDetailResponse,
  CertificateResponse,
  RiskResponse,
  PQCReadinessResponse,
  MigrationResponse,
  GraphResponse,
} from '../types/api';

const BASE_URL = import.meta.env.VITE_API_BASE_URL || '';

async function fetchJson<T>(endpoint: string, options?: RequestInit): Promise<T> {
  const url = `${BASE_URL}${endpoint}`;
  try {
    const res = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options?.headers,
      },
    });

    if (!res.ok) {
      let errorMsg = `HTTP Error ${res.status}: ${res.statusText}`;
      try {
        const errorJson = await res.json();
        if (errorJson.detail) {
          errorMsg = errorJson.detail;
        }
      } catch {
        // Fallback to generic message
      }
      throw new Error(errorMsg);
    }

    return await res.json();
  } catch (err: any) {
    if (err.name === 'TypeError' && err.message.includes('fetch')) {
      throw new Error(`Unable to connect to SignChain API at ${url}. Ensure the backend server is running.`);
    }
    throw err;
  }
}

export const api = {
  // Health
  getHealth: () => fetchJson<StatusMessage>('/health'),

  // Scans
  getScans: (page = 1, pageSize = 50, status?: string) => {
    const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
    if (status) params.append('status', status);
    return fetchJson<PaginatedResponse<ScanResponse>>(`/scans?${params.toString()}`);
  },

  getScan: (scanId: string) => fetchJson<ScanResponse>(`/scans/${scanId}`),

  // Artifacts
  getArtifacts: (
    page = 1,
    pageSize = 50,
    filters?: { ecosystem?: string; artifact_type?: string; scan_id?: string; name?: string }
  ) => {
    const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
    if (filters?.ecosystem) params.append('ecosystem', filters.ecosystem);
    if (filters?.artifact_type) params.append('artifact_type', filters.artifact_type);
    if (filters?.scan_id) params.append('scan_id', filters.scan_id);
    if (filters?.name) params.append('name', filters.name);
    return fetchJson<PaginatedResponse<ArtifactResponse>>(`/artifacts?${params.toString()}`);
  },

  getArtifact: (artifactId: string) =>
    fetchJson<ArtifactDetailResponse>(`/artifacts/${artifactId}`),

  // Certificates
  getCertificates: (
    page = 1,
    pageSize = 50,
    filters?: { algorithm?: string; quantum_status?: string; is_ca?: boolean }
  ) => {
    const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
    if (filters?.algorithm) params.append('algorithm', filters.algorithm);
    if (filters?.quantum_status) params.append('quantum_status', filters.quantum_status);
    if (filters?.is_ca !== undefined) params.append('is_ca', String(filters.is_ca));
    return fetchJson<PaginatedResponse<CertificateResponse>>(`/certificates?${params.toString()}`);
  },

  getCertificate: (fingerprint: string) =>
    fetchJson<CertificateResponse>(`/certificates/${fingerprint}`),

  // Risk
  getRiskAssessments: (page = 1, pageSize = 50, riskLevel?: string) => {
    const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
    if (riskLevel) params.append('risk_level', riskLevel);
    return fetchJson<PaginatedResponse<RiskResponse>>(`/risk?${params.toString()}`);
  },

  getRiskForArtifact: (artifactId: string) =>
    fetchJson<RiskResponse>(`/risk/${artifactId}`),

  // PQC Readiness
  getPQCReadiness: (page = 1, pageSize = 50, readinessState?: string) => {
    const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
    if (readinessState) params.append('readiness_state', readinessState);
    return fetchJson<PaginatedResponse<PQCReadinessResponse>>(`/pqc?${params.toString()}`);
  },

  getPQCForArtifact: (artifactId: string) =>
    fetchJson<PQCReadinessResponse>(`/pqc/${artifactId}`),

  // Migration Prioritization
  getMigrationAssessments: (
    page = 1,
    pageSize = 50,
    filters?: { priority?: string; priority_level?: string; migration_status?: string }
  ) => {
    const params = new URLSearchParams({ page: String(page), page_size: String(pageSize) });
    if (filters?.priority) params.append('priority', filters.priority);
    if (filters?.priority_level) params.append('priority_level', filters.priority_level);
    if (filters?.migration_status) params.append('migration_status', filters.migration_status);
    return fetchJson<PaginatedResponse<MigrationResponse>>(`/migration?${params.toString()}`);
  },

  getMigrationForArtifact: (artifactId: string) =>
    fetchJson<MigrationResponse>(`/migration/${artifactId}`),

  // Dependency Graph
  getGraphForArtifact: (artifactId: string) =>
    fetchJson<GraphResponse>(`/graph/${artifactId}`),

  getGraphForScan: (scanId: string) =>
    fetchJson<GraphResponse>(`/graph/scan/${scanId}`),
};
