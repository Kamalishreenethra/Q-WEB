/**
 * TypeScript API interfaces matching FastAPI Pydantic schemas.
 */

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export interface StatusMessage {
  status: string;
  message?: string;
  version: string;
}

export interface ScanResponse {
  id: string;
  timestamp: string;
  scanner_version: string;
  status: string;
  duration_sec: number;
  artifact_count: number;
  error_count: number;
  metadata_json?: Record<string, any>;
}

export interface CertificateResponse {
  fingerprint: string;
  subject: string;
  issuer: string;
  serial_number?: string;
  algorithm: string;
  key_size?: number;
  curve?: string;
  valid_from?: string;
  valid_to?: string;
  quantum_status: 'VULNERABLE' | 'QUANTUM_RESISTANT' | 'WEAK_CLASSICAL' | 'UNKNOWN';
  is_ca: boolean;
}

export interface SignatureResponse {
  id: string;
  artifact_id: string;
  certificate_fingerprint?: string;
  ecosystem: string;
  signature_type: string;
  status: string;
  verification_status: string;
  algorithm: string;
  signing_time?: string;
  evidence_status: string;
  certificate?: CertificateResponse;
}

export interface RiskResponse {
  id: string;
  artifact_id: string;
  risk_score: number;
  risk_level: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  factor_breakdown: {
    crypto_risk?: number;
    asset_criticality?: number;
    exposure?: number;
    validity_horizon?: number;
    dependency_impact?: number;
    migration_complexity?: number;
    [key: string]: any;
  };
  calculation_explanation: string;
  model_version: string;
  created_at: string;
}

export interface PQCReadinessResponse {
  id: string;
  artifact_id: string;
  readiness_state: 'NOT_READY' | 'PARTIALLY_READY' | 'HYBRID_READY' | 'PQC_READY' | 'UNKNOWN';
  migration_phase: string;
  candidate_algorithms?: Array<{
    name: string;
    family: string;
    security_category: number;
    nist_status: string;
  }>;
  compatibility?: Record<string, any>;
  blockers?: string[];
  evidence?: Array<{
    level: string;
    type: string;
    description: string;
  }>;
  assessment_version: string;
}

export interface MigrationResponse {
  id: string;
  artifact_id: string;
  priority_code: 'P1' | 'P2' | 'P3' | 'P4';
  priority_score: number;
  priority_level: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  migration_status: string;
  recommended_action: string;
  blockers?: string[];
  rationale: string;
  migration_phase: string;
}

export interface ArtifactResponse {
  id: string;
  scan_id: string;
  name: string;
  path: string;
  artifact_type: string;
  ecosystem: string;
  registry?: string;
  repository?: string;
  tag?: string;
  digest?: string;
  created_at: string;
  updated_at: string;
}

export interface ArtifactDetailResponse extends ArtifactResponse {
  signatures: SignatureResponse[];
  risk_assessment?: RiskResponse;
  pqc_assessment?: PQCReadinessResponse;
  migration_assessment?: MigrationResponse;
}

export interface DependencyNodeResponse {
  id: string;
  node_id: string;
  node_type: string;
  name: string;
  metadata_json?: Record<string, any>;
}

export interface DependencyEdgeResponse {
  id: string;
  source_id: string;
  target_id: string;
  edge_type: string;
  metadata_json?: Record<string, any>;
}

export interface GraphResponse {
  scan_id?: string;
  artifact_id?: string;
  nodes: DependencyNodeResponse[];
  edges: DependencyEdgeResponse[];
  statistics?: {
    node_count: number;
    edge_count: number;
    [key: string]: any;
  };
}
