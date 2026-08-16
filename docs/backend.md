# SignChain Backend Architecture: Persistent Database & REST API

## 1. Overview & Purpose
Phase 12 introduces the persistence and REST API layer for SignChain. It provides a standardized interface for saving, querying, and analyzing discovered cryptographic signing artifacts, certificates, signatures, risk evaluations, PQC readiness states, migration priorities, and dependency graph relationships.

---

## 2. Architectural Separation of Concerns

> [!IMPORTANT]
> **Source of Truth Principle**:
> The database and REST API do NOT implement or recalculate cryptographic algorithms, quantum risk scores, readiness statuses, or migration priorities.
> - **Discovery**: Scanner plugins (`X509Scanner`, `PEScanner`, `PGPScanner`, `SigstoreScanner`, `ContainerScanner`)
> - **Classification**: `CryptoClassifier`
> - **Risk Assessment**: `QuantumRiskEngine`
> - **Readiness Evaluation**: `PQCReadinessEngine`
> - **Roadmap Generation**: `MigrationPrioritizationEngine`
> - **Graph Analytics**: NetworkX `DependencyGraph`
> - **Persistence**: SQLAlchemy models (`Scan`, `Artifact`, `Certificate`, `Signature`, `RiskAssessment`, `PQCReadinessAssessment`, `MigrationAssessment`, `DependencyNode`, `DependencyEdge`)
> - **API Delivery**: FastAPI REST endpoints with Pydantic schemas

---

## 3. Database Architecture & SQLAlchemy Models

SignChain supports **SQLite** by default (offline-first development) and **PostgreSQL** in production via environment-driven configuration (`DATABASE_URL`).

### Database Entity Relationship Model
```
  ┌──────────────┐
  │     Scan     │
  └──────┬───────┘
         │ 1..N
         ├─────────────────────────────────────────┬────────────────────────────┐
         ▼                                         ▼                            ▼
  ┌──────────────┐                          ┌──────────────┐             ┌──────────────┐
  │   Artifact   │                          │DependencyNode│             │DependencyEdge│
  └──────┬───────┘                          └──────────────┘             └──────────────┘
         │ 1..N
         ├─────────────────┬───────────────────────┬────────────────────────────┐
         ▼                 ▼                       ▼                            ▼
  ┌──────────────┐  ┌──────────────┐        ┌──────────────┐             ┌──────────────┐
  │  Signature   │  │RiskAssessment│        │PQCReadiness  │             │  Migration   │
  └──────┬───────┘  └──────────────┘        │  Assessment  │             │  Assessment  │
         │ N..1                             └──────────────┘             └──────────────┘
         ▼
  ┌──────────────┐
  │ Certificate  │
  └──────────────┘
```

---

## 4. Alembic Schema Migrations

Database schemas are tracked via Alembic:
- Configuration: `alembic.ini`
- Environment: `migrations/env.py`
- Versions: `migrations/versions/001_initial_schema.py`

### Migration Commands
```powershell
# Apply all migrations to current database
alembic upgrade head

# Downgrade to baseline
alembic downgrade base
```

---

## 5. REST API Endpoints

FastAPI exposes the following endpoints (interactive OpenAPI docs at `/docs`):

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Service health status and version. |
| `GET` | `/scans` | List scan runs (paginated, filter by `status`). |
| `GET` | `/scans/{scan_id}` | Retrieve scan details by ID. |
| `POST` | `/scans/ingest` | Ingest a raw scan result dictionary. |
| `GET` | `/artifacts` | List artifacts (paginated, filter by `ecosystem`, `artifact_type`, `name`). |
| `GET` | `/artifacts/{artifact_id}` | Detailed artifact information including signatures and assessments. |
| `GET` | `/certificates` | List reusable certificates (filter by `algorithm`, `quantum_status`, `is_ca`). |
| `GET` | `/certificates/{fingerprint}` | Certificate metadata by fingerprint. |
| `GET` | `/risk` | List risk assessments (filter by `risk_level`). |
| `GET` | `/risk/{artifact_id}` | Quantum risk assessment and factor breakdown for artifact. |
| `GET` | `/pqc` | List PQC readiness assessments (filter by `readiness_state`). |
| `GET` | `/pqc/{artifact_id}` | PQC readiness state, candidate algorithms, and blockers for artifact. |
| `GET` | `/migration` | List migration priorities (filter by `priority`, `priority_level`, `migration_status`). |
| `GET` | `/migration/{artifact_id}` | Migration prioritization, action recommendation, and rationale. |
| `GET` | `/graph/{artifact_id}` | Subgraph nodes and edges for artifact's scan execution. |
| `GET` | `/graph/scan/{scan_id}` | Complete dependency graph structure for a scan run. |

---

## 6. Security Model & Safeguards

1. **Local Bind Default**: The API server strictly binds to `127.0.0.1` by default unless explicitly specified.
2. **Safe SQL Operations**: Pure SQLAlchemy ORM and parameterized queries; no raw SQL concatenation.
3. **Bounded Queries**: All list endpoints enforce strict pagination with a hard maximum of 100 items per request.
4. **Deferred Authentication Notice**: Local development baseline; production user authentication, JWT tokens, and role-based access control (RBAC) are deferred to dedicated security hardening phases.

---

## 7. CLI Integration

```powershell
# Start local API server
signchain serve --host 127.0.0.1 --port 8000

# Store scan results directly into database
signchain store release_scan.json
signchain store target_app.exe
```
