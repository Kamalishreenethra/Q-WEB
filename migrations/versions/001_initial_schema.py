"""Initial schema for SignChain database

Revision ID: 001_initial_schema
Revises: 
Create Date: 2026-08-16 20:15:00.000000

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = '001_initial_schema'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # 1. Scans
    op.create_table(
        'scans',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('timestamp', sa.DateTime(), nullable=False),
        sa.Column('scanner_version', sa.String(length=32), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('duration_sec', sa.Float(), nullable=False),
        sa.Column('artifact_count', sa.Integer(), nullable=False),
        sa.Column('error_count', sa.Integer(), nullable=False),
        sa.Column('metadata_json', sa.JSON(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_scans_status'), 'scans', ['status'], unique=False)
    op.create_index(op.f('ix_scans_timestamp'), 'scans', ['timestamp'], unique=False)

    # 2. Certificates
    op.create_table(
        'certificates',
        sa.Column('fingerprint', sa.String(length=64), nullable=False),
        sa.Column('subject', sa.Text(), nullable=False),
        sa.Column('issuer', sa.Text(), nullable=False),
        sa.Column('serial_number', sa.String(length=128), nullable=True),
        sa.Column('algorithm', sa.String(length=64), nullable=False),
        sa.Column('key_size', sa.Integer(), nullable=True),
        sa.Column('curve', sa.String(length=64), nullable=True),
        sa.Column('valid_from', sa.String(length=64), nullable=True),
        sa.Column('valid_to', sa.String(length=64), nullable=True),
        sa.Column('quantum_status', sa.String(length=32), nullable=False),
        sa.Column('is_ca', sa.Boolean(), nullable=False),
        sa.PrimaryKeyConstraint('fingerprint')
    )
    op.create_index(op.f('ix_certificates_algorithm'), 'certificates', ['algorithm'], unique=False)
    op.create_index(op.f('ix_certificates_quantum_status'), 'certificates', ['quantum_status'], unique=False)

    # 3. Artifacts
    op.create_table(
        'artifacts',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('scan_id', sa.String(length=36), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('path', sa.Text(), nullable=False),
        sa.Column('artifact_type', sa.String(length=64), nullable=False),
        sa.Column('ecosystem', sa.String(length=64), nullable=False),
        sa.Column('registry', sa.String(length=255), nullable=True),
        sa.Column('repository', sa.String(length=255), nullable=True),
        sa.Column('tag', sa.String(length=128), nullable=True),
        sa.Column('digest', sa.String(length=128), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_artifacts_artifact_type'), 'artifacts', ['artifact_type'], unique=False)
    op.create_index(op.f('ix_artifacts_digest'), 'artifacts', ['digest'], unique=False)
    op.create_index(op.f('ix_artifacts_ecosystem'), 'artifacts', ['ecosystem'], unique=False)
    op.create_index(op.f('ix_artifacts_name'), 'artifacts', ['name'], unique=False)
    op.create_index(op.f('ix_artifacts_scan_id'), 'artifacts', ['scan_id'], unique=False)
    op.create_index('ix_artifacts_ecosystem_type', 'artifacts', ['ecosystem', 'artifact_type'], unique=False)

    # 4. Signatures
    op.create_table(
        'signatures',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('artifact_id', sa.String(length=36), nullable=False),
        sa.Column('certificate_fingerprint', sa.String(length=64), nullable=True),
        sa.Column('ecosystem', sa.String(length=64), nullable=False),
        sa.Column('signature_type', sa.String(length=64), nullable=False),
        sa.Column('status', sa.String(length=32), nullable=False),
        sa.Column('verification_status', sa.String(length=64), nullable=False),
        sa.Column('algorithm', sa.String(length=64), nullable=False),
        sa.Column('signing_time', sa.String(length=64), nullable=True),
        sa.Column('evidence_status', sa.String(length=32), nullable=False),
        sa.ForeignKeyConstraint(['artifact_id'], ['artifacts.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['certificate_fingerprint'], ['certificates.fingerprint'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_signatures_artifact_id'), 'signatures', ['artifact_id'], unique=False)
    op.create_index(op.f('ix_signatures_certificate_fingerprint'), 'signatures', ['certificate_fingerprint'], unique=False)
    op.create_index(op.f('ix_signatures_ecosystem'), 'signatures', ['ecosystem'], unique=False)
    op.create_index(op.f('ix_signatures_status'), 'signatures', ['status'], unique=False)
    op.create_index(op.f('ix_signatures_verification_status'), 'signatures', ['verification_status'], unique=False)

    # 5. Risk Assessments
    op.create_table(
        'risk_assessments',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('artifact_id', sa.String(length=36), nullable=False),
        sa.Column('risk_score', sa.Float(), nullable=False),
        sa.Column('risk_level', sa.String(length=32), nullable=False),
        sa.Column('factor_breakdown', sa.JSON(), nullable=False),
        sa.Column('calculation_explanation', sa.Text(), nullable=False),
        sa.Column('model_version', sa.String(length=32), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['artifact_id'], ['artifacts.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('artifact_id')
    )
    op.create_index(op.f('ix_risk_assessments_artifact_id'), 'risk_assessments', ['artifact_id'], unique=True)
    op.create_index(op.f('ix_risk_assessments_risk_level'), 'risk_assessments', ['risk_level'], unique=False)
    op.create_index(op.f('ix_risk_assessments_risk_score'), 'risk_assessments', ['risk_score'], unique=False)

    # 6. PQC Readiness Assessments
    op.create_table(
        'pqc_readiness_assessments',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('artifact_id', sa.String(length=36), nullable=False),
        sa.Column('readiness_state', sa.String(length=32), nullable=False),
        sa.Column('migration_phase', sa.String(length=64), nullable=False),
        sa.Column('candidate_algorithms', sa.JSON(), nullable=True),
        sa.Column('compatibility', sa.JSON(), nullable=True),
        sa.Column('blockers', sa.JSON(), nullable=True),
        sa.Column('evidence', sa.JSON(), nullable=True),
        sa.Column('assessment_version', sa.String(length=32), nullable=False),
        sa.ForeignKeyConstraint(['artifact_id'], ['artifacts.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('artifact_id')
    )
    op.create_index(op.f('ix_pqc_readiness_assessments_artifact_id'), 'pqc_readiness_assessments', ['artifact_id'], unique=True)
    op.create_index(op.f('ix_pqc_readiness_assessments_readiness_state'), 'pqc_readiness_assessments', ['readiness_state'], unique=False)

    # 7. Migration Assessments
    op.create_table(
        'migration_assessments',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('artifact_id', sa.String(length=36), nullable=False),
        sa.Column('priority_code', sa.String(length=8), nullable=False),
        sa.Column('priority_score', sa.Float(), nullable=False),
        sa.Column('priority_level', sa.String(length=32), nullable=False),
        sa.Column('migration_status', sa.String(length=32), nullable=False),
        sa.Column('recommended_action', sa.Text(), nullable=False),
        sa.Column('blockers', sa.JSON(), nullable=True),
        sa.Column('rationale', sa.Text(), nullable=False),
        sa.Column('migration_phase', sa.String(length=64), nullable=False),
        sa.ForeignKeyConstraint(['artifact_id'], ['artifacts.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('artifact_id')
    )
    op.create_index(op.f('ix_migration_assessments_artifact_id'), 'migration_assessments', ['artifact_id'], unique=True)
    op.create_index(op.f('ix_migration_assessments_migration_status'), 'migration_assessments', ['migration_status'], unique=False)
    op.create_index(op.f('ix_migration_assessments_priority_code'), 'migration_assessments', ['priority_code'], unique=False)
    op.create_index(op.f('ix_migration_assessments_priority_score'), 'migration_assessments', ['priority_score'], unique=False)

    # 8. Dependency Nodes & Edges
    op.create_table(
        'dependency_nodes',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('scan_id', sa.String(length=36), nullable=False),
        sa.Column('node_id', sa.String(length=255), nullable=False),
        sa.Column('node_type', sa.String(length=64), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('metadata_json', sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_dependency_nodes_node_id'), 'dependency_nodes', ['node_id'], unique=False)
    op.create_index(op.f('ix_dependency_nodes_node_type'), 'dependency_nodes', ['node_type'], unique=False)
    op.create_index(op.f('ix_dependency_nodes_scan_id'), 'dependency_nodes', ['scan_id'], unique=False)

    op.create_table(
        'dependency_edges',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('scan_id', sa.String(length=36), nullable=False),
        sa.Column('source_id', sa.String(length=255), nullable=False),
        sa.Column('target_id', sa.String(length=255), nullable=False),
        sa.Column('edge_type', sa.String(length=64), nullable=False),
        sa.Column('metadata_json', sa.JSON(), nullable=True),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_dependency_edges_edge_type'), 'dependency_edges', ['edge_type'], unique=False)
    op.create_index(op.f('ix_dependency_edges_scan_id'), 'dependency_edges', ['scan_id'], unique=False)
    op.create_index(op.f('ix_dependency_edges_source_id'), 'dependency_edges', ['source_id'], unique=False)
    op.create_index(op.f('ix_dependency_edges_target_id'), 'dependency_edges', ['target_id'], unique=False)


def downgrade() -> None:
    op.drop_table('dependency_edges')
    op.drop_table('dependency_nodes')
    op.drop_table('migration_assessments')
    op.drop_table('pqc_readiness_assessments')
    op.drop_table('risk_assessments')
    op.drop_table('signatures')
    op.drop_table('artifacts')
    op.drop_table('certificates')
    op.drop_table('scans')
