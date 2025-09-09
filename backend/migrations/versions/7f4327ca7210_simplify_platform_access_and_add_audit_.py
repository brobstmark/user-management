"""Simplify platform access and add audit table

Revision ID: 7f4327ca7210
Revises: 79c351441509
Create Date: 2025-09-09 14:36:08.619495

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7f4327ca7210'
down_revision: Union[str, None] = '79c351441509'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Simplify UserPlatformAccess and create separate audit table"""

    # Step 1: Drop the problematic user_platform_access table
    op.execute('DROP TABLE IF EXISTS user_platform_access CASCADE')

    # Step 2: Create simplified user_platform_access table
    # Focus only on the core relationship - who has access to what
    op.create_table(
        'user_platform_access',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('platform_id', sa.Integer(), nullable=False),
        sa.Column('role', sa.String(20), nullable=False, default='user'),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'),
                  nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'),
                  nullable=False),

        # Primary key
        sa.PrimaryKeyConstraint('id'),

        # Foreign keys - ONLY TWO, no ambiguity
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], name='fk_user_platform_access_user_id', ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['platform_id'], ['platforms.id'], name='fk_user_platform_access_platform_id',
                                ondelete='CASCADE'),

        # Unique constraint - prevent duplicate access records
        sa.UniqueConstraint('user_id', 'platform_id', name='uq_user_platform_access'),
    )

    # Step 3: Create indexes for performance
    op.create_index('ix_user_platform_access_user_id', 'user_platform_access', ['user_id'])
    op.create_index('ix_user_platform_access_platform_id', 'user_platform_access', ['platform_id'])
    op.create_index('ix_user_platform_access_is_active', 'user_platform_access', ['is_active'])

    # Step 4: Create separate audit table for tracking changes
    op.create_table(
        'platform_access_audit',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('platform_id', sa.Integer(), nullable=False),
        sa.Column('action', sa.String(50), nullable=False),  # 'granted', 'revoked', 'role_changed'
        sa.Column('performed_by_user_id', sa.Integer(), nullable=False),
        sa.Column('old_value', sa.String(100), nullable=True),  # Previous state (JSON or simple value)
        sa.Column('new_value', sa.String(100), nullable=True),  # New state (JSON or simple value)
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'),
                  nullable=False),

        # Primary key
        sa.PrimaryKeyConstraint('id'),

        # Foreign keys
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], name='fk_platform_access_audit_user_id'),
        sa.ForeignKeyConstraint(['platform_id'], ['platforms.id'], name='fk_platform_access_audit_platform_id'),
        sa.ForeignKeyConstraint(['performed_by_user_id'], ['users.id'], name='fk_platform_access_audit_performed_by'),
    )

    # Step 5: Create indexes for audit table
    op.create_index('ix_platform_access_audit_user_id', 'platform_access_audit', ['user_id'])
    op.create_index('ix_platform_access_audit_platform_id', 'platform_access_audit', ['platform_id'])
    op.create_index('ix_platform_access_audit_action', 'platform_access_audit', ['action'])
    op.create_index('ix_platform_access_audit_created_at', 'platform_access_audit', ['created_at'])

    # Step 6: Create trigger to automatically update updated_at timestamp
    op.execute("""
        CREATE OR REPLACE FUNCTION update_user_platform_access_updated_at()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = CURRENT_TIMESTAMP;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)

    op.execute("""
        CREATE TRIGGER trigger_user_platform_access_updated_at
        BEFORE UPDATE ON user_platform_access
        FOR EACH ROW
        EXECUTE FUNCTION update_user_platform_access_updated_at();
    """)


def downgrade() -> None:
    """Revert to previous structure (WARNING: Will lose audit data)"""

    # Drop the new tables and triggers
    op.execute("DROP TRIGGER IF EXISTS trigger_user_platform_access_updated_at ON user_platform_access;")
    op.execute("DROP FUNCTION IF EXISTS update_user_platform_access_updated_at();")

    op.drop_table('platform_access_audit')
    op.drop_table('user_platform_access')

    # Recreate old structure (simplified - may not be exact)
    op.create_table(
        'user_platform_access',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('platform_id', sa.Integer(), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('role', sa.String(20), nullable=False, default='user'),
        sa.Column('granted_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'),
                  nullable=False),
        sa.Column('granted_by_user_id', sa.Integer(), nullable=True),
        sa.Column('revoked_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('revoked_by_user_id', sa.Integer(), nullable=True),

        sa.PrimaryKeyConstraint('id'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.ForeignKeyConstraint(['platform_id'], ['platforms.id']),
        sa.ForeignKeyConstraint(['granted_by_user_id'], ['users.id']),
        sa.ForeignKeyConstraint(['revoked_by_user_id'], ['users.id']),
        sa.UniqueConstraint('user_id', 'platform_id'),
    )