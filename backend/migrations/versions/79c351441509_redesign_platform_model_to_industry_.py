"""Redesign platform model to industry standards

Revision ID: 79c351441509
Revises: 6cf1cf7d5244
Create Date: 2025-09-09 14:20:24.190012

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '79c351441509'
down_revision: Union[str, None] = '6cf1cf7d5244'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade to new platform model design"""

    # Step 1: Drop existing platform tables (if they exist)
    # This will also drop any foreign key constraints
    op.execute('DROP TABLE IF EXISTS user_platform_access CASCADE')
    op.execute('DROP TABLE IF EXISTS platforms CASCADE')

    # Step 2: Create new platforms table with industry standard design
    op.create_table(
        'platforms',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('slug', sa.String(50), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('domain', sa.String(255), nullable=False),
        sa.Column('return_url', sa.String(500), nullable=True),
        sa.Column('api_key_hash', sa.String(255), nullable=False),
        sa.Column('api_key_prefix', sa.String(10), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.Column('is_verified', sa.Boolean(), nullable=False, default=False),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'),
                  nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'),
                  nullable=False),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),

        # Primary key
        sa.PrimaryKeyConstraint('id'),

        # Foreign key to users table
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], name='fk_platforms_user_id'),

        # Unique constraints
        sa.UniqueConstraint('slug', name='uq_platforms_slug'),
        sa.UniqueConstraint('domain', name='uq_platforms_domain'),
        sa.UniqueConstraint('api_key_hash', name='uq_platforms_api_key_hash'),
        sa.UniqueConstraint('user_id', 'slug', name='uq_user_platform_slug'),
    )

    # Step 3: Create indexes for performance
    op.create_index('ix_platforms_user_id', 'platforms', ['user_id'])
    op.create_index('ix_platforms_slug', 'platforms', ['slug'])
    op.create_index('ix_platforms_domain', 'platforms', ['domain'])
    op.create_index('ix_platforms_api_key_hash', 'platforms', ['api_key_hash'])
    op.create_index('ix_platforms_is_active', 'platforms', ['is_active'])

    # Step 4: Create new user_platform_access table with enhanced features
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

        # Primary key
        sa.PrimaryKeyConstraint('id'),

        # Foreign keys
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], name='fk_user_platform_access_user_id'),
        sa.ForeignKeyConstraint(['platform_id'], ['platforms.id'], name='fk_user_platform_access_platform_id'),
        sa.ForeignKeyConstraint(['granted_by_user_id'], ['users.id'], name='fk_user_platform_access_granted_by'),
        sa.ForeignKeyConstraint(['revoked_by_user_id'], ['users.id'], name='fk_user_platform_access_revoked_by'),

        # Unique constraint to prevent duplicate access records
        sa.UniqueConstraint('user_id', 'platform_id', name='uq_user_platform_access'),
    )

    # Step 5: Create indexes for user_platform_access
    op.create_index('ix_user_platform_access_user_id', 'user_platform_access', ['user_id'])
    op.create_index('ix_user_platform_access_platform_id', 'user_platform_access', ['platform_id'])
    op.create_index('ix_user_platform_access_is_active', 'user_platform_access', ['is_active'])

    # Step 6: Create trigger to automatically update updated_at timestamp
    op.execute("""
        CREATE OR REPLACE FUNCTION update_platforms_updated_at()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = CURRENT_TIMESTAMP;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)

    op.execute("""
        CREATE TRIGGER trigger_platforms_updated_at
        BEFORE UPDATE ON platforms
        FOR EACH ROW
        EXECUTE FUNCTION update_platforms_updated_at();
    """)


def downgrade() -> None:
    """Downgrade to previous platform model (WARNING: Data loss)"""

    # Drop the new tables and triggers
    op.execute("DROP TRIGGER IF EXISTS trigger_platforms_updated_at ON platforms;")
    op.execute("DROP FUNCTION IF EXISTS update_platforms_updated_at();")

    # Drop new tables
    op.drop_table('user_platform_access')
    op.drop_table('platforms')

    # Recreate old platform structure (basic version)
    # Note: This is a simplified recreation - you may lose data
    op.create_table(
        'platforms',
        sa.Column('id', sa.String(50), nullable=False),
        sa.Column('name', sa.String(100), nullable=False),
        sa.Column('domain', sa.String(255), nullable=False),
        sa.Column('api_key', sa.String(255), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('api_key'),
    )

    # Recreate old user_platform_access
    op.create_table(
        'user_platform_access',
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('platform_id', sa.String(50), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False, default=True),
        sa.PrimaryKeyConstraint('user_id', 'platform_id'),
        sa.ForeignKeyConstraint(['user_id'], ['users.id']),
        sa.ForeignKeyConstraint(['platform_id'], ['platforms.id']),
    )