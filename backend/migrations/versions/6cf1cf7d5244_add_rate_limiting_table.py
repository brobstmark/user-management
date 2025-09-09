"""Add rate limiting table

Revision ID: 6cf1cf7d5244
Revises: 2b7f42778f26
Create Date: 2025-09-09 12:29:41.154087

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '6cf1cf7d5244'
down_revision: Union[str, None] = '2b7f42778f26'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add rate limiting table"""
    op.create_table(
        'rate_limits',
        sa.Column('ip_address', sa.String(45), nullable=False, comment='IPv4 or IPv6 address'),
        sa.Column('endpoint', sa.String(100), nullable=False, comment='API endpoint being rate limited'),
        sa.Column('count', sa.Integer, nullable=False, default=0, comment='Number of requests made'),
        sa.Column('first_request_at', sa.DateTime(timezone=True), nullable=False,
                  comment='Timestamp of first request in current window'),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=False,
                  comment='When this rate limit window expires'),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'),
                  nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('CURRENT_TIMESTAMP'),
                  nullable=False),

        # Primary key on IP + endpoint combination
        sa.PrimaryKeyConstraint('ip_address', 'endpoint'),

        # Index for cleanup queries
        sa.Index('idx_rate_limits_expires_at', 'expires_at'),
        sa.Index('idx_rate_limits_created_at', 'created_at'),
    )

    # Add trigger to update updated_at timestamp
    op.execute("""
        CREATE OR REPLACE FUNCTION update_rate_limits_updated_at()
        RETURNS TRIGGER AS $$
        BEGIN
            NEW.updated_at = CURRENT_TIMESTAMP;
            RETURN NEW;
        END;
        $$ LANGUAGE plpgsql;
    """)

    op.execute("""
        CREATE TRIGGER trigger_rate_limits_updated_at
        BEFORE UPDATE ON rate_limits
        FOR EACH ROW
        EXECUTE FUNCTION update_rate_limits_updated_at();
    """)


def downgrade() -> None:
    """Remove rate limiting table"""
    op.execute("DROP TRIGGER IF EXISTS trigger_rate_limits_updated_at ON rate_limits;")
    op.execute("DROP FUNCTION IF EXISTS update_rate_limits_updated_at();")
    op.drop_table('rate_limits')