from alembic import op
import sqlalchemy as sa


revision = 'initial'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'secrets',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('encrypted_data', sa.Text(), nullable=False),
        sa.Column('iv', sa.String(), nullable=False),
        sa.Column('passphrase_hash', sa.String(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('expires_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('is_accessed', sa.Boolean(), default=False, nullable=True),
        sa.Column('is_deleted', sa.Boolean(), default=False, nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_secrets_id'), 'secrets', ['id'], unique=False)

    op.create_table(
        'secret_logs',
        sa.Column('id', sa.Integer(), autoincrement=True, nullable=False),
        sa.Column('secret_id', sa.String(), nullable=True),
        sa.Column('action', sa.String(), nullable=False),
        sa.Column('ip_address', sa.String(), nullable=True),
        sa.Column('user_agent', sa.String(), nullable=True),
        sa.Column('timestamp', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=True),
        sa.Column('additional_info', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_secret_logs_secret_id'), 'secret_logs', ['secret_id'], unique=False)


def downgrade():
    op.drop_index(op.f('ix_secret_logs_secret_id'), table_name='secret_logs')
    op.drop_table('secret_logs')
    op.drop_index(op.f('ix_secrets_id'), table_name='secrets')
    op.drop_table('secrets')
