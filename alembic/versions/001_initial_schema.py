"""Initial schema: users and blacklisted_tokens

Revision ID: 001
Revises:
Create Date: 2026-02-16
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = '001'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Users table
    op.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email VARCHAR NOT NULL,
            username VARCHAR NOT NULL,
            hashed_password VARCHAR NOT NULL,
            is_active BOOLEAN DEFAULT 1,
            email_verified BOOLEAN DEFAULT 0,
            verification_code VARCHAR,
            verification_code_expires DATETIME,
            verification_attempts INTEGER DEFAULT 0,
            failed_login_attempts INTEGER DEFAULT 0,
            locked_until DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Create indexes if they don't exist (SQLite-compatible)
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS ix_users_email ON users (email)")
    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS ix_users_username ON users (username)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_users_id ON users (id)")

    # Blacklisted tokens table
    op.execute("""
        CREATE TABLE IF NOT EXISTS blacklisted_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            jti VARCHAR NOT NULL,
            expires_at DATETIME NOT NULL,
            blacklisted_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    op.execute("CREATE UNIQUE INDEX IF NOT EXISTS ix_blacklisted_tokens_jti ON blacklisted_tokens (jti)")
    op.execute("CREATE INDEX IF NOT EXISTS ix_blacklisted_tokens_id ON blacklisted_tokens (id)")


def downgrade() -> None:
    op.drop_table('blacklisted_tokens')
    op.drop_table('users')
