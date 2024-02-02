"""Delete user col: email,otp_secret,confirmed

Revision ID: c0b806d863ed
Revises: b24bf17725d2
Create Date: 2023-12-27 13:01:38.376579

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'c0b806d863ed'
down_revision = 'b24bf17725d2'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    # op.drop_table('sessions')
    with op.batch_alter_table('domain', schema=None) as batch_op:
        batch_op.drop_column('dnssec')

    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('confirmed')
        batch_op.drop_column('otp_secret')
        # batch_op.drop_column('email')

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('user', schema=None) as batch_op:
        # batch_op.add_column(sa.Column('email', sa.VARCHAR(length=128), nullable=True))
        batch_op.add_column(sa.Column('otp_secret', sa.VARCHAR(length=16), nullable=True))
        batch_op.add_column(sa.Column('confirmed', sa.BOOLEAN(), nullable=True))

    with op.batch_alter_table('domain', schema=None) as batch_op:
        batch_op.add_column(sa.Column('dnssec', sa.INTEGER(), nullable=True))

    # op.create_table('sessions',
    #     sa.Column('id', sa.INTEGER(), nullable=False),
    #     sa.Column('session_id', sa.VARCHAR(length=255), nullable=True),
    #     sa.Column('data', sa.BLOB(), nullable=True),
    #     sa.Column('expiry', sa.DATETIME(), nullable=True),
    #     sa.PrimaryKeyConstraint('id'),
    #     sa.UniqueConstraint('session_id')
    # )
    # ### end Alembic commands ###
