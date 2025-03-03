"""Add Client and Buisness Compate do Project Model

Revision ID: 878dcf9b9e35
Revises: 1a9c38ed2c9c
Create Date: 2025-02-13 16:28:52.239934

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '878dcf9b9e35'
down_revision = '1a9c38ed2c9c'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('project', schema=None) as batch_op:
        batch_op.add_column(sa.Column('client_complete', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('business_complete', sa.Boolean(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('project', schema=None) as batch_op:
        batch_op.drop_column('business_complete')
        batch_op.drop_column('client_complete')

    # ### end Alembic commands ###
