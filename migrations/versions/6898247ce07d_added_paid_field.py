"""Added paid field

Revision ID: 6898247ce07d
Revises: 3753c9ed658c
Create Date: 2025-02-19 16:06:53.046025

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '6898247ce07d'
down_revision = '3753c9ed658c'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('project', schema=None) as batch_op:
        batch_op.add_column(sa.Column('paid', sa.Boolean(), nullable=True))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('project', schema=None) as batch_op:
        batch_op.drop_column('paid')

    # ### end Alembic commands ###
