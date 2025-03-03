"""Initial migration

Revision ID: 996199462bb9
Revises: 
Create Date: 2025-02-12 17:40:56.900462

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '996199462bb9'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('config',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('key', sa.String(length=64), nullable=False),
    sa.Column('value', sa.String(length=64), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('key')
    )
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=80), nullable=False),
    sa.Column('email', sa.String(length=120), nullable=False),
    sa.Column('password_hash', sa.String(length=128), nullable=False),
    sa.Column('role', sa.String(length=20), nullable=False),
    sa.Column('my_price_per_ml', sa.Float(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email'),
    sa.UniqueConstraint('username')
    )
    op.create_table('project',
    sa.Column('id', sa.String(length=36), nullable=False),
    sa.Column('name', sa.String(length=256), nullable=False),
    sa.Column('user_id', sa.Integer(), nullable=True),
    sa.Column('main_file_name', sa.String(length=256), nullable=True),
    sa.Column('main_file_path', sa.String(length=512), nullable=True),
    sa.Column('volume_ml', sa.Float(), nullable=True),
    sa.Column('estimated_cost', sa.Float(), nullable=True),
    sa.Column('final_cost', sa.Float(), nullable=True),
    sa.Column('state', sa.String(length=50), nullable=True),
    sa.Column('quantity', sa.Integer(), nullable=False),
    sa.Column('order_comment', sa.Text(), nullable=True),
    sa.ForeignKeyConstraint(['user_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('project_file',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('project_id', sa.String(length=36), nullable=False),
    sa.Column('filename', sa.String(length=256), nullable=True),
    sa.Column('file_path', sa.String(length=512), nullable=True),
    sa.ForeignKeyConstraint(['project_id'], ['project.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('project_state_log',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('project_id', sa.String(length=36), nullable=False),
    sa.Column('old_state', sa.String(length=50), nullable=True),
    sa.Column('new_state', sa.String(length=50), nullable=True),
    sa.Column('changed_by', sa.String(length=80), nullable=True),
    sa.Column('timestamp', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['project_id'], ['project.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('project_state_log')
    op.drop_table('project_file')
    op.drop_table('project')
    op.drop_table('user')
    op.drop_table('config')
    # ### end Alembic commands ###
