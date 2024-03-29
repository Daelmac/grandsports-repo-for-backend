"""empty message

Revision ID: f74fc82decb5
Revises: 565f53351eec
Create Date: 2022-04-22 11:43:47.940709

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'f74fc82decb5'
down_revision = '565f53351eec'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('vendors', sa.Column('permitted', sa.Boolean(), nullable=True))
    op.add_column('vendors', sa.Column('permitted_by', sa.String(length=255), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('vendors', 'permitted_by')
    op.drop_column('vendors', 'permitted')
    # ### end Alembic commands ###
