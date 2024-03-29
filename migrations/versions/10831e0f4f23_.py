"""empty message

Revision ID: 10831e0f4f23
Revises: cab47d7dbf7d
Create Date: 2022-08-24 12:30:04.749365

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '10831e0f4f23'
down_revision = 'cab47d7dbf7d'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('customers', sa.Column('cart_data', sa.JSON(), nullable=True))
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('customers', 'cart_data')
    # ### end Alembic commands ###
