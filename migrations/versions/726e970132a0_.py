"""empty message

Revision ID: 726e970132a0
Revises: 9d7f23f78ec7
Create Date: 2022-08-12 12:56:35.029053

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '726e970132a0'
down_revision = '9d7f23f78ec7'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index('ix_receipts_receipt_total_amount', table_name='receipts')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_index('ix_receipts_receipt_total_amount', 'receipts', ['receipt_total_amount'], unique=False)
    # ### end Alembic commands ###
