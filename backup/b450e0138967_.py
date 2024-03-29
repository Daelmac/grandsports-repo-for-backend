"""empty message

Revision ID: b450e0138967
Revises: 480c750ccded
Create Date: 2022-04-26 20:05:53.928646

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b450e0138967'
down_revision = '480c750ccded'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('admin', sa.Column('admin_reset_pin', sa.String(length=255), nullable=True))
    op.create_index(op.f('ix_admin_admin_reset_pin'), 'admin', ['admin_reset_pin'], unique=True)
    op.add_column('customers', sa.Column('customer_reset_pin', sa.String(length=255), nullable=True))
    op.create_index(op.f('ix_customers_customer_reset_pin'), 'customers', ['customer_reset_pin'], unique=True)
    op.add_column('vendors', sa.Column('vendor_reset_pin', sa.String(length=255), nullable=True))
    op.create_index(op.f('ix_vendors_vendor_reset_pin'), 'vendors', ['vendor_reset_pin'], unique=True)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_vendors_vendor_reset_pin'), table_name='vendors')
    op.drop_column('vendors', 'vendor_reset_pin')
    op.drop_index(op.f('ix_customers_customer_reset_pin'), table_name='customers')
    op.drop_column('customers', 'customer_reset_pin')
    op.drop_index(op.f('ix_admin_admin_reset_pin'), table_name='admin')
    op.drop_column('admin', 'admin_reset_pin')
    # ### end Alembic commands ###
