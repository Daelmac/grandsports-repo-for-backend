"""empty message

Revision ID: 68ee8ffa2a5a
Revises: a4539f098ed6
Create Date: 2022-08-30 11:19:07.193421

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '68ee8ffa2a5a'
down_revision = 'a4539f098ed6'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('messages',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=True),
    sa.Column('email', sa.String(length=255), nullable=True),
    sa.Column('subject', sa.String(length=255), nullable=True),
    sa.Column('message', sa.String(length=255), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_messages_email'), 'messages', ['email'], unique=False)
    op.create_index(op.f('ix_messages_message'), 'messages', ['message'], unique=False)
    op.create_index(op.f('ix_messages_subject'), 'messages', ['subject'], unique=False)
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_index(op.f('ix_messages_subject'), table_name='messages')
    op.drop_index(op.f('ix_messages_message'), table_name='messages')
    op.drop_index(op.f('ix_messages_email'), table_name='messages')
    op.drop_table('messages')
    # ### end Alembic commands ###
