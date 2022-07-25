# Imports
from enum import unique
from app import db
from sqlalchemy import Boolean, Column, Integer, String, DateTime, Text


class Admin(db.Model):
    __tablename__ = "admin"

    id = Column(Integer, primary_key=True)
    admin_id = Column(String(255),unique=True,index=True)
    admin_name = Column(String(255),unique=False,index=True)
    admin_email = Column(String(255),unique=True,index=True)
    password = Column(String(255),unique=True,index=True)
    admin_reset_pin = Column(String(255),unique=True,index=True)
    admin_push_notification_token = Column(String(255),unique=True,index=True)

    def __repr__(self):
        return f"<admin {self.user_token}>"

class Product(db.Model):
    __tablename__ = "products"

    id = Column(Integer, primary_key=True)
    product_id = Column(String(255),unique=True,index=True)
    product_name = Column(String(255),unique=False,index=True)
    product_description = Column(String(255),unique=False,index=True)
    product_price = Column(String(255),unique=False,index=True)
    product_image_name = Column(String(255),unique=True,index=True)
    product_image_filepath = Column(String(255),unique=True,index=True)
    product_discount = Column(Integer,unique=False,index=True)
    product_owner = Column(String(255),unique=False)
    product_is_available = Column(Boolean,unique=False)
    product_is_featured = Column(Boolean,unique=False)
    product_category = Column(String(255),unique=False)
    product_is_new = Column(Boolean,unique=False)
    product_is_best_seller = Column(Boolean,unique=False)

    def __repr__(self):
        return f"<product {self.product_id}>"


class Vendor(db.Model):
    __tablename__ = "vendors"

    id = Column(Integer, primary_key=True)
    vendor_id = Column(String(255),unique=True,index=True)
    vendor_name = Column(String(255),unique=False,index=True)
    vendor_email = Column(String(255),unique=True,index=True)
    password = Column(String(255),unique=True,index=True)
    vendor_reset_pin = Column(String(255),unique=True,index=True)
    permitted = Column(Boolean,unique=False)
    permitted_by = Column(String(255),unique=False)
    vendor_push_notification_token = Column(String(255),unique=True,index=True)

    def __repr__(self):
        return f"<vendor {self.vendor_id}>"


class Customer(db.Model):
    __tablename__ = "customers"

    id = Column(Integer, primary_key=True)
    customer_id = Column(String(255),unique=True,index=True)
    customer_name = Column(String(255),unique=False,index=True)
    customer_email = Column(String(255),unique=True,index=True)
    password = Column(String(255),unique=True,index=True)
    customer_address = Column(Text(2000),unique=False,index=False)
    customer_cards = Column(Text(2000),unique=False,index=False)
    customer_reset_pin = Column(String(255),unique=True,index=True)
    customer_push_notification_token = Column(String(255),unique=True,index=True)
    permitted = Column(Boolean,unique=False)
    permitted_by = Column(String(255),unique=False)

    def __repr__(self):
        return f"<customer {self.customer_id}>"


class Orders(db.Model):
    __tablename__ = "orders"

    id = Column(Integer, primary_key=True)
    order_id = Column(String(255),unique=True,index=True)
    order_vendor_id = Column(String(255),unique=False)
    order_customer_id = Column(String(255),unique=False)
    order_product_id = Column(String(255),unique=False)
    item_unique_id = Column(String(255),unique=True,index=True)
    order_product_name = Column(String(255),unique=False)
    order_product_price = Column(String(255),unique=False)
    order_product_discount = Column(String(255),unique=False)
    order_product_quantity = Column(String(255),unique=False)
    order_total_price = Column(String(255),unique=False)
    order_product_image = Column(String(255),unique=False)
    order_product_description = Column(String(255),unique=False)
    order_product_is_available = Column(Boolean,unique=False)
    order_date = Column(DateTime,unique=False)
    order_address = Column(String(255),unique=False)
    order_contact_no = Column(String(255),unique=False)

    def __repr__(self):
        return f"<order {self.order_id}>"


class Apikeys(db.Model):
    __tablename__ = "apikeys"

    id = Column(Integer, primary_key=True)
    apikey_vendor = Column(String(255),unique=True,index=True)
    apikey = Column(String(255),unique=True,index=True)

    def __repr__(self):
        return f"<apikey {self.apikey_vendor}>"