# Imports
from enum import unique
from app import db
from sqlalchemy import Boolean, Column, Integer, String, DateTime, Text ,JSON


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
    customer_contact_no=Column(String(255),unique=False)
    password = Column(String(255),unique=True,index=True)
    customer_address = Column(Text(2000),unique=False,index=False)
    customer_cards = Column(Text(2000),unique=False,index=False)
    customer_reset_pin = Column(String(255),unique=True,index=True)
    customer_push_notification_token = Column(String(255),unique=True,index=True)
    permitted = Column(Boolean,unique=False)
    permitted_by = Column(String(255),unique=False)
    cart_data= Column(JSON)
    wishlist_data=Column(JSON)
    # https://stackoverflow.com/questions/61370118/storing-arrays-in-database-using-sqlalchemy

    def __repr__(self):
        return f"<customer {self.customer_id}>"


class Orders(db.Model):
    __tablename__ = "orders"
    __table_args__ = {'extend_existing': True}

    id = Column(Integer, primary_key=True)
    order_id = Column(String(255),unique=True,index=True)
    receipt_id=Column(String(255),unique=False)
    order_owner_id = Column(String(255),unique=False)
    order_customer_id = Column(String(255),unique=False)
    order_product_id = Column(String(255),unique=False)
    item_unique_id = Column(String(255),unique=True,index=True)
    order_product_quantity = Column(String(255),unique=False)
    order_total_amount = Column(String(255),unique=False)
    order_date = Column(DateTime,unique=False)
    order_address = Column(String(255),unique=False)
    order_name = Column(String(255),unique=False)
    order_contact_no = Column(String(255),unique=False)
    order_status=Column(String(255),unique=False)
    order_tracking_id= Column(String(255),unique=False)
    order_delivery_partner=Column(String(255),unique=False)

    def __repr__(self):
        return f"<order {self.order_id}>"

class Receipts(db.Model):
    __tablename__ = "receipts"

    id = Column(Integer, primary_key=True)
    receipt_id = Column(String(255),unique=True,index=True)
    customer_id= Column(String(255),unique=False)
    receipt_total_amount = Column(String(255),unique=False)
    receipt_date= Column(DateTime,unique=False)
    # razorp_order_id=Column(String(255),unique=True)
    # razorpay_payment_id=Column(String(255),unique=True)
    # razorpay_payment_signature=Column(String(255),unique=True)
    instamojo_payment_id=Column(String(255),unique=True)
    instamojo_payment_request_id=Column(String(255),unique=True)
    is_payment_completed=Column(Boolean,unique=False)

    def __repr__(self):
        return f"<receipts {self.receipt_id}>"

class Messages(db.Model):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True)
    name= Column(String(255),unique=False)
    email=Column(String(255),unique=False,index=True)
    subject= Column(String(255),unique=False,index=True)
    message = Column(String(255),unique=False,index=True)
    date= Column(DateTime,unique=False)



class Apikeys(db.Model):
    __tablename__ = "apikeys"

    id = Column(Integer, primary_key=True)
    apikey_vendor = Column(String(255),unique=True,index=True)
    apikey = Column(String(255),unique=True,index=True)

    def __repr__(self):
        return f"<apikey {self.apikey_vendor}>"