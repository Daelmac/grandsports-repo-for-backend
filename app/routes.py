# importing libraries
import os

from io import BytesIO
from PIL import Image
from app.db_model import db
from datetime import datetime
from dotenv import load_dotenv
from app.server_utils import *
from flask import Flask,request,jsonify,current_app

# Set Up Logging For Automation
import logging

# Init App
app = current_app

# ------- Configuring Logging File -------- #

# Logger For Log File
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Log File Logging Format
formatter = logging.Formatter("%(asctime)s:%(levelname)s::%(message)s")

# Log File Handler
Log_File_Handler = logging.FileHandler("doxael.log")
Log_File_Handler.setLevel(logging.DEBUG)
Log_File_Handler.setFormatter(formatter)

# Stream Handlers
Stream_Handler = logging.StreamHandler()

# Adding The Handlers
logger.addHandler(Log_File_Handler)
logger.addHandler(Stream_Handler)

# Log On START 
logger.debug("")
logger.debug("="*100)
logger.info("App Backend :: Logging Active")
logger.debug("")

# Load env File
load_dotenv(".env")

# Test Route
@app.route("/test")
def test():
    return jsonify({"message": f"Api for {os.environ.get('PROJECT_NAME').upper()} is Alive", "status": "success"})


# Admin Routes
@app.route(f"/create_admin", methods=["POST"],endpoint="create_admin")
@token_required(['admin'])
def create_admin():

    # Get Form Data
    email = request.form["email"]
    password = request.form["password"]
    username = request.form["username"]

    # Create Admin Account
    Create_Response = Create_Account("admin",email=email,password=password,username=username)
    return Create_Response


@app.route(f"/admin_login",methods=["POST"],endpoint="admin_login")
def admin_login():

    # Handle Request
    email = request.form["email"]
    password = request.form["password"]

    # Account Login
    login_response = Account_Login("admin",email,password)

    # Request Response
    return(login_response)


@app.route(f"/all_vendors",methods=["POST"], endpoint='all_vendors')
@token_required(['admin'])
def all_vendors():

    # Handle Request Filter
    admin_id = request.form["admin_id"]
    filter = request.form["filter"]

    # Fetch Vendor
    fetch_vendor_response = Fetch_Vendors(admin_id,filter)
    return fetch_vendor_response


@app.route(f"/admin_enable_vendor",methods=["POST"],endpoint='enable_vendor')
@token_required(['admin'])
def enable_vendor():
    
    # Get Form Data
    admin_id = request.form["admin_id"]
    vendor_id = request.form["vendor_id"]

    # Enable Vendor
    Enable_Vendor_Response = Toggle_Enable_Vendor("activate",admin_id,vendor_id)
    return Enable_Vendor_Response


@app.route(f"/admin_disable_vendor",methods=["POST"],endpoint='disable_vendor')
@token_required(['admin'])
def disable_vendor():
    
    # Get Form Data
    admin_id = request.form["admin_id"]
    vendor_id = request.form["vendor_id"]

    # Enable Vendor
    Enable_Vendor_Response = Toggle_Enable_Vendor("deactivate",admin_id,vendor_id)
    return Enable_Vendor_Response


@app.route(f"/all_admin_products",methods=["POST"],endpoint="all_admin_products")
@token_required(['admin'])
def all_admin_products():

    # Get Vendor ID
    admin_id = request.form["admin_id"]

    # Get All Products
    all_products = Get_All_Products("admin",admin_id)
    return all_products


@app.route(f"/admin_remove_product",methods=["POST"],endpoint="admin_remove_product")
@token_required(['admin'])
def admin_remove_product():
    
    # Get Form Data
    admin_id = request.form["admin_id"]
    product_id = request.form["product_id"]

    # Remove Product
    Remove_Product_Response = Remove_Product("admin",admin_id,product_id)
    return Remove_Product_Response


@app.route(f"/admin_edit_product",methods=["POST"],endpoint="admin_edit_product")
@token_required(['admin'])
def admin_edit_product():

    # Get Form Data
    owner_id = request.form["admin_id"]
    product_id = request.form["product_id"]

    product_name = request.form["product_name"] if "product_name" in request.form else None
    product_description = request.form["product_description"] if "product_description" in request.form else None
    product_price = request.form["product_price"] if "product_price" in request.form else None
    product_image = request.files["product_image"] if "product_image" in request.files else None
    product_discount = request.form["product_discount"] if "product_discount" in request.form else None
    product_is_available = request.form["product_is_available"] if "product_is_available" in request.form else None
    product_category=request.form["product_category"] if "product_category" in request.form else None
    # Edit Product
    if product_is_available:
        product_is_available= True if product_is_available == 'true' else False
    Edit_Product_Response = Edit_Product("vendor",account_id=owner_id,product_id=product_id,product_name=product_name,product_description=product_description,product_price=product_price,product_image=product_image,product_discount=product_discount,product_is_available=product_is_available,product_category=product_category)
    return Edit_Product_Response


@app.route(f"/admin_make_featured_product",methods=["POST"],endpoint="make_featured_product")
@token_required(['admin'])
def make_featured_product():

    # Get Form Data
    admin_id = request.form["admin_id"]
    product_id = request.form["product_id"]

    # Make Featured Product
    Make_Featured_Product_Response = Make_Featured_Product(admin_id,product_id)
    return Make_Featured_Product_Response

@app.route(f"/admin_make_new_product",methods=["POST"],endpoint="make_new_product" )
@token_required(['admin'])
def make_new_product():

    # Get Form Data
    admin_id = request.form["admin_id"]
    product_id = request.form["product_id"]

    # Make New Product
    Make_New_Product_Response = Make_New_Product(admin_id,product_id)
    return Make_New_Product_Response

@app.route(f"/admin_make_bestseller_product",methods=["POST"],endpoint="make_bestseller_product")
@token_required(['admin'])
def make_bestseller_product():

    # Get Form Data
    admin_id = request.form["admin_id"]
    product_id = request.form["product_id"]

    # Make Bestseller Product
    Make_Bestseller_Product_Response = Make_Bestseller_Product(admin_id,product_id)
    return Make_Bestseller_Product_Response


@app.route(f"/admin_remove_featured_product",methods=["POST"],endpoint="remove_featured_product")
@token_required(['admin'])
def remove_featured_product():
 
    # Get Form Data
    admin_id = request.form["admin_id"]
    product_id = request.form["product_id"]

    # Remove Featured Product
    Remove_Featured_Product_Response = Make_Non_Featured_Product(admin_id,product_id)
    return Remove_Featured_Product_Response

@app.route(f"/admin_remove_new_product",methods=["POST"],endpoint="remove_new_product")
@token_required(['admin'])
def remove_new_product():
 
    # Get Form Data
    admin_id = request.form["admin_id"]
    product_id = request.form["product_id"]

    # Remove Featured Product
    Remove_new_Product_Response = Make_Non_new_Product(admin_id,product_id)
    return Remove_new_Product_Response

@app.route(f"/admin_remove_bestseller_product",methods=["POST"],endpoint="remove_bestseller_product")
@token_required(['admin'])
def remove_bestseller_product():
 
    # Get Form Data
    admin_id = request.form["admin_id"]
    product_id = request.form["product_id"]

    # Remove Featured Product
    Remove_bestseller_Product_Response = Make_Non_bestseller_Product(admin_id,product_id)
    return Remove_bestseller_Product_Response


@app.route(f"/admin_enable_customer",methods=["POST"],endpoint="enable_customer")
@token_required(['admin'])
def enable_customer():
        
    # Get Form Data
    admin_id = request.form["admin_id"]
    customer_id = request.form["customer_id"]

    # Enable Customer
    Enable_Customer_Response = Toggle_Enable_Customer("activate",admin_id,customer_id)
    return Enable_Customer_Response


@app.route(f"/admin_disable_customer",methods=["POST"],endpoint="disable_customer")
@token_required(['admin'])
def disable_customer():
        
    # Get Form Data
    admin_id = request.form["admin_id"]
    customer_id = request.form["customer_id"]

    # Enable Customer
    Enable_Customer_Response = Toggle_Enable_Customer("deactivate",admin_id,customer_id)
    return Enable_Customer_Response


@app.route(f"/all_customers",methods=["POST"],endpoint="all_customers")
@token_required(['admin'])
def all_customers():
    
    # Get Form Data
    
    filter = request.form["filter"]
    admin_id = request.form["admin_id"]

    # Get All Customers
    All_Customers_Response = Get_All_Customers(admin_id,filter)
    return All_Customers_Response

@app.route(f"/all_admins",methods=["GET"],endpoint="all_admins")
@token_required(['admin'])
def all_admins():
    
    # Get Form Data

    # Get All Customers
    All_Admins_Response = Get_All_Admins()
    return All_Admins_Response


@app.route(f"/admin_reset_password",methods=["POST"],endpoint="admin_reset_password")
def admin_reset_password():

    # Get Form Data
    email = request.form["email"]

    # Reset Password
    Reset_Password_Response = Reset_Password("admin",email)
    return Reset_Password_Response


@app.route(f"/admin_update_password",methods=["POST"],endpoint="admin_update_password")
def admin_update_password():

    # Get Form Data
    session_token = request.form["reset_token"]
    pin = request.form["reset_pin"]
    password = request.form["password"]
    confirmPassword = request.form["confirmPassword"]

    # Update Password
    Update_Password_Response = Update_Password("admin",session_token,pin,password,confirmPassword)
    return Update_Password_Response


# Vendor Routes
@app.route(f"/create_vendor", methods=["POST"],endpoint="create_vendor")
def create_vendor():

    # Get Form Data
    email = request.form["email"]
    password = request.form["password"]
    username = request.form["username"]

    # Create Admin Account
    Create_Response = Create_Account("vendor",email=email,password=password,username=username)
    return Create_Response


@app.route(f"/vendor_login",methods=["POST"],endpoint="vendor_login")
def vendor_login():

    # Handle Request
    email = request.form["email"]
    password = request.form["password"]

    # Account Login
    login_response = Account_Login("vendor",email,password)

    # Request Response
    return(login_response)


@app.route(f"/vendor_reset_password",methods=["POST"],endpoint="vendor_reset_password")
def vendor_reset_password():

    # Get Form Data
    email = request.form["email"]

    # Reset Password
    Reset_Password_Response = Reset_Password("vendor",email)
    return Reset_Password_Response


@app.route(f"/vendor_update_password",methods=["POST"],endpoint="vendor_update_password")
def vendor_update_password():

    # Get Form Data
    session_token = request.form["reset_token"]
    pin = request.form["reset_pin"]
    password = request.form["password"]
    confirmPassword = request.form["confirmPassword"]

    # Update Password
    Update_Password_Response = Update_Password("vendor",session_token,pin,password,confirmPassword)
    return Update_Password_Response


@app.route(f"/all_vendor_products",methods=["POST"],endpoint="all_vendor_products")
@token_required(['vendor'])
def all_vendor_products():

    # Get Vendor ID
    vendor_id = request.form["vendor_id"]

    # Get All Products
    all_products = Get_All_Products("vendor",vendor_id)
    return all_products


@app.route(f"/vendor_edit_product",methods=["POST"],endpoint="vendor_edit_product")
@token_required(['vendor'])
def vendor_edit_product():
    
    # Get Form Data
    owner_id = request.form["vendor_id"]
    product_id = request.form["product_id"]

    product_name = request.form["product_name"] if "product_name" in request.form else None
    product_description = request.form["product_description"] if "product_description" in request.form else None
    product_price = request.form["product_price"] if "product_price" in request.form else None
    product_image = request.files["product_image"] if "product_image" in request.files else None
    product_discount = request.form["product_discount"] if "product_discount" in request.form else None
    product_is_available = request.form["product_is_available"] if "product_is_available" in request.form else None
    product_category=request.form["product_category"] if "product_category" in request.form else None
    # Edit Product
    Edit_Product_Response = Edit_Product("vendor",account_id=owner_id,product_id=product_id,product_name=product_name,product_description=product_description,product_price=product_price,product_image=product_image,product_discount=product_discount,product_is_available=product_is_available,product_category=product_category)
    return Edit_Product_Response


@app.route(f"/vendor_remove_product",methods=["POST"],endpoint="vendor_remove_product")
@token_required(['vendor'])
def vendor_remove_product():
    
    # Get Form Data
    vendor_id = request.form["vendor_id"]
    product_id = request.form["product_id"]

    # Remove Product
    Remove_Product_Response = Remove_Product("vendor",vendor_id,product_id)
    return Remove_Product_Response


# Customer Routes
@app.route(f"/create_customer", methods=["POST"],endpoint="create_customer")
def create_customer():

    # Get Form Data
    email = request.form["email"]
    password = request.form["password"]
    username = request.form["username"]

    # Create Admin Account
    Create_Response = Create_Account("customer",email=email,password=password,username=username)
    return Create_Response


@app.route(f"/customer_login",methods=["POST"],endpoint="customer_login")
def customer_login():

    # Handle Request
    email = request.form["email"]
    password = request.form["password"]

    # Account Login
    login_response = Account_Login("customer",email,password)

    # Request Response
    return(login_response)


@app.route(f"/customer_reset_password",methods=["POST"],endpoint="customer_reset_password")
def customer_reset_password():

    # Get Form Data
    email = request.form["email"]

    # Reset Password
    Reset_Password_Response = Reset_Password("customer",email)
    return Reset_Password_Response


@app.route(f"/customer_update_password",methods=["POST"] ,endpoint="customer_update_password")
def customer_update_password():

    # Get Form Data
    session_token = request.form["reset_token"]
    pin = request.form["reset_pin"]
    password = request.form["password"]
    confirmPassword = request.form["confirmPassword"]

    # Update Password
    Update_Password_Response = Update_Password("customer",session_token,pin,password,confirmPassword)
    return Update_Password_Response


@app.route(f"/show_customer_purchases",methods=["POST"],endpoint="show_customer_purchases")
@token_required(['customer'])
def show_customer_purchases():
    
        # Get Customer ID
        customer_id = request.form["customer_id"]
        filter_type = request.form["filter_type"] if "filter_type" in request.form else None
        filter_value = request.form["filter_value"] if "filter_value" in request.form else None
    
        # Get All Purchases
        all_purchases = Show_Purchases(customer_id,filter_type,filter_value)
        return all_purchases
@app.route(f"/set_default_billing_address",methods=["POST"],endpoint="set_default_billing_address")
@token_required(['customer'])
def set_default_billing_address():
    
        # Get Customer ID
        customer_id = request.form["customer_id"]
        address = request.form["address"]
    
        # Get All Purchases
        address_update_response = update_customer_address(customer_id,address)
        return address_update_response


@app.route(f"/add_customer_purchases",methods=["POST"],endpoint="add_purchases")
@token_required(['customer'])
def add_purchases():

    try:
        # Get Form Data
        # order_id = request.json["order_id"]
        import uuid
        # order_id = str(uuid.uuid4())
        print(request.json)
        customer_id = request.json["customer_id"]
        total_receipt_amount = request.json["total_receipt_amount"]
        contact_no = request.json["contact_no"]
        address = request.json["address"]   
        purchase_data = request.json["purchases"]
        order_name = request.json["name"]
        instamojo_payment_request_id = request.json['instamojo_payment_request_id']
        # razorpay_order_id=request.json['razorpay_order_id']
        # razorpay_payment_id=request.json['razorpay_payment_id']
        # razorpay_payment_signature=request.json['razorpay_payment_signature']
        # Add Purchase
        Add_Purchase_Response = Add_Purchase(customer_id,total_receipt_amount,contact_no,order_name,address,purchase_data,instamojo_payment_request_id)
        return Add_Purchase_Response

    except Exception as e:
        print(e)
        return jsonify({"error":str(e)})


# Multi Category Routes
@app.route(f"/add_product",methods=["POST"],endpoint="add_product")
@token_required(['admin','vendor'])
def add_product():
    # Get Form Data
    owner_id = request.form["owner_id"]
    product_name = request.form["product_name"]
    product_description = request.form["product_description"]
    product_price = request.form["product_price"]
    product_image_name = request.files["product_image"].filename
    product_image = request.files["product_image"]
    product_discount = request.form["product_discount"]
    product_category = request.form["product_category"]

    # Add Product
    newProduct = Add_Product(owner_id,product_name,product_description,product_price,product_image,product_image_name,product_discount,product_category)
    return newProduct


@app.route(f"/single_product",methods=["POST"],endpoint="single_product")
def single_product():

    # Get Product ID
    product_id = request.form["product_id"]

    # Get Product
    product_data = Get_Single_Product(product_id)
    return product_data


@app.route(f"/all_products",methods=["GET"],endpoint="")
def all_products():

    # Get All Products
    all_products = Get_All_Products()
    return all_products


@app.route(f"/single_vendor",methods=["POST"],endpoint="fetch_vendor_details")
@token_required(['admin'])
def fetch_vendor_details():

    # Handle Request
    vendor_id = request.form["vendor_id"]

    # Fetch Vendor Details
    fetch_vendor_details_response = Single_Vendor(vendor_id)
    return fetch_vendor_details_response


@app.route(f"/featured_products",methods=["GET"],endpoint="feature_products")
def feature_products():
    
    # Get Featured Products
    featured_products = Get_Featured_Products()
    return featured_products

@app.route(f"/new_products",methods=["GET"],endpoint="new_products")
def new_products():
    
    # Get new Products
    new_products = Get_New_Products()
    return new_products

@app.route(f"/best_seller_products",methods=["GET"],endpoint="best_seller_products")
def best_seller_products():
    
    # Get best_seller Products
    best_seller_products = Get_Best_Seller_Products()
    return best_seller_products

@app.route(f"/category_sort_products",methods=["POST"],endpoint="category_sort_products")
def category_sort_products():
    try:
        category = request.form["category"]
    except KeyError:
        return{"status_message":"Please enter category","status":"failed","status_code":400}

    # Get category_sort Products
    category_sort_products = Get_category_sort_Products(category)
    return category_sort_products
@app.route(f"/fetch_product",methods=["POST"],endpoint="fetch_product")
def fetch_product():
    try:
        pid = request.form["product_id"]
    except KeyError:
        return{"status_message":"Please enter product_id","status":"failed","status_code":400}

    # Get category_sort Products
    product = Get_Products(product_id=pid)
    return product

@app.route(f"/show_all_customer_purchases",methods=["POST"],endpoint="show_all_customer_purchases")
@token_required(['admin'])
def show_all_customer_purchases():
    
        # Get Customer ID
        filter_type = request.form["filter_type"] if "filter_type" in request.form else None
    
        # Get All Purchases
        all_purchases = Show_all_Purchases(filter_type)
        return all_purchases 

@app.route(f"/get_order_details",methods=["POST"],endpoint="get_order_details")
@token_required(['admin'])
def get_order_details():
    
        # Get Customer ID
        order_id = request.form["order_id"] 
       
        # Get All Purchases
        purchase_details = Show_Purchases_by_id(order_id)
        return purchase_details 

@app.route(f"/edit_order_details",methods=["POST"],endpoint="edit_order_details")
@token_required(['admin'])
def edit_order_details():
    
        # Getorder ID
        order_id = request.form["order_id"] 
        order_status = request.form["order_status"] if "order_status" in request.form else None
        order_tracking_id = request.form["order_tracking_id"] if "order_tracking_id" in request.form else None
        order_delivery_partner = request.form["order_delivery_partner"] if "order_delivery_partner" in request.form else None
        # Get All Purchases
        order_edit_status = Edit_Order(order_id,order_status,order_tracking_id,order_delivery_partner)
        return order_edit_status 

@app.route(f"/show_all_receipts",methods=["GET"],endpoint="show_all_receipts")
@token_required(['admin'])
def show_all_receipts():
    
    # Get Form Data

    # Get All Customers
    All_Receipts = Show_all_Receipts()
    return All_Receipts

@app.route(f"/get_dashboard_data",methods=["GET"],endpoint="get_dashboard_data")
@token_required(['admin'])
def get_dashboard_data():
    

    # Get All Customers
    Dashboard_Data = Get_dashboard_data()
    return Dashboard_Data

@app.route(f"/update_cart_data",methods=["POST"],endpoint="update_cart_data")
@token_required(['customer'])
def update_cart_data():
    
    customer_id = request.form["customer_id"] 
    cart_data = request.form["cart_data"]
    # Get All Customers
    Cart_Data_Response = Update_cart_Data(customer_id,cart_data)
    return Cart_Data_Response

@app.route(f"/update_wishlist_data",methods=["POST"],endpoint="update_wishlist_data")
@token_required(['customer'])
def update_wishlist_data():
    
    customer_id = request.form["customer_id"] 
    wishlist_data = request.form["wishlist_data"]
    # Get All Customers
    Wishlist_data_Response = Update_wishlist_Data(customer_id,wishlist_data)
    return Wishlist_data_Response

@app.route(f"/customer_change_password",methods=["POST"],endpoint="customer_change_password")
@token_required(['customer'])
def customer_change_password():
    
    customer_id = request.form["customer_id"] 
    current_password = request.form["current_password"]
    new_password = request.form["new_password"]

    Change_Password_Response = Customer_Change_Password(customer_id,current_password,new_password)
    return Change_Password_Response

@app.route(f"/cancel_order",methods=["POST"],endpoint="cancel_order")
@token_required(['customer'])
def cancel_order():
    order_id = request.form["order_id"] 
    Order_cancel_Response = Cancel_Order(order_id)
    return Order_cancel_Response

@app.route(f"/send_message", methods=["POST"],endpoint="send_message")
def send_message():

    # Get Form Data
    name = request.form["name"]
    email = request.form["email"]
    subject = request.form["subject"]
    message = request.form["message"]

    # Create Admin Account
    message_Response = Send_Message(name,email,subject,message)
    return message_Response

@app.route(f"/get_messages",methods=["GET"],endpoint="get_messages")
@token_required(['admin'])
def get_messages():
    all_message_Response = Get_Messages()
    return all_message_Response

# @app.route(f"/razorpay_order",methods=["POST"],endpoint="razorpay_order")
# @token_required(['customer'])
# def razorpay_order():
#     name = request.form["name"]
#     amount = request.form["amount"]
#     razorpay_order_response = Razorpay_Order(name, amount)
#     return razorpay_order_response

# @app.route(f"/razorpay_callback",methods=["POST"],endpoint="razorpay_callback")
# @token_required(['customer'])
# def razorpay_order():
#     response =request.get_json()
#     callback_response = Razorpay_Callback(response)
#     return callback_response

@app.route(f"/instamojo_order",methods=["POST"],endpoint="instamojo_order")
@token_required(['customer'])
def instamojo_order():
    buyer_name = request.form["buyer_name"]
    email = request.form["email"]
    phone = request.form["phone"]
    purpose = request.form["purpose"]
    amount =  request.form["amount"]
    redirect_url = request.form["redirect_url"]
    instamojo_order_response = Instamojo_Order(buyer_name,email,phone,purpose, amount,redirect_url)
    return instamojo_order_response

@app.route(f"/instamojo_callback",methods=["GET"],endpoint="instamojo_callback")
def instamojo_callback():
    response = request.args
    callback_response = Instamojo_Callback(response)
    return callback_response

# https://www.valuebound.com/resources/blog/how-set-razorpay-integration-django-reactjs

