###########################################################
#####                                                ######
#####       SERVER UTILS CALLBACK DATA SECTION       ######
#####                                                ######
###########################################################

import os
import jwt
import uuid
import secrets
import logging
import datetime
import sib_api_v3_sdk
from functools import wraps
from sqlalchemy import desc

from PIL import Image
from io import BytesIO
from random import randint
from sib_api_v3_sdk.rest import ApiException
from app.db_model import db, Admin, Product, Vendor, Customer, Orders, Receipts
from werkzeug.security import generate_password_hash, check_password_hash
from flask import Flask, request, jsonify, make_response,g

# Configure API key authorization: api-key for SENDINBLUE
configuration = sib_api_v3_sdk.Configuration()
configuration.api_key['api-key'] = os.environ.get("SENDINBLUE_API_KEY")


# Logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


# Log File Logging Format
formatter = logging.Formatter("%(asctime)s:%(levelname)s::%(message)s")


# Log File Handler
Log_File_Handler = logging.FileHandler("doxael_server_utils.log")
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
logger.info("Server Utils Section :: Logging Active")
logger.debug("")

def admin_token_required(f):
   @wraps(f)
   def decorator(*args, **kwargs):

      token = None

      if 'x-access-token' in request.headers:
         token = request.headers['x-access-token']

      if not token:
         return jsonify({'message': 'a valid token is missing'}), 401

      try:
         data = jwt.decode(token,os.environ.get('SECRETE_KEY'),algorithms=['HS256'])
         current_user = Admin.query.filter_by(admin_id=data['admin_id']).first()
      except Exception as e:
         return jsonify({'message': 'token is invalid',"error":str(e)}), 401
      return f(*args, **kwargs)
      
   return decorator

def token_required(roles):
   def wrap(f):
        def decorator(*args, **kwargs):
            token = None
            #   roles = kwargs['roles']
            if 'x-access-token' in request.headers:
                token = request.headers['x-access-token']

            if not token:
                return jsonify({'message': 'a valid token is missing'}), 401
            try:
                data = jwt.decode(token,os.environ.get('SECRETE_KEY'),algorithms=['HS256'])
                if 'admin_id' in data.keys():
                    role = 'admin'
                elif 'vendor_id' in data.keys():
                    role = 'vendor'
                else:
                    role = 'customer'
                if role not in roles:
                    return jsonify({'message': 'you are not allowed to access this api'}), 403
            except Exception as e:
                return jsonify({'message': 'token is invalid','msg':str(e)}), 401
            return f(*args, **kwargs)
            
        return decorator
#    Renaming the function name:
#    wrap.__name__ = f.__name__
   return wrap

def genID(N=16):
    """ 
    Randomly generates a N character long
    alphanumeric

    Params
    ------
    N: Length of ID to be generated

    Returns
    -------
    Type: String
    """
    gen_id = secrets.token_hex(N)
    return gen_id


def genUniqueID(table):
    """
    Randomly generates a Unique 16 character
    long alphanumeric by checking the table 
    to ensure uniqueness

    Params
    ------
    table: Database table against which the 
            uniqueness of the generated ID 
            is checked. 

    Returns
    -------
    Type: String
    """
    # Generated ID
    newID = genID()

    # Check IDs uniqueness
    if table == Admin:
        checkID = Admin.query.filter_by(admin_id = newID).all()

    if table == Customer:
        checkID = Customer.query.filter_by(customer_id = newID).all()

    if table == Vendor:
        checkID = Vendor.query.filter_by(vendor_id = newID).all()

    if table == Product:
        checkID = Product.query.filter_by(product_id = newID).all()

    if table == Orders:
        checkID = Orders.query.filter_by(order_id = newID).all()

    if table == Receipts:
        checkID = Receipts.query.filter_by(receipt_id = newID).all()

    if len(checkID) > 0:
        genUniqueID(table)
    else:
        return newID


def genToken(N=32):
    """
    Randomly generates a N character long url
    safe token

    Params
    ------
    N: Length of generated token

    Returns
    -------
    Type: String
    """
    gen_token = secrets.token_urlsafe(N)
    return gen_token


def genUniqueToken(table):
    """
    Randomly generates a Unique 32 character
    long url safe token by checking the table 
    to ensure uniqueness

    Params
    ------
    table: Database table against which the 
            uniqueness of the generated ID 
            is checked.

    Returns
    -------
    Type: String
    """
    # Generated ID
    newToken = genToken()

    # Check IDs uniqueness
    if table == Admin:
        checkToken = Admin.query.filter_by(admin_push_notification_token = newToken).all()

    if table == Customer:
        checkToken = Customer.query.filter_by(customer_push_notification_token = newToken).all()

    if table == Vendor:
        checkToken = Vendor.query.filter_by(vendor_push_notification_token = newToken).all()

    if len(checkToken) > 0:
        genUniqueToken(table)
    else:
        return newToken


def genResetPin(N=6):
    """
    Randomly generates an N character long
    number for resetting the password

    Params
    ------
    N: Length of ID to be generated

    Returns
    -------
    Type: String
    """
    gen_pin = ''.join(["{}".format(randint(0, 9)) for num in range(0,N)])
    return gen_pin


def genUniqueResetPin(table):
    """
    Randomly generates a Unique 6 character
    long reset pin by checking the table 
    to ensure uniqueness

    Params
    ------
    table: Database table against which the 
            uniqueness of the generated ID 
            is checked.

    Returns
    -------
    Type: String
    """
    # Generated ID
    newPin = genResetPin(6)

    # Check IDs uniqueness
    if table == Admin:
        checkPin = Admin.query.filter_by(admin_reset_pin = newPin).all()

    if table == Customer:
        checkPin = Customer.query.filter_by(customer_reset_pin = newPin).all()

    if table == Vendor:
        checkPin = Vendor.query.filter_by(vendor_reset_pin = newPin).all()

    if len(checkPin) > 0:
        genUniqueResetPin(table)
    else:
        return newPin


def Create_Account(account_type,**kwargs):
    """ 
    Creates the defaul admin user if one dosent exit

    Params
    ------
    account_type: The type of account
            user is creating
    kwargs: Keyword arguments for
            email -> "email"
            password -> "password"
            username -> "username"

    Returns
    -------
    Type: Dict
    keys: username,password,email,pussh_notification_token
    status_message: the result of the api query
    status: Login status
            options: success,failed
    status_code: request status code
    """

    # Check Account Exists
    if account_type == "admin":

        # Check if admin exists
        Account = Admin.query.filter_by(admin_email=kwargs["email"]).first()

    elif account_type == "vendor":

        # Check if vendor exists
        Account = Vendor.query.filter_by(vendor_email=kwargs["email"]).first()

    elif account_type == "customer":

        # Check if customer exists
        Account = Customer.query.filter_by(customer_email=kwargs["email"]).first()

    # if Account Does Not Exist
    if Account is None:
        
        # Params
        username = kwargs["username"] if kwargs["username"] is not None else None
        email = kwargs["email"]
        Password = kwargs["password"]
        hashedPassword = generate_password_hash(Password)


        # Create admin account
        if account_type == "admin":

            id = genUniqueID(Admin)
            push_notification_token = genUniqueToken(Admin)

            admin_user = Admin(admin_id=id, admin_name=username, admin_email=email, password=hashedPassword, admin_push_notification_token=push_notification_token)
            db.session.add(admin_user)
            db.session.commit()

        # Create vendor account
        elif account_type == "vendor":

            id = genUniqueID(Vendor)
            push_notification_token = genUniqueToken(Vendor)

            vendor_user = Vendor(vendor_id=id, vendor_name=username, vendor_email=email, password=hashedPassword, vendor_push_notification_token=push_notification_token)
            db.session.add(vendor_user)
            db.session.commit()

        # Create customer account
        elif account_type == "customer":

            id = genUniqueID(Customer)
            push_notification_token = genUniqueToken(Customer)

            customer_user = Customer(customer_id=id, customer_name=username, customer_email=email, password=hashedPassword, customer_push_notification_token=push_notification_token,permitted=True)
            db.session.add(customer_user)
            db.session.commit()

        # Response
        return {"id":id,"username":username,"password":Password,"email":email,"push_notification_token":push_notification_token,"status_message":f"{account_type.capitalize()} Account Created","status":"success","status_code":200}
    
    # If Account Exists
    else:
        return {"status_message":f"Account Already Exists with email {kwargs['email']}","status":"failed","status_code":400}


def Account_Login(account_type,email,password):
    """
    Function validates that account exist and
    logs user in

    Params
    ------
    email: Account Email
    password: Account Password
    account_type: The type of account
            user is logging into

    Returns
    -------
    id: account ID
    username: account password
    email: account email
    push_notification_token: account 
            associated push notification token
    status_message: the result of the api query
    status: Login status
            options: success,failed
    status_code: request status code
    """

    # For Admin
    if(account_type == "admin"):
        Account = Admin.query.filter_by(admin_email=email).first()

    # For Vendor
    elif(account_type == "vendor"):
        Account = Vendor.query.filter_by(vendor_email=email).first()

    # For Customer
    elif(account_type == "customer"):
        Account = Customer.query.filter_by(customer_email=email).first()

    
    # Check Account Exists
    if Account is not None:

        # Check For Permitted Accounts
        if account_type == "admin":
            pass
        
        elif (account_type == "vendor") and (Account.permitted == True):
            vendor_permitted = True

        elif (account_type == "customer") and (Account.permitted == True):
            customer_permitted = True

        else:
            return({"status_message":"You have not permitted to access this account.your account may be disaable by admin.","status":"failed","status_code":400})


        # Checked Password
        hashedpassword = Account.password
        checkPassword = check_password_hash(hashedpassword,password)

        if checkPassword == True:
            # For Admin
            if(account_type == "admin"):
                token = jwt.encode({'admin_id': Account.admin_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(days=1)}, os.environ.get('SECRETE_KEY'))
                return{"admin_id":Account.admin_id,"user_name":Account.admin_name,"email":Account.admin_email,"push_notification_token":Account.admin_push_notification_token,"token":token,"status_message":"Admin Logged In","role":"admin","status":"success","status_code":200}

            # For Vendor
            elif(account_type == "vendor") and (vendor_permitted == True):
                token = jwt.encode({'vendor_id': Account.vendor_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(days=1)}, os.environ.get('SECRETE_KEY'))
                return{"vendor_id":Account.vendor_id,"user_name":Account.vendor_name,"email":Account.vendor_email,"push_notification_token":Account.vendor_push_notification_token,"token":token,"status_message":"Vendor Logged In","role":"vendor","status":"success","status_code":200}

            # For Customer
            elif(account_type == "customer") and (customer_permitted == True):
                token = jwt.encode({'customer_id': Account.customer_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(days=1)}, os.environ.get('SECRETE_KEY'))
                return{"customer_id":Account.customer_id,"cart_data":Account.cart_data,"wishlist_data":Account.wishlist_data,"user_name":Account.customer_name,"email":Account.customer_email,"address":Account.customer_address,"push_notification_token":Account.customer_push_notification_token,"token":token,"status_message":"Customer Logged In","role":"customer","status":"success","status_code":200}

        else:
            return{"status_message":"Invalid Password","status":"failed","status_code":400}

    else:
        return{"status_message":"account does not exist","status":"failed","status_code":400}
    

def Add_Product(account_id,product_name,product_description,product_price,product_image,product_image_name,product_discount,product_category):
    """
    This function adds a product to the database

    Params
    ------
    account_id: The account ID of either admin or vendor
    product_name: The name of the product
    product_description: The description of the product
    product_price: The price of the product
    product_image: The image of the product
    product_image_name: The name of the image
    product_discount: The discount of the product
    product_category: The category of the product

    Returns
    -------
    product_id: The id of the product
    product_name: The name of the product
    product_description: The description of the product
    product_price: The price of the product
    product_image: The image of the product
    product_discount: The discount of the product
    product_category: The category of the product
    product_is_available: The availability of the product
    status_message: the result of the api query
    status: Add Product Status
            options: success,failed
    status_code: request status code
    """
    try:
            
        # Get Image
        image = product_image.read()

        # Convert Image To Bytes
        image = BytesIO(image)

        # Convert Image To PIL Image
        image = Image.open(image)

        # Image Name
        image_name = f"{genID()}_{product_image_name}"

        # Image Destination
        image_destination = os.path.join(os.path.dirname(os.path.abspath(__file__)),f"static/images/products/{image_name}")

        # Product ID
        id = genUniqueID(Product)

        # Save Image
        image.save(image_destination)

        # Add Product
        product = Product(product_id=id,product_name=product_name,product_description=product_description,product_price=product_price,product_image_name=image_name,product_image_filepath=image_destination,product_discount=product_discount,product_owner=account_id,product_is_available=True,product_category=product_category)
        db.session.add(product)
        db.session.commit()

        # Response
        return {"product_id":id,"product_name":product_name,"product_description":product_description,"product_price":product_price,"product_image":f"/static/images/products/{image_name}","product_discount":product_discount,"product_category":product_category,"product_is_available":True,"status_message":f"Product {product_name} Added","status":"success","status_code":200}

    except Exception as e:
        logger.debug(f"AddNewProductError: Failed to Add New Product,{e}")
        return{"status_message":"Failed to Add New Product","status":"failed","status_code":400}


def Get_Single_Product(product_id):
    """
    This function fetches data for a single product

    Params
    ------
    product_id: The id of the product being fetched

    Returns
    -------
    product_id: The id of the product
    product_name: The name of the product
    product_description: The description of the product
    product_price: The price of the product
    product_image: The image of the product
    product_discount: The discount of the product
    product_is_available: The availability of the product
    status_message: the result of the api query
    status: Add Product Status
            options: success,failed
    status_code: request status code
    """
    try:
        # Fetch Product
        product = Product.query.filter_by(product_id=product_id).first()

        # Check Product Exists and Return Response
        if product is not None:
            return {"product_id":product.product_id,"product_name":product.product_name,"product_description":product.product_description,"product_price":product.product_price,"product_image":f"/static/images/products/{product.product_image_name}","product_discount":product.product_discount,"product_category":product.product_category,"product_is_available":product.product_is_available,"product_is_featured":product.product_is_featured,"product_is_new":product.product_is_new,"product_is_best_seller":product.product_is_best_seller,"status_message":"Product Fetched","status":"success","status_code":200}
        else:
            return{"status_message":"Product Not Found","status":"failed","status_code":400}

    # On Error Handler and Return Response
    except Exception as e:
        logger.debug(f"GetSingleProductError: Failed to Get Single Product,{e}")
        return{"status_message":"Failed to Get Single Product","status":"failed","status_code":400}


def Get_All_Products(account_type=None,account_id=None):
    """
    This function fetches product from the database,
    if account_type is admin, it fetches all admin products
    if account_type is vendor, it fetches all vendor products
    if account_type is None, it fetches all products

    Params
    ------
    account_type: The type of account used to fetch products
    account_id: The id of the account used to fetch products

    Returns
    -------
    product_id: The id of the product
    product_name: The name of the product
    product_description: The description of the product
    product_price: The price of the product
    product_image: The image of the product
    product_discount: The discount of the product
    product_is_available: The availability of the product
    status_message: the result of the api query
    status: Add Product Status
            options: success,failed
    status_code: request status code
    """
    try:
        # Fetch All Products
        if (account_type == None and account_id == None):
            products = Product.query.all()

        # Fetch Admin Products
        elif(account_type == "admin"):
            products = Product.query.filter_by(product_owner=account_id).all()

        # Fetch Vendor Products
        elif(account_type == "vendor"):
            products = Product.query.filter_by(product_owner=account_id).all()

        # Check Products Exists and Return Response
        if products is not None:
            product_data = [{"product_id":product.product_id,"product_name":product.product_name,"product_description":product.product_description,"product_price":product.product_price,"product_image":f"/static/images/products/{product.product_image_name}","product_discount":product.product_discount,"product_is_available":product.product_is_available,"product_owner":product.product_owner, "product_category":product.product_category,"product_is_featured":product.product_is_featured,"product_is_new":product.product_is_new,"product_is_best_seller":product.product_is_best_seller} for product in products]
            return {"product_data":product_data,"status_message":"All Products Fetched","status":"success","status_code":200}
        else:
            return{"status_message":"No Products Found","status":"failed","status_code":400}

    # On Error Handler and Return Response
    except Exception as e:
        logger.debug(f"GetAllProductsError: Failed to Get All Products,{e}")
        return{"status_message":"Failed to Get All Products","status":"failed","status_code":400}


def Toggle_Enable_Vendor(action,admin_id,vendor_id):
    """ 
    This function enables admin to activate or deactivate a vendors account

    Params
    ------
    action: The action to be performed
            ation options: activate,deactivate
    admin_id: The id of the admin
    vendor_id: The id of the vendor

    Returns
    -------
    status_message: the result of the api query
    status: Add Product Status
            options: success,failed
    status_code: request status code
    """
    try:
        # Fetch Admin
        admin = Admin.query.filter_by(admin_id=admin_id).first()

        # Check Admin Exists
        if admin is not None: 

            # Fetch Vendor
            vendor = Vendor.query.filter_by(vendor_id=vendor_id).first()
            
            #  Activate Vendor
            if action == "activate":
                vendor.permitted = True
                vendor.permited_by = admin_id
                db.session.commit()
                return {"status_message":"Vendor Activated","status":"success","status_code":200}

            # Deactivate Vendor
            elif action == "deactivate":
                vendor.permitted = False
                vendor.permited_by = admin_id
                db.session.commit()
                return {"status_message":"Vendor Deactivated","status":"success","status_code":200}

            # On Invalid Action
            else:
                return{"status_message":"Invalid Action","status":"failed","status_code":400}

        # On Invalid Admin
        else:
            return{"status_message":"Invalid Admin","status":"failed","status_code":400}

    # On Error Handler and Return Response
    except Exception as e:
        logger.debug(f"ToggleEnableVendorError: Failed to Toggle Enable Vendor,{e}")
        return{"status_message":"Failed to Toggle Enable Vendor","status":"failed","status_code":400}


def Remove_Product(account_type,account_id,product_id):
    """
    This function is used to remove products from the database

    Params
    ------
    account_type: The type of account used to remove products
                    account_type options: admin,vendor
    account_id: The id of the account used to remove products
    product_id: The id of the product to be removed

    Returns
    -------
    status_message: the result of the api query
    status: Add Product Status
            options: success,failed
    status_code: request status code
    """
    try:
        # For Admin
        if account_type == "admin":
            
            # Verify Account Is Admin
            admin = Admin.query.filter_by(admin_id=account_id).first()
            
            # Verify Admin Exists
            if admin is not None:

                # Admin Remove Product
                product = Product.query.filter_by(product_id=product_id).first()

        # For Vendor
        elif account_type == "vendor":

            # Fetch Vendor Product
            product = Product.query.filter_by(product_id=product_id,product_owner=account_id).first()

        # Verify Product Exists
        if product is not None:

            # Remove Product Image
            os.remove(product.product_image_filepath)

            # Remove Product
            db.session.delete(product)
            db.session.commit()
            return {"status_message":"Product Removed","status":"success","status_code":200}
        else:
            return{"status_message":"Product Not Found","status":"failed","status_code":400}

    except Exception as e:
        logger.debug(f"RemoveProductError: Failed to Remove Product,{e}")
        return{"status_message":"Failed to Remove Product","status":"failed","status_code":400}


def Edit_Product(account_type,account_id,**kwargs):
    """
    This function edits an uploaded product

    Params
    ------
    account_type: The type of account used to edit products
                    account_type options: admin,vendor
    account_id: The id of the account used to edit products
    product_id: The id of the product to be edited
    product_name: The name of the product to be edited
    product_description: The description of the product to be edited
    product_price: The price of the product to be edited
    product_image: The image of the product to be edited
    product_discount: The discount of the product to be edited
    product_is_available: The availability of the product to be edited

    Returns
    -------
    updated_product_id: The id of the product to be edited
    updated_product_name: The name of the product to be edited
    updated_product_description: The description of the product to be edited
    updated_product_price: The price of the product to be edited
    updated_product_image: The image of the product to be edited
    updated_product_discount: The discount of the product to be edited
    updated_product_is_available: The availability of the product to be edited
    status_message: the result of the api query
    status: Add Product Status
            options: success,failed
    status_code: request status code
    """
    try:
        # For Admin
        if account_type == "admin":
            
            # Verify Account Is Admin
            admin = Admin.query.filter_by(admin_id=account_id).first()
            
            # Verify Admin Exists
            if admin is not None:

                # Admin Edit Product
                product = Product.query.filter_by(product_id=kwargs["product_id"]).first()

        # For Vendor
        elif account_type == "vendor":

            # Fetch Vendor Product
            product = Product.query.filter_by(product_id=kwargs["product_id"],product_owner=account_id).first()

        else:
            product = None

        # Verify Product Exists
        if product is not None:
            
            # Get Product Image
            product_image = kwargs["product_image"]

            # Get Image
            if product_image is not None:

                # Read Product Image
                image = product_image.read()

                # Convert Image To Bytes
                image = BytesIO(image)

                # Convert Image To PIL Image
                image = Image.open(image)

                # Get Image Name
                image_name = product_image.filename

                # Image Name
                product_image_name = f"{genID()}_{image_name}"

                # Image Destination
                image_destination = os.path.join(os.path.dirname(os.path.abspath(__file__)),f"static/images/products/{product_image_name}")
                # image_destination = os.path.join(os.path.dirname(os.path.abspath(__file__)),f"static/images/products/{image_name}")
                # Save Image
                image.save(image_destination)

                # remove old image
                old_image = product.product_image_filepath
                os.remove(old_image)

                # Edit Image Data
                product.product_image_name = product_image_name
                product.product_image_filepath = image_destination

            # Edit Product
            product.product_name = kwargs["product_name"] if kwargs["product_name"] is not None else product.product_name
            product.product_description = kwargs["product_description"] if kwargs["product_description"] is not None else product.product_description
            product.product_price = kwargs["product_price"] if kwargs["product_price"] is not None else product.product_price
            product.product_discount = kwargs["product_discount"] if kwargs["product_discount"] is not None else product.product_discount
            product.product_is_available = kwargs["product_is_available"] if kwargs["product_is_available"] is not None else product.product_is_available
            product.product_category = kwargs["product_category"] if kwargs["product_category"] is not None else product.product_category
            db.session.commit()

            return {"product_id":product.product_id,"product_name":product.product_name,"product_description":product.product_description,"product_price":product.product_price,"product_image_name":f"/static/images/products/{product.product_image_name}","product_discount":product.product_discount,"product_is_available":product.product_is_available,"product_category":product.product_category,"status_message":"Product Edited","status":"success","status_code":200}
        else:
            return{"status_message":"Product Not Found","status":"failed","status_code":400}

    except Exception as e:
        logger.debug(f"EditProductError: Failed to Edit Product,{e}")
        return{"status_message":"Failed to Edit Product","status":"failed","status_code":400}


def Fetch_Vendors(admin_id,filter):
    """
    This function fetches all the vendors 
    and filters them depending on the filter

    Params
    ------
    admin_id: The id of the admin used to fetch vendors
    filter: The filter used to filter vendors
            options: all,active,inactive

    Returns
    -------
    vendors: The list of vendors
    status_message: the result of the api query
    status: Add Product Status
            options: success,failed
    status_code: request status code
    """
    try:
        # Check For Admin
        admin = Admin.query.filter_by(admin_id=admin_id).first()

        # Verify Admin Exists
        if admin is not None:

            # Fetch Vendors
            vendors = Vendor.query.all()

            # Filter Vendors
            if filter == "active":
                vendors = [{"vendor_id":vendor.vendor_id,"vendor_name":vendor.vendor_name,"vendor_email":vendor.vendor_email,"vendor_push_notification_token":vendor.vendor_push_notification_token} for vendor in vendors if vendor.permitted == True]
            elif filter == "inactive":
                vendors = [{"vendor_id":vendor.vendor_id,"vendor_name":vendor.vendor_name,"vendor_email":vendor.vendor_email,"vendor_push_notification_token":vendor.vendor_push_notification_token} for vendor in vendors if not vendor.permitted == True]
            else:
                vendors = [{"vendor_id":vendor.vendor_id,"vendor_name":vendor.vendor_name,"vendor_email":vendor.vendor_email,"vendor_push_notification_token":vendor.vendor_push_notification_token, "vendor_permitted":vendor.permitted} for vendor in vendors]

        # Return Vendors
        return {"vendors":vendors,"status_message":"Vendors Fetched","status":"success","status_code":200}

    except Exception as e:
        logger.debug(f"FetchVendorsError: Failed to Fetch Vendors,{e}")
        return{"status_message":"Failed to Fetch Vendors","status":"failed","status_code":400}


def Single_Vendor(vendor_id):
    """
    This function fetches a single vendor

    Params
    ------
    vendor_id: The id of the vendor to be fetched

    Returns
    -------
    vendor: The vendor to be fetched
    status_message: the result of the api query
    status: Add Product Status
            options: success,failed
    status_code: request status code
    """
    try:
        # Fetch Vendor
        vendor = Vendor.query.filter_by(vendor_id=vendor_id).first()

        # Verify Vendor Exists
        if vendor is not None:

            # Return Vendor
            return {"vendor":[{"vendor_id":vendor.vendor_id,"vendor_name":vendor.vendor_name,"vendor_email":vendor.vendor_email,"vendor_push_notification_token":vendor.vendor_push_notification_token,"vendor_permitted":vendor.permitted}],"status_message":"Vendor Fetched","status":"success","status_code":200}
        else:
            return{"status_message":"Vendor Not Found","status":"failed","status_code":400}

    except Exception as e:
        logger.debug(f"SingleVendorError: Failed to Fetch Vendor,{e}")
        return{"status_message":"Failed to Fetch Vendor","status":"failed","status_code":400}


def Make_Featured_Product(admin_id,product_id):
    """
    This function makes a product featured

    Params
    ------
    admin_id: The id of the admin used to make a product featured
    product_id: The id of the product to be made featured

    Returns
    -------
    status_message: the result of the api query
    status: Add Product Status
            options: success,failed
    status_code: request status code
    """
    try:
        # Check For Admin
        admin = Admin.query.filter_by(admin_id=admin_id).first()

        # Verify Admin Exists
        if admin is not None:

            # Fetch Product
            product = Product.query.filter_by(product_id=product_id).first()

            # Verify Product Exists
            if product is not None:

                # Make Product Featured
                product.product_is_featured = True

                # Commit Changes
                db.session.commit()

                # Return Success
                return {"status_message":"Product Made Featured","status":"success","status_code":200}
            else:
                return{"status_message":"Product Not Found","status":"failed","status_code":400}

        else:
            return{"status_message":"Admin Not Found","status":"failed","status_code":400}

    except Exception as e:
        logger.debug(f"MakeFeaturedProductError: Failed to Make Product Featured,{e}")
        return{"status_message":"Failed to Make Product Featured","status":"failed","status_code":400}


def Make_Non_Featured_Product(admin_id,product_id):
    """
    This function makes a product non featured

    Params
    ------
    admin_id: The id of the admin used to make a product non featured
    product_id: The id of the product to be made non featured

    Returns
    -------
    status_message: the result of the api query
    status: Add Product Status
            options: success,failed
    status_code: request status code
    """
    try:
        # Check For Admin
        admin = Admin.query.filter_by(admin_id=admin_id).first()

        # Verify Admin Exists
        if admin is not None:

            # Fetch Product
            product = Product.query.filter_by(product_id=product_id).first()

            # Verify Product Exists
            if product is not None:

                # Make Product Non Featured
                product.product_is_featured = False

                # Commit Changes
                db.session.commit()

                # Return Success
                return {"status_message":"Product Made Non Featured","status":"success","status_code":200}
            else:
                return{"status_message":"Product Not Found","status":"failed","status_code":400}

        else:
            return{"status_message":"Admin Not Found","status":"failed","status_code":400}

    except Exception as e:
        logger.debug(f"MakeNonFeaturedProductError: Failed to Make Product Non Featured,{e}")
        return{"status_message":"Failed to Make Product Non Featured","status":"failed","status_code":400}

def Make_Non_new_Product(admin_id,product_id):
    """
    This function makes a product non new

    Params
    ------
    admin_id: The id of the admin used to make a product non featured
    product_id: The id of the product to be made non new

    Returns
    -------
    status_message: the result of the api query
    status: Add Product Status
            options: success,failed
    status_code: request status code
    """
    try:
        # Check For Admin
        admin = Admin.query.filter_by(admin_id=admin_id).first()

        # Verify Admin Exists
        if admin is not None:

            # Fetch Product
            product = Product.query.filter_by(product_id=product_id).first()

            # Verify Product Exists
            if product is not None:

                # Make Product Non Featured
                product.product_is_new = False

                # Commit Changes
                db.session.commit()

                # Return Success
                return {"status_message":"Product Made Non new","status":"success","status_code":200}
            else:
                return{"status_message":"Product Not Found","status":"failed","status_code":400}

        else:
            return{"status_message":"Admin Not Found","status":"failed","status_code":400}

    except Exception as e:
        logger.debug(f"MakeNonNewProductError: Failed to Make Product Non new,{e}")
        return{"status_message":"Failed to Make Product Non New","status":"failed","status_code":400}        

def Make_Non_bestseller_Product(admin_id,product_id):
    """
    This function makes a product non new

    Params
    ------
    admin_id: The id of the admin used to make a product non bestseller
    product_id: The id of the product to be made non bestseller

    Returns
    -------
    status_message: the result of the api query
    status: Add Product Status
            options: success,failed
    status_code: request status code
    """
    try:
        # Check For Admin
        admin = Admin.query.filter_by(admin_id=admin_id).first()

        # Verify Admin Exists
        if admin is not None:

            # Fetch Product
            product = Product.query.filter_by(product_id=product_id).first()

            # Verify Product Exists
            if product is not None:

                # Make Product Non Featured
                product.product_is_best_seller = False

                # Commit Changes
                db.session.commit()

                # Return Success
                return {"status_message":"Product Made Non bestseller","status":"success","status_code":200}
            else:
                return{"status_message":"Product Not Found","status":"failed","status_code":400}

        else:
            return{"status_message":"Admin Not Found","status":"failed","status_code":400}

    except Exception as e:
        logger.debug(f"MakeNonBestSellerProductError: Failed to Make Product Non bestseller,{e}")
        return{"status_message":"Failed to Make Product Non Bestseller","status":"failed","status_code":400}   

def Get_Featured_Products():
    """
    This function returns all featured products

    Params
    ------
    None

    Returns
    -------
    featured_products: The featured products
    status_message: the result of the api query
    status: Add Product Status
            options: success,failed
    status_code: request status code
    """
    try:
        # Fetch Featured Products
        products = Product.query.filter_by(product_is_featured=True).all()

        # Verify Products Exists
        if products is not None:
            
            # Get Featured Products
            featured_products = [{"product_id":product.product_id,"product_name":product.product_name,"product_description":product.product_description,"product_price":product.product_price,"product_image":f"/static/images/products/{product.product_image_name}","product_discount":product.product_discount,"product_is_available":product.product_is_available,"product_owner":product.product_owner,"product_category":product.product_category} for product in products]

            # Return Featured Products
            return {"featured_products":featured_products,"status_message":"Featured Products Fetched","status":"success","status_code":200}
        else:
            return{"status_message":"Featured Products Not Found","status":"failed","status_code":400}

    except Exception as e:
        logger.debug(f"GetFeaturedProductError: Failed to Fetch Featured Products,{e}")
        return{"status_message":"Failed to Fetch Featured Products","status":"failed","status_code":400}



def Make_New_Product(admin_id,product_id):
    """
    This function makes a product New

    Params
    ------
    admin_id: The id of the admin used to make a product New
    product_id: The id of the product to be made New

    Returns
    -------
    status_message: the result of the api query
    status: Add Product Status
            options: success,failed
    status_code: request status code
    """
    try:
        # Check For Admin
        admin = Admin.query.filter_by(admin_id=admin_id).first()

        # Verify Admin Exists
        if admin is not None:

            # Fetch Product
            product = Product.query.filter_by(product_id=product_id).first()

            # Verify Product Exists
            if product is not None:

                # Make Product New
                product.product_is_new = True

                # Commit Changes
                db.session.commit()

                # Return Success
                return {"status_message":"Product Made New","status":"success","status_code":200}
            else:
                return{"status_message":"Product Not Found","status":"failed","status_code":400}

        else:
            return{"status_message":"Admin Not Found","status":"failed","status_code":400}

    except Exception as e:
        logger.debug(f"MakeNewProductError: Failed to Make Product New,{e}")
        return{"status_message":"Failed to Make Product New","status":"failed","status_code":400}


def Make_Bestseller_Product(admin_id,product_id):
    """
    This function makes a product Bestseller

    Params
    ------
    admin_id: The id of the admin used to make a product Bestseller
    product_id: The id of the product to be made Bestseller

    Returns
    -------
    status_message: the result of the api query
    status: Add Product Status
            options: success,failed
    status_code: request status code
    """
    try:
        # Check For Admin
        admin = Admin.query.filter_by(admin_id=admin_id).first()

        # Verify Admin Exists
        if admin is not None:

            # Fetch Product
            product = Product.query.filter_by(product_id=product_id).first()

            # Verify Product Exists
            if product is not None:

                # Make Product Bestseller
                product.product_is_best_seller = True

                # Commit Changes
                db.session.commit()

                # Return Success
                return {"status_message":"Product Made Bestseller","status":"success","status_code":200}
            else:
                return{"status_message":"Product Not Found","status":"failed","status_code":400}

        else:
            return{"status_message":"Admin Not Found","status":"failed","status_code":400}

    except Exception as e:
        logger.debug(f"MakeBestsellerProductError: Failed to Make Product Bestseller,{e}")
        return{"status_message":"Failed to Make Product Bestseller","status":"failed","status_code":400}

def Get_Best_Seller_Products():
    """
    This function returns all best_seller products

    Params
    ------
    None

    Returns
    -------
    best_seller_products: The best_seller products
    status_message: the result of the api query
    status: Add Product Status
            options: success,failed
    status_code: request status code
    """
    try:
        # Fetch best_seller Products
        products = Product.query.filter_by(product_is_best_seller=True).all()

        # Verify Products Exists
        if products is not None:
            
            # Get best_seller Products
            best_seller_products = [{"product_id":product.product_id,"product_name":product.product_name,"product_description":product.product_description,"product_price":product.product_price,"product_image":f"/static/images/products/{product.product_image_name}","product_discount":product.product_discount,"product_is_available":product.product_is_available,"product_owner":product.product_owner,"product_category":product.product_category,"product_is_featured":product.product_is_featured,"product_is_new":product.product_is_new,"product_is_best_seller":product.product_is_best_seller} for product in products]

            # Return best_seller Products
            return {"best_seller_products":best_seller_products,"status_message":"best_seller Products Fetched","status":"success","status_code":200}
        else:
            return{"status_message":"best_seller Products Not Found","status":"failed","status_code":400}

    except Exception as e:
        logger.debug(f"GetFeaturedProductError: Failed to Fetch Featured Products,{e}")
        return{"status_message":"Failed to Fetch Featured Products","status":"failed","status_code":400}


def Get_New_Products():
    """
    This function returns all new products

    Params
    ------
    None

    Returns
    -------
    new_products: The new products
    status_message: the result of the api query
    status: Add Product Status
            options: success,failed
    status_code: request status code
    """
    try:
        # Fetch new Products
        products = Product.query.filter_by(product_is_new=True).all()

        # Verify Products Exists
        if products is not None:
            
            # Get new Products
            new_products = [{"product_id":product.product_id,"product_name":product.product_name,"product_description":product.product_description,"product_price":product.product_price,"product_image":f"/static/images/products/{product.product_image_name}","product_discount":product.product_discount,"product_is_available":product.product_is_available,"product_owner":product.product_owner,"product_category":product.product_category,"product_is_featured":product.product_is_featured,"product_is_new":product.product_is_new,"product_is_best_seller":product.product_is_best_seller} for product in products]

            # Return new Products
            return {"new_products":new_products,"status_message":"new Products Fetched","status":"success","status_code":200}
        else:
            return{"status_message":"new Products Not Found","status":"failed","status_code":400}

    except Exception as e:
        logger.debug(f"GetFeaturedProductError: Failed to Fetch Featured Products,{e}")
        return{"status_message":"Failed to Fetch Featured Products","status":"failed","status_code":400}


def Toggle_Enable_Customer(action,admin_id,customer_id):
    """ 
    This function enables admin to activate or deactivate a customers account

    Params
    ------
    action: The action to be performed
            ation options: activate,deactivate
    admin_id: The id of the admin
    vendor_id: The id of the vendor

    Returns
    -------
    status_message: the result of the api query
    status: Add Product Status
            options: success,failed
    status_code: request status code
    """
    try:
        # Fetch Admin
        admin = Admin.query.filter_by(admin_id=admin_id).first()

        # Check Admin Exists
        if admin is not None: 

            # Fetch Vendor
            customer = Customer.query.filter_by(customer_id=customer_id).first()
            
            #  Activate Vendor
            if action == "activate":
                customer.permitted = True
                customer.permited_by = admin_id
                db.session.commit()
                return {"status_message":"Customer Activated","status":"success","status_code":200}

            # Deactivate Vendor
            elif action == "deactivate":
                customer.permitted = False
                customer.permited_by = admin_id
                db.session.commit()
                return {"status_message":"Customer Deactivated","status":"success","status_code":200}

            # On Invalid Action
            else:
                return{"status_message":"Invalid Action","status":"failed","status_code":400}

        # On Invalid Admin
        else:
            return{"status_message":"Invalid Admin","status":"failed","status_code":400}

    # On Error Handler and Return Response
    except Exception as e:
        logger.debug(f"ToggleEnableCustomerError: Failed to Toggle Enable Vendor,{e}")
        return{"message":"Failed to Toggle Enable Customer","status":"failed","status_code":400}


def Get_All_Customers(admin_id,filter):
    """
    This function fetches all the vendors 
    and filters them depending on the filter

    Params
    ------
    admin_id: The id of the admin used to fetch vendors
    filter: The filter used to filter vendors
            options: all,active,inactive

    Returns
    -------
    customers: The list of customers
    status_message: the result of the api query
    status: Add Product Status
            options: success,failed
    status_code: request status code
    """
    try:
        # Check For Admin
        admin = Admin.query.filter_by(admin_id=admin_id).first()

        # Verify Admin Exists
        if admin is not None:

            # Fetch Vendors
            customers = Customer.query.all()

            # Filter Vendors
            if filter == "active":
                customers = [{"customer_id":customer.customer_id,"customer_name":customer.customer_name,"customer_email":customer.customer_email,"customer_address":customer.customer_address,"customer_push_notification_token":customer.customer_push_notification_token, "customer_permitted":customer.permitted} for customer in customers if customer.permitted == True]
            elif filter == "inactive":
                customers = [{"customer_id":customer.customer_id,"customer_name":customer.customer_name,"customer_email":customer.customer_email,"customer_address":customer.customer_address,"customer_push_notification_token":customer.customer_push_notification_token,"customer_permitted":customer.permitted} for customer in customers if not customer.permitted == True]
            else:
                customers = [{"customer_id":customer.customer_id,"customer_name":customer.customer_name,"customer_email":customer.customer_email,"customer_address":customer.customer_address,"customer_push_notification_token":customer.customer_push_notification_token, "customer_permitted":customer.permitted} for customer in customers]

        # Return Vendors
        return {"customers":customers,"status_message":"Customers Fetched","status":"success","status_code":200}

    except Exception as e:
        logger.debug(f"FetchCustomersError: Failed to Fetch Customers,{e}")
        return{"status_message":"Failed to Fetch Customers","status":"failed","status_code":400}

def Get_All_Admins():
    """
    This function fetches all the admins 


    Returns
    -------
    admins: The list of admins
    status_message: the result of the api query
    status: Add Product Status
            options: success,failed
    status_code: request status code
    """
    try:
        # Check For Admin
        admins = Admin.query.all()
        admins = [{"admin_id":admin.admin_id,"admin_name":admin.admin_name,"admin_email":admin.admin_email,"admin_push_notification_token":admin.admin_push_notification_token} for admin in admins]
        
        # Return Vendors
        return {"admins":admins,"status_message":"Customers Fetched","status":"success","status_code":200}

    except Exception as e:
        logger.debug(f"FetchAdminError: Failed to Fetch Admin,{e}")
        return{"status_message":"Failed to Fetch Admins","status":"failed","status_code":400}

def Send_Reset_Mail(email,reset_pin):
    """
    This function sends the password reset mail to
    the specified email.

    Params:
    -------
    email: The email of the user
    reset_pin: The reset pin to be sent

    Returns:
    --------
    ApiResponse: The response of the send in blue api
    ResetToken: The reset token to be sent to the user,
            expires after 13 minutes.
    status_message: The result of sending the mail
    status: The status of the mail sending
            options: success,failed
    status_code: request status code
    """
    try:
        # Create a new API Instance
        sendinblue_api = sib_api_v3_sdk.TransactionalEmailsApi(sib_api_v3_sdk.ApiClient(configuration))

        senderSmtp = sib_api_v3_sdk.SendSmtpEmailSender(name="Password Reset",email="no_reply@doxael.com")
        sendTo = sib_api_v3_sdk.SendSmtpEmailTo(email=f"{email}")
        arrTo = [sendTo] 
        send_smtp_email = sib_api_v3_sdk.SendSmtpEmail(sender=senderSmtp,to=arrTo,html_content=f"Kindly Reset Your Password using the code {reset_pin}, please be aware that, the validity period for password reset is 15 minutes",subject="Resetting Your Account Password")

        # Send a transactional 
        sendinblue_api.send_transac_email(send_smtp_email)

        # Create Timed Token
        expiry_time = datetime.datetime.now() + datetime.timedelta(minutes=15)
        token = jwt.encode({'reset_pin':reset_pin,'email':email,'expiration': f"{expiry_time}"},os.environ.get('SECRETE_KEY'),algorithm='HS256')

        # Return Response
        return {"reset_token":token,"status_message":"Password Reset Mail Sent","status":"success","reset_pin":reset_pin,"status_code":200}

    except ApiException as e:
        logger.exception(f"SendResetMailError: Failed to Send Reset Mail,{e}")
        return {"status_message":"Failed to Send Password Reset Mail","status":"failed","status_code":400}


def Reset_Password(account_type,email=None):
    """
    This function resets the password of the specified user

    Params:
    -------
    account_type: The type of account to be reset
    email: The email of the user

    Returns:
    --------
    status_message: The result of sending the mail
    status: The status of the mail sending
            options: success,failed
    status_code: request status code
    """
    try:
        # Generate and Store Reset Pin
        if account_type == "admin":
            reset_pin = genUniqueResetPin(Admin)
            admin = Admin.query.filter_by(admin_email=email).first()
            admin.admin_reset_pin = reset_pin
            db.session.commit()

        elif account_type == "vendor":
            reset_pin = genUniqueResetPin(Vendor)
            vendor = Vendor.query.filter_by(vendor_email=email).first()
            vendor.vendor_reset_pin = reset_pin
            db.session.commit()

        elif account_type == "customer":
            reset_pin = genUniqueResetPin(Customer)
            customer = Customer.query.filter_by(customer_email=email).first()
            customer.customer_reset_pin = reset_pin
            db.session.commit()

        # Send Reset Pin to Email
        Send_Response = Send_Reset_Mail(email,reset_pin)
        return Send_Response
    
    except Exception as e:
        logger.exception(f"ResetPasswordError: Failed to Reset Password,{e}")
        return{"status_message":"Failed to Reset Password,Please check your email","status":"failed","status_code":400}


def Update_Password(account_type,token,pin,password,confirmPassword):
    """
    This function updates the password of the specified account

    Params:
    -------
    account_type: The type of account to be updated
    token: The reset token to be used to update the password
    pin: The reset pin to be used to update the password
    password: The new password to be used to update the password
    confirmPassword: The new password to be used to update the password

    Returns:
    --------
    status_message: The result of password update request
    status: The status of the password update
            options: success,failed
    status_code: request status code
    """

    # Check Validity Of Session
    try:
        data = jwt.decode(token,os.environ.get('SECRETE_KEY'),algorithms=['HS256'])
        email = data['email']
        expiry_time = datetime.datetime.strptime(data['expiration'], "%Y-%m-%d %H:%M:%S.%f")

        # Check If Token Expired
        if datetime.datetime.now() > expiry_time:
            return {"status_message":"Session Expired","status":"failed","status_code":400}

        # Check If Password Matches
        if password != confirmPassword:
            return {"status_message":"Passwords Do Not Match","status":"failed","status_code":400}

        # Check If Pin Matches
        if account_type == "admin":
            admin = Admin.query.filter_by(admin_email=email).first()
            if admin.admin_reset_pin != pin:
                return {"status_message":"Invalid Pin","status":"failed","status_code":400}

            # Update Password
            admin.password = generate_password_hash(password)
            db.session.commit()

        elif account_type == "vendor":
            vendor = Vendor.query.filter_by(vendor_email=email).first()
            if vendor.vendor_reset_pin != pin:
                return {"status_message":"Invalid Pin","status":"failed","status_code":400}

            # Update Password
            vendor.password = generate_password_hash(password)
            db.session.commit()

        elif account_type == "customer":
            customer = Customer.query.filter_by(customer_email=email).first()
            if customer.customer_reset_pin != pin:
                return {"status_message":"Invalid Pin","status":"failed","status_code":400}

            # Update Password
            customer.password = generate_password_hash(password)
            db.session.commit()

        # Return Response
        return {"status_message":"Password Updated","status":"success","status_code":200}

    except Exception as e:
        logger.exception(f"UpdatePasswordError: Failed to Update Password,{e}")
        return{"status_message":"Failed to Update Password","status":"failed","status_code":400}


def Add_Purchase(customer_id,total_receipt_amount,contact_no,order_name,address,purchase_details):
    """
    This function adds a purchase to the database

    Params:
    -------
    customer_id: The id of the customer who made the purchase
    purchase_details: The details of the purchase
    total_price: The total price of the purchase

    Returns:
    --------
    status_message: The result of adding the purchase
    status: The status of the purchase addition
            options: success,failed
    status_code: request status code
    """
    rec_id = genUniqueID(Receipts)
    try:
            # Add receipt
            receipt = Receipts(receipt_id = rec_id,receipt_total_amount=total_receipt_amount,customer_id=customer_id,receipt_date=datetime.datetime.now())
            db.session.add(receipt)
            db.session.commit()

    except Exception as e:
        logger.exception(f"AddPurchaseError: Failed to Add Purchase,{e}")
        return{"status_message":"Failed to Add receipt","status":"failed","status_code":400}

    for details in purchase_details:

        # Create Order Entry        
        order_owner_id=details['owner_id'] if details["owner_id"] else None
        order_product_id=details['product_id'] if details["product_id"] else None
        # order_product_name=details['product_name'] if details["product_name"] else None
        # order_product_image=details['product_image'] if details["product_image"] else None
        # order_product_price=details['product_price'] if details["product_price"] else None
        # order_product_discount=details["product_discount"] if details["product_discount"] else None
        order_product_quantity=details['product_quantity'] if details["product_quantity"] else None
        order_total_amount=details['total_amount'] if details["total_amount"] else None
        # order_product_description=details['product_description'] if details["product_description"] else None
        # order_address=details['address'] if details["address"] else None

        # Contact no
        # if len(str(details['contact_no'])) == 10:
        #     order_contact_no=details['contact_no'] if details["contact_no"] else None
        # else:
        #     return{"status_message":"Invalid contact number","status":"failed","status_code":400}

        # Order date
        if 'order_date' in details.keys():
            order_date = details['order_date']
        else:
            order_date = datetime.datetime.now()

        # Get ID
        prod_id = genUniqueID(Product)
        print("prod==>",prod_id)
        
        ord_id = genUniqueID(Orders)
        print("prod==>",ord_id)

        try:
            # Add Purchase
            purchase = Orders(order_id = ord_id,receipt_id=rec_id,order_customer_id=customer_id,item_unique_id=prod_id,order_owner_id=order_owner_id,order_total_amount=order_total_amount,order_product_id=order_product_id,order_product_quantity=order_product_quantity,order_date=order_date,order_contact_no=contact_no,order_address=address,order_name=order_name,order_status='Pending')
            db.session.add(purchase)
            db.session.commit()

        except Exception as e:
            logger.exception(f"AddPurchaseError: Failed to Add Purchase,{e}")
            return{"status_message":"Failed to Add Purchase","status":"failed","status_code":400}

    return {"status_message":"Purchase Added","status":"success","status_code":200}


def Show_Purchases(customer_id,filter_type=None,filter_value=None):
    """
    This function shows all the purchases made by the specified customer

    Params:
    -------
    customer_id: The id of the customer
    filter_type: The type filter to be used to filter the purchases made by the customer
            The filter options are: order_id,item_unique_id,order_date,order_name
    filter_value: The value of the filter to be used to filter the purchases made by the customer

    Returns:
    --------
    status_message: The result of showing the purchases
    status: The status of the showing of the purchases
            options: success,failed
    status_code: request status code
    """
    try:
        # Get Purchase
        # if filter_type == "order_id":
        #     orders = Orders.query.filter_by(order_customer_id=customer_id,order_id=filter_value).all()

        # elif filter_type == "item_unique_id":
        #     orders = Orders.query.filter_by(order_customer_id=customer_id,item_unique_id=filter_value).all()

        # elif filter_type == "order_date":
        #     orders = Orders.query.filter_by(order_customer_id=customer_id,order_date=filter_value).all()

        # elif filter_type == "product_name":
        #     orders = Orders.query.filter_by(order_customer_id=customer_id,order_product_name=filter_value).all()

        # else:
        #     orders = Orders.query.filter_by(order_customer_id=customer_id).all()

        receipts=Receipts.query.filter_by(customer_id=customer_id).order_by(desc(Receipts.receipt_date)).all()
        orders_list=[{"receipt_id":receipt.receipt_id,"receipt_total":receipt.receipt_total_amount,"date":receipt.receipt_date,"orders":[{"id":order.order_id,"product":[{"id":product.product_id,"name":product.product_name,"product_image":f"/static/images/products/{product.product_image_name}"} for product in Product.query.filter_by(product_id=order.order_product_id)][0],"quantity":order.order_product_quantity,"total_amount":order.order_total_amount,"order_status":order.order_status,"order_tracking_id":order.order_tracking_id,"order_delivery_partner":order.order_delivery_partner,"address":order.order_address,"name":order.order_name,"phone":order.order_contact_no} for order in Orders.query.filter_by(receipt_id=receipt.receipt_id).all()] } for receipt in receipts ]
        # orders_list = [{"order_part_of":order.order_id,"order_vendor_id":order.order_vendor_id,"item_unique_id":order.item_unique_id,"order_total_price":order.order_total_price,"order_product_id":order.order_product_id,"order_product_name":order.order_product_name,"order_product_price":order.order_product_price,"order_product_discount":order.order_product_discount,"order_product_quantity":order.order_product_quantity,"order_product_image":order.order_product_image,"order_product_description":order.order_product_description,"order_product_was_available":order.order_product_is_available,"order_date":order.order_date,"item_order_total_value":((int(order.order_product_price) * int(order.order_product_quantity)) - ((int(order.order_product_discount)/100) * (int(order.order_product_price) * int(order.order_product_quantity))))} for order in orders]

        # Return Response
        return {"status_message":"Purchases Found","status":"success","status_code":200,"purchases":orders_list}

    except Exception as e:
        logger.exception(f"ShowPurchasesError: Failed to Show Purchases,{e}")
        return{"status_message":"Failed to Show Purchases","status":"failed","status_code":400}

def Show_all_Purchases(filter_type=None):
    """
    This function shows all the purchases made by the specified customer

    Params:
    -------
    customer_id: The id of the customer
    filter_type: The type filter to be used to filter the purchases made by the customer
            The filter options are: order_id,item_unique_id,order_date,order_name
    filter_value: The value of the filter to be used to filter the purchases made by the customer

    Returns:
    --------
    status_message: The result of showing the purchases
    status: The status of the showing of the purchases
            options: success,failed
    status_code: request status code
    """
    try:
        # Get Purchase
        if filter_type == "Pending":
            orders = Orders.query.filter_by(order_status="Pending").order_by(desc(Orders.order_date)).all()

        elif filter_type == "Confirmed":
            orders = Orders.query.filter_by(order_status="Confirmed").order_by(desc(Orders.order_date)).all()
        elif filter_type == "Shipped":
            orders = Orders.query.filter_by(order_status="Shipped").order_by(desc(Orders.order_date)).all()
        elif filter_type == "Delivered":
            orders = Orders.query.filter_by(order_status="Delivered").order_by(desc(Orders.order_date)).all()
        elif filter_type == "Cancelled":
            orders = Orders.query.filter_by(order_status="Cancelled").order_by(desc(Orders.order_date)).all()
        else:
            orders = Orders.query.order_by(desc(Orders.order_date)).all()

        # receipts=Receipts.query.filter_by(customer_id=customer_id).order_by(desc(Receipts.receipt_date)).all()
        # orders_list=[{"receipt_id":receipt.receipt_id,"receipt_total":receipt.receipt_total_amount,"date":receipt.receipt_date,"orders":[{"id":order.order_id,"product":[{"id":product.product_id,"name":product.product_name,"product_image":f"/static/images/products/{product.product_image_name}"} for product in Product.query.filter_by(product_id=order.order_product_id)],"quantity":order.order_product_quantity,"total_amount":order.order_total_amount,"address":order.order_address,"name":order.order_name,"phone":order.order_contact_no} for order in Orders.query.filter_by(receipt_id=receipt.receipt_id).all()] } for receipt in receipts ]
        orders_list = [{"order_id":order.order_id,"receipt_id":order.receipt_id,"order_total_amount":order.order_total_amount,"order_product_id":order.order_product_id,"order_status":order.order_status,"order_date":order.order_date,"customer":[{"id":customer.customer_id,"name":customer.customer_name} for customer in Customer.query.filter_by(customer_id=order.order_customer_id)][0]} for order in orders]

        # Return Response
        return {"status_message":"Purchases Found","status":"success","status_code":200,"purchases":orders_list}

    except Exception as e:
        logger.exception(f"ShowAllPurchasesError: Failed to Show all Purchases,{e}")
        return{"status_message":"Failed to Show all Purchases","status":"failed","status_code":400}
def Show_all_Receipts():
    """
    This function shows all the purchases made by the specified customer

    Params:
    -------
    customer_id: The id of the customer
    filter_type: The type filter to be used to filter the purchases made by the customer
            The filter options are: order_id,item_unique_id,order_date,order_name
    filter_value: The value of the filter to be used to filter the purchases made by the customer

    Returns:
    --------
    status_message: The result of showing the purchases
    status: The status of the showing of the purchases
            options: success,failed
    status_code: request status code
    """
    try:

        receipts=Receipts.query.order_by(desc(Receipts.receipt_date)).all()
        # orders_list=[{"receipt_id":receipt.receipt_id,"receipt_total":receipt.receipt_total_amount,"date":receipt.receipt_date,"orders":[{"id":order.order_id,"product":[{"id":product.product_id,"name":product.product_name,"product_image":f"/static/images/products/{product.product_image_name}"} for product in Product.query.filter_by(product_id=order.order_product_id)],"quantity":order.order_product_quantity,"total_amount":order.order_total_amount,"address":order.order_address,"name":order.order_name,"phone":order.order_contact_no} for order in Orders.query.filter_by(receipt_id=receipt.receipt_id).all()] } for receipt in receipts ]
        receipt_list=[{"receipt_id":receipt.receipt_id,"receipt_total":receipt.receipt_total_amount,"date":receipt.receipt_date,"orders":[{"id":order.order_id,"quantity":order.order_product_quantity,"total_amount":order.order_total_amount} for order in Orders.query.filter_by(receipt_id=receipt.receipt_id).all()] } for receipt in receipts ]

        # Return Response
        return {"status_message":"Receipts Found","status":"success","status_code":200,"receipts":receipt_list}

    except Exception as e:
        logger.exception(f"ShowAllReceiptsError: Failed to Show all Receipts,{e}")
        return{"status_message":"Failed to Show all Receipts","status":"failed","status_code":400}

def Show_Purchases_by_id(order_id):
    """
    This function shows all the purchases made by the specified customer

    Params:
    -------
    customer_id: The id of the customer
    filter_type: The type filter to be used to filter the purchases made by the customer
            The filter options are: order_id,item_unique_id,order_date,order_name
    filter_value: The value of the filter to be used to filter the purchases made by the customer

    Returns:
    --------
    status_message: The result of showing the purchases
    status: The status of the showing of the purchases
            options: success,failed
    status_code: request status code
    """
    try:
        # Get Purchase
        order = Orders.query.filter_by(order_id=order_id).first()
        print("Order",order)
        # receipts=Receipts.query.filter_by(customer_id=customer_id).order_by(desc(Receipts.receipt_date)).all()
        order_details=[{"receipt_id":order.receipt_id,"customer_id":order.order_customer_id,"order_status":order.order_status,"order_tracking_id":order.order_tracking_id,"order_delivery_partner":order.order_delivery_partner,"date":order.order_date,"id":order.order_id,"product":[{"id":product.product_id,"name":product.product_name,"product_image":f"/static/images/products/{product.product_image_name}"} for product in Product.query.filter_by(product_id=order.order_product_id)][0],"quantity":order.order_product_quantity,"total_amount":order.order_total_amount,"address":order.order_address,"name":order.order_name,"phone":order.order_contact_no}]
        # orders_list = [{"order_id":order.order_id,"receipt_id":order.receipt_id,"order_total_amount":order.order_total_amount,"order_product_id":order.order_product_id,"order_status":order.order_status,"order_date":order.order_date} for order in orders]

        # Return Response
        return {"status_message":"Purchase Found","status":"success","status_code":200,"purchaseDetails":order_details}

    except Exception as e:
        logger.exception(f"ShowPurchaseDetailsError: Failed to Show Purchase details,{e}")
        return{"status_message":"Failed to Show Purchase details","status":"failed","status_code":400}

def update_customer_address(customer_id,address):
    try:
        # Check For Admin

            # Fetch Product
        customer = Customer.query.filter_by(customer_id=customer_id).first()

            # Verify Product Exists
        if customer is not None:

            # Make Product Featured
            customer.customer_address = address

            # Commit Changes
            db.session.commit()

            # Return Success
            return {"status_message":"address updated successfully","status":"success","status_code":200}
        else:
            return{"status_message":"customer Not Found","status":"failed","status_code":400}

    except Exception as e:
        logger.debug(f"MakeFeaturedProductError: Failed to Make Product Featured,{e}")
        return{"status_message":"Failed to Make Product Featured","status":"failed","status_code":400}
def Get_category_sort_Products(category):
    """
    This function returns all products of specified category

    Params
    ------
    product_category (str)

    Returns
    -------
    best_seller_products: The best_seller products
    status_message: the result of the api query
    status: Add Product Status
            options: success,failed
    status_code: request status code
    """
    try:
        # Fetch best_seller Products
        products = Product.query.filter_by(product_category=category).all()

        # Verify Products Exists
        if products is not None:
            
            # Get best_seller Products
            products = [{"product_id":product.product_id,"product_name":product.product_name,"product_description":product.product_description,"product_price":product.product_price,"product_image":f"/static/images/products/{product.product_image_name}","product_discount":product.product_discount,"product_is_available":product.product_is_available,"product_owner":product.product_owner,"product_category":product.product_category} for product in products]

            # Return best_seller Products
            return {"products":products,"status_message":f"Products Fetched with category {category}","status":"success","status_code":200}
        else:
            return{"status_message":"best_seller Products Not Found","status":"failed","status_code":400}

    except Exception as e:
        logger.debug(f"GetFeaturedProductError: Failed to Fetch Featured Products,{e}")
        return{"status_message":"Failed to Fetch Featured Products","status":"failed","status_code":400}

def Get_Products(product_id):
    """
    This function returns single product with given ID

    Params
    ------
    product_id (str)

    Returns
    -------
    singular product details: The product details of given id
    status_message: the result of the api query
    status: Get Product Status
            options: success,failed
    status_code: request status code
    """
        # Fetch Product
    products = Product.query.filter_by(product_id=product_id)

    # Verify Products Exists
    if products is not None:
        
        # Get best_seller Products
        products_data = [{"product_id":product.product_id,"product_name":product.product_name,"product_description":product.product_description,"product_price":product.product_price,"product_image":f"/static/images/products/{product.product_image_name}","product_discount":product.product_discount,"product_is_available":product.product_is_available,"product_owner":product.product_owner,"product_category":product.product_category} for product in products]

        # Return best_seller Products
        return {"products":products_data,"status_message":f"Products Fetched with product id {product_id}","status":"success","status_code":200}
    else:
        return{"status_message":"best_seller Products Not Found","status":"failed","status_code":400}

def Edit_Order(order_id,order_status,order_tracking_id,order_delivery_partner):
    try:
        # For Admin
        order=Orders.query.filter_by(order_id=order_id).first()

        # Verify order Exists
        if order is not None:
            
        
            # Edit Product
            order.order_status = order_status if order_status is not None else order.order_status
            order.order_tracking_id = order_tracking_id if order_tracking_id is not None else order.order_tracking_id
            order.order_delivery_partner = order_delivery_partner if order_delivery_partner is not None else order.order_delivery_partner

            db.session.commit()

            return {"status_message":"Order updated successfully","status":"success","status_code":200}
        else:
            return{"status_message":"Order Not Found","status":"failed","status_code":400}

    except Exception as e:
        logger.debug(f"EditProductError: Failed to Edit Product,{e}")
        return{"status_message":"Failed to Edit Order","status":"failed","status_code":400}

def Get_dashboard_data():
    try: 
        total_orders = Orders.query.order_by(desc(Orders.order_date)).count()
        inProgress_orders=Orders.query.filter(Orders.order_status.in_(["Pending","Confirmed","Shipped"])).order_by(desc(Orders.order_date)).count()
        delivered_orders=Orders.query.filter_by(order_status="Delivered").order_by(desc(Orders.order_date)).count()
        total_receipts= Receipts.query.order_by(desc(Receipts.receipt_date)).count()
        total_products=Product.query.count()
        total_customers=Customer.query.count()
        total_featured_product = Product.query.filter_by(product_is_featured=True).count()
        total_best_selling_product=Product.query.filter_by(product_is_best_seller=True).count()
        total_new_product=Product.query.filter_by(product_is_new =True).count()

        return {"total_new_product":total_new_product,"total_best_selling_product":total_best_selling_product,"total_featured_product":total_featured_product,"total_customers":total_customers,"total_products":total_products,"total_receipts":total_receipts,"total_orders":total_orders,"in_progress_orders":inProgress_orders,"delivered_orders":delivered_orders,"status_message":"Dashboard data get successfully","status":"success","status_code":200}

    except Exception as e:
        logger.debug(f"DashboardDataError: Failed to get dashboard data,{e}")
        return{"status_message":"Failed to get dashboard data","status":"failed","status_code":400}

def Update_cart_Data(customer_id,cart_data):
    try:
        # For Admin
        customer = Customer.query.filter_by(customer_id=customer_id).first()

            # Verify Product Exists
        if customer is not None:

            # Make Product Featured
            customer.cart_data = cart_data

            # Commit Changes
            db.session.commit()

            return {"status_message":"cart data updated successfully","status":"success","status_code":200}
        else:
            return{"status_message":"customer Not Found","status":"failed","status_code":400}

    except Exception as e:
        logger.debug(f"UpdateCartDataError: Failed to update Cart data,{e}")
        return{"status_message":"Failed to update cart data","status":"failed","statuse":400}

def Update_wishlist_Data(customer_id,wishlist_Data):
    try:
        # For Admin
        customer = Customer.query.filter_by(customer_id=customer_id).first()

            # Verify Product Exists
        if customer is not None:

            # Make Product Featured
            customer.wishlist_Data = wishlist_Data

            # Commit Changes
            db.session.commit()

            return {"status_message":"wishlist data updated successfully","status":"success","status_code":200}
        else:
            return{"status_message":"customer Not Found","status":"failed","status_code":400}

    except Exception as e:
        logger.debug(f"UpdatewishlistDataError: Failed to update wishlist data,{e}")
        return{"status_message":"Failed to updatewishlist data","status":"failed","statuse":400}

def Customer_Change_Password(customer_id,current_password,new_password):

    Account = Customer.query.filter_by(customer_id=customer_id).first()
    if Account is not None:
        hashedpassword = Account.password
        checkPassword = check_password_hash(hashedpassword,current_password)

        if checkPassword == True:
            Account.password = generate_password_hash(new_password)
            db.session.commit()
            return {"status_message":"Password Changed Successfully","status":"success","status_code":200}
        else:
            return{"status_message":"Invalid Current Password","status":"failed","status_code":400}
            
    else:
        return{"status_message":"customer does not exist","status":"failed","status_code":400}

def Cancel_Order(order_id):
    try:
        # For Admin
        order=Orders.query.filter_by(order_id=order_id).first()

        # Verify order Exists
        if order is not None:
            
        
            # Edit Product
            order.order_status = "Cancelled"

            db.session.commit()

            return {"status_message":"Order Cancelled successfully","status":"success","status_code":200}
        else:
            return{"status_message":"Order Not Found","status":"failed","status_code":400}

    except Exception as e:
        logger.debug(f"CancelOrderError: Failed to Edit Product,{e}")
        return{"status_message":"Failed to cancel Order","status":"failed","status_code":400}


