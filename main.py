from pymongo import MongoClient, errors
from flask import Flask, request, jsonify, session
from itsdangerous import TimedSerializer  as Serializer, BadSignature, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash
import logging
import os
import pyotp
#import smtplib
#from email.mime.text import MIMImage
from dotenv import load_dotenv
from functools import wraps
from bson import ObjectId
from datetime import datetime , timedelta
import jwt
import time
import uuid
import re

app = Flask(__name__)

load_dotenv()
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
MONGO_URL = os.getenv("MONGO_URL")
app.config["MONGO_URL"] = MONGO_URL
app.config["SESSION_TYPE"] = "filesystem"

#SMTP_SERVER = os.getenv("SMTP_SERVER")
#SMTP_PORT = int(os.getenv("SMTP_PORT"))
#SMTP_USERNAME = os.getenv("SMTP_USERNAME")
#SMTP_PASSWORD = os.getenv("SMTP_PASSWORD")

server = MongoClient(MONGO_URL)
db = server["Main"]
users = db["users"]
product = db["product"]
basket = db["basket"]
order = db["order"]

users.create_index([("firstname", 1), ("lastname", 1)], unique=True)
users.create_index([("email", 1)], unique=True)

product_validation_rules = {
    "bsonType": "object",
    "required": ["name", "price", "description", "quantity", "image_path"],
    "properties": {
        "name": {
            "bsonType": "string",
            "description": "must be a string and is required"
        },
        "price": {
            "bsonType": "double",
            "description": "must be a double and is required"
        },
        "description": {
            "bsonType": "string",
            "description": "must be a string and is required"
        },
        "quantity": {
            "bsonType": "int",
            "description": "must be an integer and is required"
        },
        "image_path": {
            "bsonType": "string",
            "description": "must be a string (path to image) and is required"
        }
    }
}

user_validation_rules = {
        "bsonType": "object",
        "required": ["firstname", "lastname", "email", "password"],
        "properties": {
            "firstname": {
                "bsonType": "string",
                "description": "must be a string"
            },
            "lastname": {
                "bsonType": "string",
                "description": "must be a string"
            },
            "email": {
                "bsonType": "string",
                "description": "must be a string and is required"
            },
            "password": {
                "bsonType": "string",
                "description": "must be a string and is required"
            }
        }
    }

try:
    if "product" not in db.list_collection_names():
        db.create_collection("product", validator={"$jsonSchema": product_validation_rules})
        print("Product collection created successfully.")
    if "users" not in db.list_collection_names():
        db.create_collection("users", validator={"$jsonSchema": user_validation_rules})
        print("Users collection created successfully.")
except Exception as e:
    print(f"An error occurred: {e}")

#def send_otp(email, otp):
    #msg = MIMEText(f"Your OTP is {otp}")
    #msg["Subject"] = "Your OTP Code"
    #msg["From"] = SMTP_USERNAME
    #msg["To"] = email

    #try:
         #with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            #server.starttls()
            #server.login(SMTP_USERNAME, SMTP_PASSWORD)
            #server.sendmail(SMTP_USERNAME, [email], msg.as_string())
    #except smtplib.SMTPException as e:
        #logging.error(f"Failed to send OTP email: {str(e)}")
        #raise

@app.errorhandler(errors.PyMongoError)
def handle_pymongo_error(e):
    logging.error(f"A database error occurred: {str(e)}")
    return jsonify({"status": "error", "error": {"code": 500, "message": "Database Error"}}), 500

@app.errorhandler(BadSignature)
def handle_bad_signature(e):
    logging.error(f"Bad signature: {str(e)}")
    return jsonify({"status": "error", "error": {"code": 401, "message": "Invalid token"}}), 401

@app.errorhandler(SignatureExpired)
def handle_signature_expired(e):
    logging.error(f"Signature expired: {str(e)}")
    return jsonify({"status": "error", "error": {"code": 401, "message": "Token has expired"}}), 401

@app.errorhandler(ValueError)
def handle_value_error(e):
    logging.error(f"Validation error: {str(e)}")
    return jsonify({"status": "error", "error": {"code": 400, "message": "Validation Error"}}), 400

@app.errorhandler(Exception)
def handle_exception(e):
    logging.error(f"An error occurred: {str(e)}")
    return jsonify({"status": "error", "error": {"code": 500, "message": "Internal Server Error"}}), 500

@app.errorhandler(404)
def not_found(e):
    return jsonify({"status": "error", "error": {"code": 404, "message": "Resource Not Found"}}), 404

@app.route("/Home")
def Home():
    return jsonify({"message": "Welcome to the Online Shop!"})

@app.route("/Creat_account",methods=["POST"])
def Creat_account():
    if request.method == "POST":
        email = request.json["email"]
        firstname = request.json["firstname"]
        lastname = request.json["lastname"]
        password1 = request.json["password1"]
        password2 = request.json["password1"]

        if not all([email,firstname,lastname,password1,password2]):
            return jsonify({"status": "error", "error": {"code": 400, "message": "Email and password are required"}}), 400

        Email_is_exists = users.find_one({"email":email})
        if Email_is_exists:
            return jsonify({"status":"error","error":{"code": 400, "message":"Email already exists"}})
        if not Email_is_exists:
            if len(password1) < 7:
                return jsonify({"status": "error", "error": {"code": 400, "message": "Password must be longer than 7 characters"}}), 400
            if password1 != password2:
                return jsonify({"status": "error", "error": {"code": 400, "message": "Confirm password is not correct"}}), 400
            if len(firstname) < 2:
                return jsonify({"status": "error", "error": {"code": 400, "message": "Firstname must be more than 2 Caractor"}}), 400

            hash_password = generate_password_hash(password1)
            secret = (uuid.uuid4())
            new_session = {
            "token" : secret,
            "exp" : datetime.now() + timedelta(hours=1)
            }

            
            new_user = {
            "email": email,
            "firstname": firstname,
            "lastname": lastname,
            "password": hash_password,
            "session_token" : new_session
        }
            
            users.insert_one(new_user)
            return jsonify({"status": "success", "code": 200, "data": {"message": "Create account successful", "session_token": new_session["token"]}}), 200
        
@app.route("/Login", methods=["POST"])
def Login():
    if request.method == "POST":
        email = request.json["email"]
        password = request.json["password"]
        
        if not email or not password:
            return jsonify({"status": "error", "error": {"code": 400, "message": "Email and password are required"}}), 400
        
        stored_user = users.find_one({"email": email})
        if not stored_user or not check_password_hash(stored_user["password"], password):
            return jsonify({"status": "error", "error": {"code": 400, "message": "Invalid email or password"}}), 400
        secret = str(uuid.uuid4())
        new_session = {
            "token" : secret,
            "exp" : datetime.now() + timedelta(hours=1)
        }

        users.update_one({"email": email}, {"$set": {"session_token": new_session}})
        
        session["email"] = email

        return jsonify({"status": "success", "code": 200, "data": {"message": "Login successful", "token": new_session}}), 200

@app.route("/logout", methods=["POST"])
def logout():
    email = session.pop("email", None)
    if email:
        users.update_one({"email":email},{"$unset":{"session_token":" "}})
        return jsonify({"status": "success", "success": {"code": 200, "message": "Logged out successfully"}}), 200
    return jsonify({"status": "error", "error": {"code": 400, "message": "No active session"}}), 400

@app.route("/Froget_Password", methods=["POST"])
def Froget_Password():
    if request.method == "POST":
        email = request.json["email"]
        new_password1 = request.json["new_password1"]
        new_password2 = request.json["new_password2"]

        if not all([email,new_password1,new_password2,]):
            return jsonify({"status": "error", "error": {"code": 400, "message": "Email and password are required"}}), 400
        
        Email_is_exists = users.find_one({"email":email})
        if Email_is_exists:
            if len(new_password1) < 7:
                return jsonify({"status": "error", "error": {"code": 400, "message": "Password must be longer than 7 characters"}}), 400
            if new_password1 != new_password2:
                return jsonify({"status": "error", "error": {"code": 400, "message": "Confirm password is not correct"}}), 400
       
            hash_password = generate_password_hash(new_password1)
            
            users.update_one(
                {"email":email},
                {"$set":{"password":hash_password}}
            )

        return jsonify({"status": "success", "success": {"code": 200, "message": "Password change successfully"}}), 200

@app.route("/delete_user", methods=["DELETE"])
def delete_user():
    if request.method == "DELETE":
        email = request.json["email"]
        if not email:
            return jsonify({"status": "error", "error": {"code": 400, "message": "Email is required"}}), 400
        
        Email_is_exists = users.find_one({"email":email})
        if Email_is_exists:
            users.delete_one({"email": email})
            return jsonify({"status": "success", "success": {"code": 200, "message": "User deleted successfully"}}), 200
        

IMAGE_UPLOAD_FOLDER = "images"
os.makedirs(IMAGE_UPLOAD_FOLDER, exist_ok=True)

@app.route("/create_product", methods=["POST"])
def create_product():
    name = request.form.get("name")
    price = request.form.get("price")
    description = request.form.get("description")
    quantity = request.form.get("quantity")
    mime_type = request.form.get("mime_type")
    image = request.files.get("image")

    if not all([name, price, description, quantity, mime_type]):
        return jsonify({"status": "error", "error": {"code": 400, "message": "All fields are required"}}), 400

    file_extension = "png" if mime_type == "image/png" else "jpg"
    random_filename = f"{uuid.uuid4()}.{file_extension}"
    image_path = os.path.join(IMAGE_UPLOAD_FOLDER, random_filename)

    try:
        image.save(image_path)
    except Exception as e:
        return jsonify({"status": "error", "error": {"code": 500, "message": f"Failed to save image: {str(e)}"}}), 500

    new_product = {
        "name": name,
        "price": float(price),
        "description": description,
        "quantity": int(quantity),
        "image": image_path
    }

    try:
        product.insert_one(new_product)
    except Exception as e:
        return jsonify({"status": "error", "error": {"code": 500, "message": f"Failed to add product to the database: {str(e)}"}}), 500

    return jsonify({"status": "success", "success": {"code": 200, "message": "Product created successfully"}}), 200

@app.route("/update_product", methods=["POST"])
def update_product():
    if request.method == "POST":
        name = request.form.get("name")
        price = request.form.get("price")
        description = request.form.get("description")
        quantity = request.form.get("quantity")
        mime_type = request.form.get("mime_type")
        image = request.files.get("image")

        if not all([name, price, description, quantity, mime_type]):
            return jsonify({"status": "error", "error": {"code": 400, "message": "All fields are required"}}), 400

        Product_is_exists = product.find_one({"name":name})
        if Product_is_exists:
            file_extension = "png" if mime_type == "image/png" else "jpg"
            random_filename = f"{uuid.uuid4()}.{file_extension}"
            image_path = os.path.join(IMAGE_UPLOAD_FOLDER, random_filename)

            try:
                image.save(image_path)
            except Exception as e:
                return jsonify({"status": "error", "error": {"code": 500, "message": f"Failed to save image: {str(e)}"}}), 500
            
            try:
                product.update_many(
                {"name": name},
                {"$set": {
                "price": float(price),
                "description": description,
                "quantity": int(quantity),
                "image": image_path
                }}
            )
                return jsonify({"status": "success", "success": {"code": 200, "message": "Product updated successfully"}}), 200
            except Exception as e:
                return jsonify({"status": "error", "error": {"code": 500, "message": f"Failed to update product: {str(e)}"}}), 500
        else:
            return jsonify({"status": "error", "error": {"code": 400, "message": "Product dose not find"}}), 400

@app.route("/delete_product", methods=["DELETE"])
def delete_product():
    if request.method == "DELETE":
        _id = request.json["_id"]

        if not _id:
            return jsonify({"status": "error", "error": {"code": 400, "message": "ID is required"}}), 400
        
        try:
            _id = ObjectId(_id)  
        except Exception as e:
            return jsonify({"status": "error", "error": {"code": 400, "message": "Invalid ID format"}}), 400

        Product_is_exists = product.find_one({"_id": _id})

        if Product_is_exists:
            product.delete_one({"_id": _id})
            return jsonify({"status": "success", "success": {"code": 200, "message": "Product deleted successfully"}}), 200
        else:
            return jsonify({"status": "error", "error": {"code": 404, "message": "Product not found"}}), 404

app.route("/list_product", methods=["GET"])
def product_list():
    try:
        product_list = list(product.find({},{"_id":0}))
        return jsonify({"status":"success","success":{"code":"200","data":product_list}})
    
    except errors.PyMongoError as e:
        logging.error(f"Failed to list product:{str(e)}")
        return jsonify({"status": "error", "error": {"code": 500, "message": "Internal Server Error"}}), 500
    
@app.route("/add_to_basket", methods=["POST"])
def add_to_basket():
    session_token = re.sub(r'[^a-zA-Z0-9-_]', '', request.headers.get('Session-Token', ''))
    product_id = request.json["product_id"]

    user = users.find_one({"session_token.token":session_token})
    if not user:
        return jsonify({"status":"error","error":{"code":400,"message":"Invalid session token"}}), 400
    
    product_exists = product.find_one({"_id": ObjectId(product_id)})
    if not product_exists:
        return jsonify({"status": "error", "error": {"code": 400, "message": "Product not found"}}), 400
    
    if product_exists ["quantity"] < 1 :
        return jsonify({"status": "error", "error": {"code": 400, "message": "not enough quantity"}}), 400
    
    user_basket = basket.find_one({"_id":user["_id"]})
    item_price = product_exists ["price"]

    if user_basket:
        basket_item = user_basket.get("items",{})
        total_price = user_basket.get("total_price",0)
        existing_quantity = basket_item.get(product_id,{}).get("quantity",0)
        new_quantity = existing_quantity + 1
        new_total_price = new_quantity * item_price
        basket_item[product_id] = {"quantity": new_quantity, "total_price": new_total_price}
        total_price += item_price
        basket.update_one({"_id":user["_id"]},{"$set":{"items":basket_item,"total_price":total_price}})
    else:
        total_price = item_price
        basket.insert_one({"_id":user["_id"], "items": {product_id: {"quantity": 1, "total_price": item_price}}, "total_price": total_price}) 

    return jsonify({"status": "success", "success": {"code": 200, "message": f"Product added to basket. Total Price:{total_price}"}}), 200

@app.route("/remove_from_basket", methods=["DELETE"])
def remove_from_basket():
    try:
        session_token = re.sub(r'[^a-zA-Z0-9-_]', '', request.headers.get('Session-Token', ''))
        product_id = request.json["product_id"]
        user = users.find_one({"session_token.token":session_token})
        if not user:
            return jsonify({"status":"error","error":{"code":400,"message":"All  are required"}}), 400
        if not all([session_token,product_id]):
            return jsonify({"status": "error", "error": {"code": 400, "message": "All fields are required"}}), 400

        product_exists = product.find_one({"_id": ObjectId(product_id)})
        if not product_exists:
            return jsonify({"status": "error", "error": {"code": 400, "message": "Product not found"}}), 400
        
        user_basket = basket.find_one({"_id":user["_id"]})
        if not user_basket:
            return jsonify({"status": "error", "error": {"code": 400, "message": "Basket not found"}}), 400
        
        items = user_basket.get("items" ,{})
        if product_id not in items:
            return jsonify({"status": "error", "error": {"code": 400, "message": "Product not in basket"}}), 400
        
        del items[product_id]
        new_total_price = sum(item["total_price"] for item in items.values())

        if items:
            basket.update_one({"_id":user["_id"]},{"$set":{"items":items,"total_price":new_total_price}})
        else:
            basket.delete_one({"_id":user["_id"]})

        return jsonify({"status": "success", "success": {"code": 200, "message": "Removed from basket successfully"}}), 200
        
    except Exception as e:
        logging.error(f"Error removing from basket: {str(e)}")
        return jsonify({"status": "error", "error": {"code": 500, "message": "An error occurred while removing from basket"}}), 500

@app.route("/view_basket", methods=["GET"])
def view_basket():
    user_id = request.json["user_id"]
    if not user_id:
        return jsonify({"status":"error","error":{"code":400,"message":"All fields are required"}}), 400
    user_basket = basket.find_one({"user_id":user_id})
    if not user_basket:
        return jsonify({"status":"error","error":{"code":400,"message":"basket is empty"}}), 400
    else:
        return user_basket

@app.route("/checkout", methods=["POST"])
def checkout():
    session_token = re.sub(r'[^a-zA-Z0-9-_]', '', request.headers.get('Session-Token', ''))
    address = request.json["address"]
    phone = request.json["phone"]
    comment = request.json["comment"]
    firstname = request.json["firstname"]

    user = users.find_one({"session_token.token":session_token})
    if not user:
        return jsonify({"status":"error","error":{"code":400,"message":"Invalid session token"}}), 400
    
    user_basket = basket.find_one({"_id":user["_id"]})  

    if not all ([session_token,address,phone,firstname]):
        return jsonify({"status":"error","error":{"code":400,"message":"All fields are required"}}), 400
    
    if not user_basket:
        return jsonify({"status":"error","error":{"code":400,"message":"basket is empty"}}), 400
    
    basket_items = user_basket.get("items",{})
    total_price = user_basket.get("total_price",0)

    if not basket_items:
        return jsonify({"status":"error","error":{"code":400,"message":"basket is empty"}}), 400
    
    for product_id, items_data in basket_items.items():
        product_is_exists = product.find_one({"_id":ObjectId(product_id)})
        if product_is_exists:
            available_quantity = product_is_exists["quantity"]
            basket_quantity = items_data["quantity"]
            if basket_quantity > available_quantity:
                return jsonify({"status":"error","error":{"code":400,"message":f"Not enough quantity for {product['name']}. Only {available_quantity} left."}}), 400
            
            new_quantity = product_is_exists["quantity"] - items_data["quantity"]
            new_reserved = product_is_exists.get("reserved",0) + items_data["quantity"]
            product.update_one({"_id":ObjectId(product_id)},{"$set":{"quantity":new_quantity, "reserved":new_reserved}})

            order_id = str(uuid.uuid4())[:8]
            order_time = datetime.utcnow()
            order_data = {
                "order_id": order_id,
                "user_id": str(user["_id"]),
                "items": basket_items,
                "total_price": total_price,
                "comment": comment,
                "address": address,
                "firstname": firstname,
                "phone": phone,
                "payment_status": "pending",
                "order_time": order_time
            }

            order.insert_one(order_data)
            user_info = users.find_one({"session_token.token":session_token})

            if address or phone not in user_info.get("address",[]):
                users.update_one({"_id":user_info["_id"]},{"$push":{"addresses":address}})
                users.update_one({"_id":user_info["_id"]},{"$set":{"phone":phone}})
           
            basket.delete_one({"_id":user["_id"]})
            
            return {
                "order_id":order_id,
                "total_price":total_price,
                "order_time":order_time.strftime('%Y-%m-%d %H:%M:%S.%f')
            }

@app.route("/reject_order",methods=["POST"])
def reject_order():
    session_token = re.sub(r'[^a-zA-Z0-9-_]', '', request.headers.get('Session-Token', ''))
    order_id = request.json["order_id"]

    user = users.find_one({"session_token.token":session_token})
    if not user:
        return jsonify({"status":"error","error":{"code":400,"message":"Invalid session token"}}), 400

    if not all([session_token,order_id]):
        return jsonify({"status":"error","error":{"code":400,"message":"All fields are required"}}), 400
    
    user_order = order.find_one({"order_id": order_id, "user_id": str(user["_id"])})
    if not user_order:
        return jsonify({"status": "error", "error": {"code": 400, "message": "Order not found"}}), 400
    order_items = user_order.get("items",{})

    for product_id, item_data in order_items.items():
        product_is_exists = product.find_one({"_id":ObjectId(product_id)})
        if not product_is_exists:
            continue
        reserved_quantity = product_is_exists.get("reserved",0) - item_data["quantity"]
        quantity = product_is_exists["quantity"] + item_data["quantity"]
        product.update_one({"_id": ObjectId(product_id)}, {"$set": {"reserved": reserved_quantity, "quantity": quantity}})

    order.update_one({"order_id": order_id}, {"$set": {"payment_status": "rejected"}})
    return jsonify({"status": "success", "success": {"code": 200, "message": "Removed from order successfully"}}), 200

if __name__ == "__main__":
    app.run(debug=True)
