# api/routes/auth.py 
import secrets
from flask import Blueprint, request, jsonify, make_response, Response
from Models.user_model import User, UserStatus
from controllers.users.users_controller import find_user, add_user, change_user_status
from bson import ObjectId
from DB.connect import user_col, pending_col
from services.mail import send_confirmation_email
from functools import wraps
import jwt
from datetime import datetime, timedelta
import os

auth_bp = Blueprint('auth', __name__)
SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'linh')

# ============ MIDDLEWARE ============
def require_auth(f):
    """Decorator to protect routes"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('access_token')
        if not token:
            return jsonify({"message": "Authentication required"}), 401
        
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            request.user_id = ObjectId(payload['user_id'])
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token"}), 401
        
        return f(*args, **kwargs)
    return decorated

# ============ LOGIN ============
@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    mail = data.get('mail', '').strip()
    passwd = data.get('password', '')

    # Input validation
    if not mail or not passwd:
        return jsonify({"message": "Email and password required"}), 400

    # Find user
    user_id = find_user(mail, passwd)
    if not user_id:
        return jsonify({"message": "Invalid credentials"}), 401

    # Update status
    change_user_status(user_id=user_id, status=UserStatus.IDLE)

    # Generate JWT token instead of plain user_id
    token = jwt.encode({
        'user_id': str(user_id),
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, SECRET_KEY, algorithm='HS256')

    res = make_response(jsonify({
        "message": "Login successful",
        "user_id": str(user_id)
    }), 200)
    
    # Secure cookie settings
    res.set_cookie(
        key="access_token",
        value=token,
        httponly=True,      # Prevent XSS
        secure=True,        # HTTPS only (set False for localhost dev)
        samesite="Strict",  # CSRF protection
        max_age=86400       # 24 hours
    )
    
    return res

# ============ REGISTER ============
@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    mail = data.get('mail', '').strip().lower()
    passwd = data.get('password', '')
    name = data.get('name', '').strip()

    # Enhanced validation
    if not mail or not passwd or not name:
        return jsonify({"message": "Missing required fields"}), 400
    
    if len(passwd) < 8:
        return jsonify({"message": "Password must be at least 8 characters"}), 400
    
    if len(name) < 2 or len(name) > 50:
        return jsonify({"message": "Name must be 2-50 characters"}), 400

    # Check duplicates
    if user_col.find_one({"mail": mail}):
        return jsonify({"message": "Email already registered"}), 409
    
    if pending_col.find_one({"mail": mail}):
        return jsonify({"message": "Registration pending. Check your email"}), 409

    # Generate secure token
    token = secrets.token_urlsafe(32)
    expire_at = datetime.utcnow() + timedelta(seconds=10)

    # Store pending user
    pending_col.insert_one({
        "name": name,
        "mail": mail,
        "passwd": passwd,
        "token": token,
        "expireAt": expire_at
    })

    # Send confirmation email
    send_confirmation_email(mail, token)

    return jsonify({
        "message": "Registration started. Please confirm via email.",
        "confirm_link": f"http://localhost:5000/api/auth/confirm/{token}"
    }), 201

# ============ CONFIRM (UNCHANGED) ============
@auth_bp.route('/confirm/<token>', methods=['GET'])
def confirm_email(token):
    pending_user = pending_col.find_one({"token": token})
    if not pending_user:
        return jsonify({"message": "Invalid or expired token"}), 400

    new_user = User(
        name=pending_user["name"],
        mail=pending_user["mail"],
        passwd=pending_user["passwd"]
    )
    
    if not add_user(new_user):
        return jsonify({"message": "Failed to create user"}), 500

    pending_col.delete_one({"_id": pending_user["_id"]})
    
    return jsonify({"message": " Email confirmed. Account created."}), 201

# ============ LOGOUT ============
@auth_bp.route('/logout', methods=['POST'])
@require_auth
def logout():
    user_id = request.user_id
    change_user_status(user_id=user_id, status=UserStatus.OFFLINE)

    res = make_response(jsonify({
        "message": "Logout successful"
    }), 200)
    
    # Clear all auth cookies
    res.delete_cookie("access_token")
    res.delete_cookie("user_id")
    
    return res

# ============ GET CURRENT USER ============
@auth_bp.route('/me', methods=['GET'])
@require_auth
def get_current_user():
    """New endpoint to get current user info"""
    user = user_col.find_one({"_id": request.user_id})
    if not user:
        return jsonify({"message": "User not found"}), 404
    
    return jsonify({
        "user_id": str(user["_id"]),
        "name": user["name"],
        "mail": user["mail"],
        "elo": user["elo"],
        "status": user["status"]
    }), 200