import secrets
from flask import Blueprint, request, jsonify, make_response, Response
from Models.user_model import User, UserStatus
from controllers.users.users_controller import find_user, add_user,change_user_status
from bson import ObjectId
from DB.connect import user_col,pending_col
from services.mail import send_confirmation_email

auth_bp: Blueprint = Blueprint('auth', __name__)
user_status: UserStatus = UserStatus

# ========== LOGIN ==========
@auth_bp.route('/login', methods=['POST'])
def login() -> Response:
    data: dict = request.get_json() or {}
    mail: str = data.get('mail')
    passwd: str = data.get('password')

    id_user: ObjectId | None = find_user(mail, passwd)
    change_user_status(user_id=id_user, status=user_status.IDLE)
    if id_user:
        payload = {"message": "Login successful", "user_id": str(id_user)}
        res: Response = make_response(jsonify(payload), 200)
        res.set_cookie(key="user_id", value=str(id_user), httponly=True, samesite="Lax",max_age=3600)
        return res
    else:
        return make_response(jsonify({"message": "Invalid credentials"}), 401)

# ========== REGISTER ==========
@auth_bp.route('/register', methods=['POST'])
def register() -> Response:
    data = request.get_json() or {}
    mail = data.get('mail')
    passwd = data.get('password')
    name = data.get('name')

    if not mail or not passwd or not name:
        return make_response(jsonify({"message": "Missing required fields"}), 400)

    if user_col.find_one({"mail": mail}) or pending_col.find_one({"mail": mail}):
        return make_response(jsonify({"message": "Email already registered"}), 409)

    token = secrets.token_urlsafe(32)

    pending_col.insert_one({
        "name": name,
        "mail": mail,
        "passwd": passwd,
        "token": token
    })

    send_confirmation_email(mail, token)

    return make_response(jsonify(
        {
            "message": "Registration started. Please confirm via email.",
            "confirm_link":f"http://localhost:5000/api/auth/confirm/{token}",
            "token": token
        }), 201)

# ========== CONFIRM ==========
@auth_bp.route('/confirm/<token>', methods=['GET'])
def confirm_email(token: str) -> Response:
    pending_user = pending_col.find_one({"token": token})
    if not pending_user:
        return make_response(jsonify({"message": "Invalid or expired token"}), 400)

    # Create real user
    new_user = User(
        name=pending_user["name"],
        mail=pending_user["mail"],
        passwd=pending_user["passwd"]
    )
    if not add_user(new_user):
        return jsonify({"message": "Failed to create user"}), 500

    # Delete from pending
    pending_col.delete_one({"_id": pending_user["_id"]})

    return make_response(jsonify({"message": "✅ Email confirmed. Account created."}), 201)

# ========== LOGOUT ==========
@auth_bp.route('/logout', methods=['POST', 'GET', 'DELETE', 'PUT', 'PATCH'])
def logout() -> Response:
    user_id = request.cookies.get("user_id")
    if not user_id:
        return jsonify({"message": "No user logged in"}), 400

    change_user_status(user_id=ObjectId(user_id), status=user_status.OFFLINE)

    res: Response = make_response(jsonify(
        {
            "message": "Logout successful",
            "user_id": user_id
        }), 200)
    res.delete_cookie("user_id")
    res.delete_cookie("csrf_token")
    return res
