# frontends/routes/auth.py
from flask import Blueprint, request, jsonify

auth_frontend_bp = Blueprint('auth_frontend', __name__,static_folder='../../static', template_folder='../../templates')

# =========== LOGIN PAGE ============
@auth_frontend_bp.route('/login', methods=['GET'])
def login_page():
    return auth_frontend_bp.send_static_file('login.html')

# =========== REGISTER PAGE ============
@auth_frontend_bp.route('/register', methods=['GET'])
def register_page():
    return auth_frontend_bp.send_static_file('register.html')

# =========== CONFIRM PAGE ============
@auth_frontend_bp.route('/confirm/', methods=['GET'])
def confirm_page():
    return auth_frontend_bp.send_static_file('confirm.html')