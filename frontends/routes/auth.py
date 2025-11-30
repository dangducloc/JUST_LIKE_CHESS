# frontends/routes/auth.py
from flask import Blueprint, render_template

auth_frontend_bp = Blueprint('auth_frontend', __name__,static_folder='../../static', template_folder='../../templates')

# =========== LOGIN PAGE ============
@auth_frontend_bp.route('/login', methods=['GET'], strict_slashes=False)
def login_page():
    return render_template('auth/login.html')

# =========== REGISTER PAGE ============
@auth_frontend_bp.route('/register', methods=['GET'], strict_slashes=False)
def register_page():
    return render_template('auth/register.html')

# =========== CONFIRM PAGE ============
@auth_frontend_bp.route('/confirm', methods=['GET'], strict_slashes=False)
def confirm_page():
    return render_template('auth/confirm.html')
