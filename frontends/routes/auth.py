from flask import Blueprint, render_template
auth_fe = Blueprint('auth_fe', __name__, template_folder='../templates/auth')

# ===== LOGIN ROUTES =====
@auth_fe.route('/login', methods=['GET'])
def login():
    return render_template('login.html')
# ===== REGISTER ROUTES =====
@auth_fe.route('/register', methods=['GET'])
def register():
    return render_template('register.html')
# ===== CONFIRM ROUTES =====
@auth_fe.route('/confirm', methods=['GET'])
def confirm():
    return render_template('comfirm.html')


