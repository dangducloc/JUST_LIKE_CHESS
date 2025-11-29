from flask import Blueprint, render_template
dash_fe = Blueprint('auth', __name__, template_folder='../templates/dashboards')

# ===== LOGIN ROUTES =====
@dash_fe.route('/', methods=['GET'])
def login():
    return render_template('home.html')



