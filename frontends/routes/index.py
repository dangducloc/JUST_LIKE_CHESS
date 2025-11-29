from flask import Blueprint
from frontends.routes.auth import auth_fe
from frontends.routes.statics import statics_css, statics_js
from frontends.routes.dashboards import dash_fe

fe:Blueprint = Blueprint('fe', __name__)
fe.register_blueprint(auth_fe)
fe.register_blueprint(statics_css)
fe.register_blueprint(statics_js)
fe.register_blueprint(dash_fe)
