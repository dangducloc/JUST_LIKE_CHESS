from flask import Blueprint
from api.routes.auth import auth_bp
from api.routes.matching import matching_bp
from api.routes.match import match_bp

api:Blueprint = Blueprint('api', __name__)
api.register_blueprint(auth_bp, url_prefix='/auth')
api.register_blueprint(matching_bp, url_prefix='/matching')
api.register_blueprint(match_bp, url_prefix='/match')
