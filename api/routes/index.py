from flask import Blueprint, request, jsonify
from api.routes.auth import auth_bp

api:Blueprint = Blueprint('api', __name__)
api.register_blueprint(auth_bp, url_prefix='/auth')
