from flask import Blueprint, request
from api.routes.auth import auth_bp
from api.routes.matching import matching_bp, init_socket_events

api:Blueprint = Blueprint('api', __name__)
api.register_blueprint(auth_bp, url_prefix='/auth')
api.register_blueprint(matching_bp, url_prefix='/match')

def init_sockets(socketio):
    init_socket_events(socketio)
