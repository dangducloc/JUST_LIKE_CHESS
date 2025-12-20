# frontends/routes/index.py
from flask import Blueprint
from frontends.routes.auth import auth_frontend_bp
from frontends.routes.matching import matching_frontend_bp
from frontends.routes.review import review_frontends_bp

fe_bp:Blueprint = Blueprint('fe', __name__)
fe_bp.register_blueprint(auth_frontend_bp, url_prefix='/')
fe_bp.register_blueprint(matching_frontend_bp, url_prefix='/')
fe_bp.register_blueprint(review_frontends_bp, url_prefix="/")
