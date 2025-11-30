# web.py 
from flask import Flask
from flask_mail import Mail
from flask_cors import CORS
from api.routes.index import api
from frontends.routes.index import fe_bp
from utils.validators import register_error_handlers
from DB.connect import db_instance
import os
from dotenv import load_dotenv, find_dotenv
import logging

# Load environment variables
load_dotenv(find_dotenv())

# ============ CONFIGURATION ============
class Config:
    """Base configuration"""
    SECRET_KEY = os.getenv('SECRET_KEY', 'linh')
    JWT_SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'linh')
    
    # Mail config
    MAIL_SERVER = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.getenv('MAIL_PORT', 587))
    MAIL_USE_TLS = os.getenv('MAIL_USE_TLS', 'True') == 'True'
    MAIL_USERNAME = os.getenv('MAIL')
    MAIL_PASSWORD = os.getenv('APP_PASS')
    MAIL_DEFAULT_SENDER = ('Chess App', os.getenv('MAIL', 'fak'))
    
    # CORS config
    CORS_ORIGINS = os.getenv('CORS_ORIGINS', 'http://localhost:5000').split(',')

class DevelopmentConfig(Config):
    DEBUG = True
    TESTING = False

class ProductionConfig(Config):
    DEBUG = False
    TESTING = False

class TestingConfig(Config):
    DEBUG = True
    TESTING = True

config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}

# ============ APPLICATION FACTORY ============
def create_app(config_name='default'):
    """Application factory pattern"""
    app = Flask(__name__)
    
    # Load config
    app.config.from_object(config[config_name])
    
    # Setup logging
    if not app.debug:
        logging.basicConfig(level=logging.INFO)
    
    # Initialize extensions
    mail = Mail(app)
    
    # Setup CORS
    CORS(app, 
         resources={r"/api/*": {"origins": app.config['CORS_ORIGINS']}},
         supports_credentials=True,
         allow_headers=['Content-Type', 'Authorization'],
         methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
    
    # Register blueprints
    app.register_blueprint(api, url_prefix='/api')
    app.register_blueprint(fe_bp, url_prefix='/')

    # Register error handlers
    register_error_handlers(app)
    
    # Health check endpoint
    @app.route('/health')
    def health():
        return {"status": "ok", "database": "connected"}, 200
    
    @app.route('/')
    def home():
        return {"message": "Chess API is running", "version": "1.0.0"}, 200
    
    # Cleanup on shutdown
    @app.teardown_appcontext
    def shutdown_db(error):
        if error:
            app.logger.error(f"App context error: {error}")
    
    return app

# ============ RUN APPLICATION ============
if __name__ == '__main__':
    env = os.getenv('FLASK_ENV', 'development')
    app = create_app(env)
    
    host = os.getenv('HOST', '0.0.0.0')
    port = 5000
    
    app.run(
        host=host,
        port=port,
        debug=app.config['DEBUG']
    )