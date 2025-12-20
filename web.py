# web.py - Updated with WebSocket Support
from flask import Flask
from flask_mail import Mail
from flask_cors import CORS
from flask_socketio import SocketIO
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
    MAIL_DEFAULT_SENDER = ('Chess App', os.getenv('MAIL', 'noreply@chess.com'))
    
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

# Global SocketIO instance
socketio = None

# ============ APPLICATION FACTORY ============
def create_app(config_name='default'):
    """Application factory pattern with WebSocket support"""
    global socketio
    
    app = Flask(__name__)
    
    # Load config
    app.config.from_object(config[config_name])
    
    # Setup logging
    if not app.debug:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.DEBUG)
    
    logger = logging.getLogger(__name__)
    logger.info(f"Starting Chess App in {config_name} mode")
    
    # Initialize extensions
    mail = Mail(app)
    logger.info("[+] Mail initialized")
    
    # Initialize SocketIO with proper configuration
    socketio = SocketIO(
        app,
        cors_allowed_origins="*",  # TODO: Change in production
        async_mode='eventlet',
        logger=app.debug,
        engineio_logger=app.debug,
        ping_timeout=60,
        ping_interval=25
    )
    logger.info("[+] SocketIO initialized")
    
    # Setup CORS
    CORS(app, 
         resources={r"/api/*": {"origins": app.config['CORS_ORIGINS']}},
         supports_credentials=True,
         allow_headers=['Content-Type', 'Authorization'],
         methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'])
    logger.info("[+] CORS configured")
    
    # Register blueprints
    app.register_blueprint(api, url_prefix='/api')
    app.register_blueprint(fe_bp, url_prefix='/')
    logger.info("[+] Blueprints registered")
    
    # Register error handlers
    register_error_handlers(app)
    logger.info("[+] Error handlers registered")
    
    # Import and register WebSocket events
    # This must be after SocketIO initialization
    try:
        from api.routes import pvp
        pvp.register_socket_events(socketio)
        logger.info("[+] WebSocket events registered")
    except Exception as e:
        logger.error(f"[-] Failed to register WebSocket events: {e}")
        raise
    
    # Health check endpoint
    @app.route('/health')
    def health():
        return {
            "status": "ok", 
            "database": "connected",
            "websocket": "enabled"
        }, 200
    
    @app.route('/')
    def home():
        return {
            "message": "Chess API is running", 
            "version": "2.0.0-websocket",
            "features": ["REST API", "WebSocket", "Real-time Chess"]
        }, 200
    
    # Cleanup on shutdown
    @app.teardown_appcontext
    def shutdown_db(error):
        if error:
            app.logger.error(f"App context error: {error}")
    
    logger.info("[+] Application created successfully")
    return app, socketio

# ============ RUN APPLICATION ============
if __name__ == '__main__':
    env = os.getenv('FLASK_ENV', 'development')
    
    print("=" * 60)
    print(" CHESS APP - WebSocket Edition")
    print("=" * 60)
    print(f"Environment: {env}")
    print(f"Starting server...")
    print("=" * 60)
    
    app, socketio = create_app(env)
    
    host = os.getenv('HOST', '0.0.0.0')
    port = int(os.getenv('APP_PORT', 5000))
    
    print(f"[+] Server running on http://{host}:{port}")
    print(f"[+] WebSocket enabled at ws://{host}:{port}")
    print(f"[+] Socket.IO endpoint: http://{host}:{port}/socket.io/")
    print("=" * 60)
    print("[+] Ready to accept connections!")
    print("=" * 60)
    
    # Use socketio.run instead of app.run
    socketio.run(
        app,
        host=host,
        port=port,
        debug=app.config['DEBUG'],
        use_reloader=app.config['DEBUG'],
        log_output=True
    )