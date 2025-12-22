Repository: dangducloc/just_like_chess
Files analyzed: 48

Estimated tokens: 73.2k

Directory structure:
└── dangducloc-just_like_chess/
    ├── schemaScript.js
    ├── web.py
    ├── api/
    │   └── routes/
    │       ├── auth.py
    │       ├── index.py
    │       ├── match.py
    │       ├── matching.py
    │       └── review.py
    ├── controllers/
    │   ├── bot/
    │   │   └── bot_controller.py
    │   ├── matchs/
    │   │   └── match_controller.py
    │   ├── review/
    │   │   └── review_controller.py
    │   └── users/
    │       └── users_controller.py
    ├── DB/
    │   └── connect.py
    ├── frontends/
    │   └── routes/
    │       ├── auth.py
    │       ├── bot.py
    │       ├── index.py
    │       ├── matching.py
    │       ├── review.py
    │       └── static.py
    ├── Models/
    │   ├── bot_model.py
    │   ├── match_model.py
    │   └── user_model.py
    ├── services/
    │   └── mail.py
    ├── static/
    │   ├── css/
    │   │   ├── auth/
    │   │   │   └── auth.css
    │   │   ├── game/
    │   │   │   ├── game.css
    │   │   │   └── promotion.css
    │   │   ├── matching/
    │   │   │   └── matching.css
    │   │   └── review/
    │   │       └── review.css
    │   └── js/
    │       ├── auth/
    │       │   ├── confirm.js
    │       │   ├── login.js
    │       │   └── register.js
    │       ├── game/
    │       │   ├── bot_game.js
    │       │   ├── game.js
    │       │   └── promotion.js
    │       ├── matching/
    │       │   ├── bot_selection.js
    │       │   ├── matching.js
    │       │   └── recent_matches.js
    │       └── review/
    │           └── review.js
    ├── templates/
    │   ├── auth/
    │   │   ├── confirm.html
    │   │   ├── login.html
    │   │   └── register.html
    │   ├── game/
    │   │   ├── bot.html
    │   │   └── index.html
    │   ├── matching/
    │   │   └── index.html
    │   └── review/
    │       └── index.html
    ├── utils/
    │   ├── helper.py
    │   └── validators.py
    └── web_socket/
        ├── pve.py
        └── pvp.py


================================================
FILE: schemaScript.js
================================================
// ================= USER =================
db.createCollection("user", {
  validator: {
    $jsonSchema: {
      bsonType: "object",
      title: "user",
      required: ["_id", "name", "pass", "mail", "elo", "status"],
      properties: {
        _id: { bsonType: "objectId" },
        name: { bsonType: "string" },
        pass: { bsonType: "string" },   // hashed password
        mail: {
          bsonType: "string",
          description: "Must be a valid email"
        },
        elo: {
          bsonType: "int",
          minimum: 0,
          description: "ELO rating (default 400)"
        },
        status: {
          enum: ["idle", "playing", "offline"],
          description: "User status"
        }
      }
    }
  },
  validationLevel: "strict",
  validationAction: "error"
});

// Unique index cho email
db.user.createIndex({ mail: 1 }, { unique: true });


// ================= MATCH =================
db.createCollection("match", {
  validator: {
    $jsonSchema: {
      bsonType: "object",
      title: "match",
      required: ["_id", "black", "white", "status", "start"],
      properties: {
        _id: { bsonType: "objectId" },
        black: { bsonType: "objectId" },
        white: { bsonType: "objectId" },
        pgn: { bsonType: "string" },
        start: { bsonType: "date" },
        end: { bsonType: ["date", "null"] },
        status: {
          enum: ["ongoing", "white_win", "black_win", "draw"],
          description: "Current status of the match"
        }
      }
    }
  },
  validationLevel: "strict",
  validationAction: "error"
});


db.createCollection("pending_user", {
  validator: {
    $jsonSchema: {
      bsonType: "object",
      title: "pending_user",
      required: ["_id", "name", "mail", "pass", "token", "expireAt"],
      properties: {
        _id: { bsonType: "objectId" },
        name: { bsonType: "string" },
        mail: { bsonType: "string" },
        pass: { bsonType: "string" }, // hashed password
        token: { bsonType: "string" }, // random confirm token
        expireAt: { bsonType: "date" } // TTL index để tự xoá khi quá hạn
      }
    }
  }
});

db.pending_user.createIndex({ expireAt: 1 }, { expireAfterSeconds: 0 })



================================================
FILE: web.py
================================================
# web.py - Updated with WebSocket Support
from flask import Flask,redirect
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
from utils.helper import bot_initial_setup

logger = logging.getLogger(__name__)

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
     # Initial bot setup
    bot_initial_setup()
    logger.info("Bot initial setup completed")
    app = Flask(__name__)
    
    # Load config
    app.config.from_object(config[config_name])
    
    # Setup logging
    if not app.debug:
        logging.basicConfig(level=logging.INFO)
    else:
        logging.basicConfig(level=logging.DEBUG)
    
    logger.info(f"Starting Chess App in {config_name} mode")
    
    # Initialize extensions
    mail = Mail(app)
    logger.info("[+] Mail initialized")
    
    # Initialize SocketIO with proper configuration
    socketio = SocketIO(
        app,
        cors_allowed_origins="*",  
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
        from web_socket import pvp,pve
        pve.register_bot_socket_events(socketio)
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
    
    @app.route('/api')
    def home():
        return {
            "message": "Chess API is running", 
            "version": "2.0.0-websocket",
            "features": ["REST API", "WebSocket", "Real-time Chess"]
        }, 200
    @app.route('/')
    def frontend_home():
        return redirect('/home')
    
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


================================================
FILE: api/routes/auth.py
================================================
# api/routes/auth.py 
import secrets
from flask import Blueprint, request, jsonify, make_response, Response
from Models.user_model import User, UserStatus
from controllers.users.users_controller import find_user, add_user, change_user_status
from bson import ObjectId
from DB.connect import user_col, pending_col
from services.mail import send_confirmation_email
from functools import wraps
import jwt
from datetime import datetime, timedelta
import os

auth_bp = Blueprint('auth', __name__)
SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'linh')

# ============ MIDDLEWARE ============
def require_auth(f):
    """Decorator to protect routes"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('access_token')
        if not token:
            return jsonify({"message": "Authentication required"}), 401
        
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
            request.user_id = ObjectId(payload['user_id'])
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Invalid token"}), 401
        
        return f(*args, **kwargs)
    return decorated

# ============ LOGIN ============
@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    mail = data.get('mail', '').strip()
    passwd = data.get('password', '')

    # Input validation
    if not mail or not passwd:
        return jsonify({"message": "Email and password required"}), 400

    # Find user
    user_id = find_user(mail, passwd)
    if not user_id:
        return jsonify({"message": "Invalid credentials"}), 401

    # Update status
    change_user_status(user_id=user_id, status=UserStatus.IDLE)

    # Generate JWT token instead of plain user_id
    token = jwt.encode({
        'user_id': str(user_id),
        'exp': datetime.utcnow() + timedelta(hours=24)
    }, SECRET_KEY, algorithm='HS256')

    res = make_response(jsonify({
        "message": "Login successful",
        "user_id": str(user_id)
    }), 200)
    
    # Secure cookie settings
    res.set_cookie(
        key="access_token",
        value=token,
        httponly=True,      # Prevent XSS
        secure=True,        # HTTPS only (set False for localhost dev)
        samesite="Strict",  # CSRF protection
        max_age=86400       # 24 hours
    )
    
    return res

# ============ REGISTER ============
@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    mail = data.get('mail', '').strip().lower()
    passwd = data.get('password', '')
    name = data.get('name', '').strip()

    # Enhanced validation
    if not mail or not passwd or not name:
        return jsonify({"message": "Missing required fields"}), 400
    
    if len(passwd) < 8:
        return jsonify({"message": "Password must be at least 8 characters"}), 400
    
    if len(name) < 2 or len(name) > 50:
        return jsonify({"message": "Name must be 2-50 characters"}), 400

    # Check duplicates
    if user_col.find_one({"mail": mail}):
        return jsonify({"message": "Email already registered"}), 409
    
    if pending_col.find_one({"mail": mail}):
        return jsonify({"message": "Registration pending. Check your email"}), 409

    # Generate secure token
    token = secrets.token_urlsafe(32)
    expire_at = datetime.utcnow() + timedelta(seconds=10)

    # Store pending user
    pending_col.insert_one({
        "name": name,
        "mail": mail,
        "passwd": passwd,
        "token": token,
        "expireAt": expire_at
    })

    # Send confirmation email
    send_confirmation_email(mail, token)

    return jsonify({
        "message": "Registration started. Please confirm via email.",
        "confirm_link": f"http://localhost:5000/api/auth/confirm/{token}"
    }), 201

# ============ CONFIRM (UNCHANGED) ============
@auth_bp.route('/confirm/<token>', methods=['GET'])
def confirm_email(token):
    pending_user = pending_col.find_one({"token": token})
    if not pending_user:
        return jsonify({"message": "Invalid or expired token"}), 400

    new_user = User(
        name=pending_user["name"],
        mail=pending_user["mail"],
        passwd=pending_user["passwd"]
    )
    
    if not add_user(new_user):
        return jsonify({"message": "Failed to create user"}), 500

    pending_col.delete_one({"_id": pending_user["_id"]})
    
    return jsonify({"message": " Email confirmed. Account created."}), 201

# ============ LOGOUT ============
@auth_bp.route('/logout', methods=['POST'])
@require_auth
def logout():
    user_id = request.user_id
    change_user_status(user_id=user_id, status=UserStatus.OFFLINE)

    res = make_response(jsonify({
        "message": "Logout successful"
    }), 200)
    
    # Clear all auth cookies
    res.delete_cookie("access_token")
    res.delete_cookie("user_id")
    
    return res

# ============ GET CURRENT USER ============
@auth_bp.route('/me', methods=['GET'])
@require_auth
def get_current_user():
    """New endpoint to get current user info"""
    user = user_col.find_one({"_id": request.user_id})
    if not user:
        return jsonify({"message": "User not found"}), 404
    
    return jsonify({
        "user_id": str(user["_id"]),
        "name": user["name"],
        "mail": user["mail"],
        "elo": user["elo"],
        "status": user["status"]
    }), 200


================================================
FILE: api/routes/index.py
================================================
from flask import Blueprint
from api.routes.auth import auth_bp
from api.routes.matching import matching_bp
from api.routes.match import match_bp
from api.routes.review import review_bp

api:Blueprint = Blueprint('api', __name__)
api.register_blueprint(auth_bp, url_prefix='/auth')
api.register_blueprint(matching_bp, url_prefix='/matching')
api.register_blueprint(match_bp, url_prefix='/match')
api.register_blueprint(review_bp, url_prefix='/review')



================================================
FILE: api/routes/match.py
================================================
# api/routes/match.py
from flask import Blueprint, request, jsonify
from controllers.matchs.match_controller import (
    get_match, 
    update_match_pgn, 
    append_move_to_pgn,
    end_match, 
    resign_match,
    get_user_matches,
    get_user_stats,
    get_leaderboard,
    is_valid_player
)
from bson import ObjectId
from utils.helper import get_user_from_token
import logging

match_bp = Blueprint('match', __name__)
logger = logging.getLogger(__name__)
#helper


# ============ GET MATCH DETAILS ============
@match_bp.route('/<match_id>', methods=['GET'])
def get_match_details(match_id):
    """Get detailed information about a specific match"""
    user_id, error, status_code = get_user_from_token()
    if error:
        return jsonify(error), status_code
    
    try:
        match_obj_id = ObjectId(match_id)
    except Exception:
        return jsonify({"message": "Invalid match ID"}), 400
    
    # Verify player is in this match
    is_valid, error_msg = is_valid_player(match_obj_id, user_id)
    if not is_valid:
        return jsonify({"message": error_msg}), 403
    
    match = get_match(match_obj_id)
    if not match:
        return jsonify({"message": "Match not found"}), 404
    
    return jsonify({
        "match_id": str(match._id),
        "white": str(match.white),
        "black": str(match.black),
        "pgn": match.pgn,
        "status": match.status,
        "start": match.start.isoformat() if match.start else None,
        "end": match.end.isoformat() if match.end else None,
        "your_color": "white" if match.white == user_id else "black"
    }), 200

# ============ GET USER MATCH HISTORY ============
@match_bp.route('/history', methods=['GET'])
def match_history():
    """Get user's match history"""
    user_id, error, status_code = get_user_from_token()
    if error:
        return jsonify(error), status_code
    
    # Get pagination parameters
    limit = request.args.get('limit', 10, type=int)
    skip = request.args.get('skip', 0, type=int)
    
    # Limit max items per page
    limit = min(limit, 50)
    
    matches = get_user_matches(user_id, limit, skip)
    
    return jsonify({
        "matches": matches,
        "limit": limit,
        "skip": skip,
        "count": len(matches)
    }), 200

# ============ GET USER STATS ============
@match_bp.route('/stats', methods=['GET'])
def user_stats():
    """Get user's match statistics"""
    user_id, error, status_code = get_user_from_token()
    if error:
        return jsonify(error), status_code
    
    stats = get_user_stats(user_id)
    
    return jsonify(stats), 200

# ============ GET LEADERBOARD ============
@match_bp.route('/leaderboard', methods=['GET'])
def leaderboard():
    """Get top players leaderboard"""
    limit = request.args.get('limit', 10, type=int)
    limit = min(limit, 100)  # Max 100 players
    
    board = get_leaderboard(limit)
    
    return jsonify({
        "leaderboard": board,
        "count": len(board)
    }), 200


================================================
FILE: api/routes/matching.py
================================================
# api/routes/matching.py
from flask import Blueprint, request, jsonify, make_response
from Models.user_model import User, UserStatus
from Models.match_model import Match
from controllers.users.users_controller import change_user_status
from controllers.matchs.match_controller import create_match
from bson import ObjectId
from DB.connect import user_col, waiting_col, match_col
from datetime import datetime, timedelta
import logging
from utils.helper import get_user_from_token

matching_bp = Blueprint('matching', __name__)
logger = logging.getLogger(__name__)

#helper

# ============ MATCHMAKING QUEUE ============
class MatchmakingQueue:
    def __init__(self):
        self.queue = []  # [(user_id, elo, timestamp), ...]
        self.max_wait_time = 60  # seconds
        self.elo_range = 100
        self._load_from_db()
    
    def _load_from_db(self):
        """Load existing queue from DB on startup"""
        try:
            cutoff = datetime.utcnow() - timedelta(seconds=self.max_wait_time)
            entries = waiting_col.find({
                'created_at': {'$gte': cutoff}
            })
            
            for entry in entries:
                self.queue.append({
                    'user_id': entry['user_id'],
                    'elo': entry['elo'],
                    'timestamp': entry['created_at']
                })
            
            logger.info(f"Loaded {len(self.queue)} users from waiting queue")
        except Exception as e:
            logger.error(f"Error loading queue from DB: {e}")
    
    def add_user(self, user_id: ObjectId, elo: int) -> bool:
        """Add user to queue. Returns False if already in queue."""
        # Check if user already in queue
        if any(e['user_id'] == user_id for e in self.queue):
            logger.warning(f"User {user_id} already in queue")
            return False
        
        entry = {
            'user_id': user_id,
            'elo': elo,
            'timestamp': datetime.utcnow()
        }
        self.queue.append(entry)
        
        # Also add to DB for persistence
        try:
            waiting_col.insert_one({
                'user_id': user_id,
                'elo': elo,
                'created_at': datetime.utcnow(),
                'expire_at': datetime.utcnow() + timedelta(seconds=self.max_wait_time)
            })
            logger.info(f" User {user_id} added to queue (ELO: {elo})")
            return True
        except Exception as e:
            logger.error(f" Error adding user to DB: {e}")
            # Remove from memory if DB insert failed
            self.queue = [e for e in self.queue if e['user_id'] != user_id]
            return False
    
    def find_match(self, user_id: ObjectId, elo: int) -> ObjectId | None:
        """Find opponent for user"""
        # Clean expired entries first
        self._clean_expired()
        
        # Try to find match with increasing ELO range
        for multiplier in [1, 2, 3]:
            current_range = self.elo_range * multiplier
            
            for entry in self.queue:
                # Skip self
                if entry['user_id'] == user_id:
                    continue
                
                # Check ELO range
                if abs(entry['elo'] - elo) <= current_range:
                    opponent_id = entry['user_id']
                    
                    # Remove both from queue
                    self._remove_from_queue([user_id, opponent_id])
                    
                    logger.info(f" Match found: {user_id} vs {opponent_id} (ELO diff: {abs(entry['elo'] - elo)})")
                    return opponent_id
        
        return None
    
    def remove_user(self, user_id: ObjectId) -> bool:
        """Remove user from queue"""
        return self._remove_from_queue([user_id])
    
    def _remove_from_queue(self, user_ids: list[ObjectId]) -> bool:
        """Remove multiple users from queue"""
        try:
            # Remove from memory
            initial_count = len(self.queue)
            self.queue = [e for e in self.queue if e['user_id'] not in user_ids]
            removed_count = initial_count - len(self.queue)
            
            # Remove from DB
            result = waiting_col.delete_many({'user_id': {'$in': user_ids}})
            
            logger.info(f" Removed {removed_count} users from queue")
            return removed_count > 0
        except Exception as e:
            logger.error(f" Error removing users from queue: {e}")
            return False
    
    def _clean_expired(self):
        """Remove expired entries"""
        cutoff = datetime.utcnow() - timedelta(seconds=self.max_wait_time)
        expired = [e['user_id'] for e in self.queue if e['timestamp'] < cutoff]
        
        if expired:
            self._remove_from_queue(expired)
            logger.info(f"🧹 Cleaned {len(expired)} expired entries")
    
    def get_queue_status(self) -> dict:
        """Get queue statistics"""
        self._clean_expired()
        return {
            'total': len(self.queue),
            'users': [
                {
                    'user_id': str(e['user_id']),
                    'elo': e['elo'],
                    'wait_time': (datetime.utcnow() - e['timestamp']).seconds
                }
                for e in self.queue
            ]
        }

# Global queue instance
matchmaking_queue = MatchmakingQueue()

# ============ REST ENDPOINTS ============
@matching_bp.route('/find_match', methods=['POST'])
def find_match():
    """Add user to matchmaking queue"""
    # Get user from JWT
    user_id, error, status_code = get_user_from_token()
    if error:
        return jsonify(error), status_code
    
    try:
        # Get user from DB
        user = user_col.find_one({"_id": user_id})
        if not user:
            return jsonify({"message": "User not found"}), 404
        
        user_elo = user.get("elo", 1200)
        
        # Check if already in queue
        existing = waiting_col.find_one({"user_id": user_id})
        if existing:
            return jsonify({
                "message": "Already in queue",
                "status": "waiting",
                "elo": user_elo
            }), 200
        
        # Try to find immediate match
        opponent_id = matchmaking_queue.find_match(user_id, user_elo)
        
        if opponent_id:
            # Create match
            match = create_match(user_id, opponent_id)
            
            # Update user statuses
            change_user_status(user_id, UserStatus.PLAYING)
            change_user_status(opponent_id, UserStatus.PLAYING)
            
            # Get opponent info
            opponent = user_col.find_one({"_id": opponent_id})
            
            return jsonify({
                "message": "Match found!",
                "status": "matched",
                "match_id": str(match._id),
                "opponent": {
                    "id": str(opponent_id),
                    "name": opponent.get("name", "Unknown"),
                    "elo": opponent.get("elo", 1200)
                },
                "your_color": "white" if match.white == user_id else "black"
            }), 200
        else:
            # Add to queue
            if matchmaking_queue.add_user(user_id, user_elo):
                change_user_status(user_id, UserStatus.MATCHING)
                
                return jsonify({
                    "message": "Added to queue. Waiting for opponent...",
                    "status": "waiting",
                    "elo": user_elo,
                    "queue_position": len(matchmaking_queue.queue)
                }), 202
            else:
                return jsonify({"message": "Failed to join queue"}), 500
    
    except Exception as e:
        logger.error(f" Error in find_match: {e}")
        return jsonify({"message": "Internal error"}), 500

@matching_bp.route('/cancel_match', methods=['POST'])
def cancel_match():
    """Cancel matchmaking"""
    # Get user from JWT
    user_id, error, status_code = get_user_from_token()
    if error:
        return jsonify(error), status_code
    
    try:
        if matchmaking_queue.remove_user(user_id):
            change_user_status(user_id, UserStatus.IDLE)
            return jsonify({
                "message": "Matchmaking cancelled",
                "status": "idle"
            }), 200
        else:
            return jsonify({
                "message": "Not in queue",
                "status": "idle"
            }), 200
    
    except Exception as e:
        logger.error(f" Error in cancel_match: {e}")
        return jsonify({"message": "Internal error"}), 500

@matching_bp.route('/queue_status', methods=['GET'])
def queue_status():
    """Get matchmaking queue status"""
    # Get user from JWT (optional for this endpoint)
    user_id, _, _ = get_user_from_token()
    
    try:
        status = matchmaking_queue.get_queue_status()
        
        # Add user-specific info if authenticated
        if user_id:
            user_in_queue = waiting_col.find_one({"user_id": user_id})
            status['in_queue'] = user_in_queue is not None
            
            if user_in_queue:
                wait_time = (datetime.utcnow() - user_in_queue['created_at']).seconds
                status['your_wait_time'] = wait_time
        
        return jsonify(status), 200
    
    except Exception as e:
        logger.error(f" Error in queue_status: {e}")
        return jsonify({"message": "Internal error"}), 500

# ============ POLLING ENDPOINT ============
@matching_bp.route('/check_match', methods=['GET'])
def check_match():
    """
    Polling endpoint for frontend to check if match is found.
    Alternative to WebSocket for simpler implementation.
    """
    # Get user from JWT
    user_id, error, status_code = get_user_from_token()
    if error:
        return jsonify(error), status_code
    
    try:
        # Check if user is in an active match
        match = match_col.find_one({
            '$or': [
                {'white': user_id, 'status': 'ongoing'},
                {'black': user_id, 'status': 'ongoing'}
            ]
        })
        
        if match:
            opponent_id = match['black'] if match['white'] == user_id else match['white']
            opponent = user_col.find_one({"_id": opponent_id})
            # cookie
            res = make_response(jsonify({
                "status": "matched",
                "match_id": str(match['_id']),
                "opponent": {
                    "id": str(opponent_id),
                    "name": opponent.get("name", "Unknown"),
                    "elo": opponent.get("elo", 1200)
                },
                "your_color": "white" if match['white'] == user_id else "black"
            }), 200)
            res.set_cookie('match_id', str(match['_id']), httponly=True, samesite='Lax')
            return res
        
        # Check if still in queue
        in_queue = waiting_col.find_one({"user_id": user_id})
        
        if in_queue:
            wait_time = (datetime.utcnow() - in_queue['created_at']).seconds
            return jsonify({
                "status": "waiting",
                "wait_time": wait_time,
                "queue_size": len(matchmaking_queue.queue)
            }), 200
        
        # Not in queue and no active match
        return jsonify({
            "status": "idle"
        }), 200
    
    except Exception as e:
        logger.error(f" Error in check_match: {e}")
        return jsonify({"message": "Internal error"}), 500


================================================
FILE: api/routes/review.py
================================================
# api/route/review.py
import os
from dotenv import load_dotenv, find_dotenv
import jwt
from flask import Blueprint, jsonify
from bson import ObjectId
from controllers.review.review_controller import review_game
from controllers.matchs.match_controller import is_valid_player
from utils.helper import get_user_from_token
import logging

logger = logging.getLogger(__name__)

review_bp = Blueprint('review', __name__, url_prefix='/api/review')
@review_bp.route('/<match_id>', methods=['GET'])
def review_match(match_id):
    try:
        user_id, error, status_code = get_user_from_token()
        id = ObjectId(match_id)
        is_valid,msg = is_valid_player(match_id=id, user_id=user_id)
        if(not is_valid):
            logger.error(f"[-] Unauthorized access to match ID: {match_id}")
            return jsonify({"error": "Unauthorized access"}), 403
        
    except Exception as e:
        logger.error(f"[-] Invalid match ID: {match_id}, error: {e}")
        return jsonify({"error": "Invalid match ID"}), 400

    analysis = review_game(id)
    if analysis is None:
        return jsonify({"error": "Match not found or analysis failed"}), 404

    return analysis, 200


================================================
FILE: controllers/bot/bot_controller.py
================================================
import chess
import chess.engine
import random
import os
import time
import logging
from typing import Optional, Tuple
from bson import ObjectId
from datetime import datetime
from dotenv import load_dotenv
from Models.bot_model import BotMatch, BotProfile, BotDifficulty
from Models.user_model import User
from DB.connect import PyMongoError, user_col, match_col

load_dotenv()
logger = logging.getLogger(__name__)

STOCKFISH_PATH = os.getenv('STOCKFISH_PATH', '../../engine/stockfish.exe')

class ChessBot:
    """Chess bot using Stockfish engine"""
    
    def __init__(self, difficulty: str = BotDifficulty.MEDIUM):
        self.difficulty = difficulty
        self.settings = BotProfile.get_settings(difficulty)
        self.engine = None
        
    def __enter__(self):
        try:
            self.engine = chess.engine.SimpleEngine.popen_uci(STOCKFISH_PATH)
            logger.info(f"[+] Stockfish engine initialized for {self.difficulty} bot")
            return self
        except Exception as e:
            logger.error(f"[-] Failed to initialize Stockfish: {e}")
            raise
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.engine:
            self.engine.quit()
            logger.info("[+] Stockfish engine closed")
    
    def get_best_move(self, board: chess.Board) -> Optional[chess.Move]:
        if not self.engine:
            logger.error("Engine not initialized")
            return None
        
        try:
            time.sleep(self.settings["thinking_time"])
            
            depth = self.settings["depth"]
            result = self.engine.analyse(
                board,
                chess.engine.Limit(depth=depth),
                multipv=3
            )
            
            if random.random() < self.settings["error_rate"]:
                move_index = random.choice([1, 2])
                if len(result) > move_index and "pv" in result[move_index]:
                    move = result[move_index]["pv"][0]
                    logger.info(f"Bot making suboptimal move (error simulation)")
                    return move
            
            if result and "pv" in result[0]:
                return result[0]["pv"][0]
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting bot move: {e}")
            return None
    
    def make_move(self, fen: str) -> Tuple[Optional[str], Optional[str]]:
        try:
            board = chess.Board(fen)
            
            if board.is_game_over():
                logger.warning("Game is already over")
                return None, None
            
            best_move = self.get_best_move(board)
            
            if not best_move:
                logger.error("No move found")
                return None, None
            
            san_move = board.san(best_move)
            board.push(best_move)
            
            logger.info(f"Bot move: {san_move} (depth: {self.settings['depth']})")
            
            return san_move, board.fen()
            
        except Exception as e:
            logger.error(f"Error making bot move: {e}")
            return None, None


def create_bot_match(player_id: ObjectId, difficulty: str, player_color: str) -> BotMatch:
    try:
        bot_match = BotMatch(
            player_id=player_id,
            bot_difficulty=difficulty,
            player_color=player_color,
            status="ongoing"
        )
        
        result = match_col.insert_one(bot_match.to_dict())
        bot_match._id = result.inserted_id
        
        logger.info(f"[+] Bot match created: {bot_match._id}")
        logger.info(f"  Player: {player_id}, Difficulty: {difficulty}, Color: {player_color}")
        
        return bot_match
        
    except PyMongoError as e:
        logger.error(f"[-] Error creating bot match: {e}")
        raise


def get_bot_match(match_id: ObjectId) -> Optional[BotMatch]:
    try:
        data = match_col.find_one({"_id": match_id})
        if data and "bot_difficulty" in data:
            return BotMatch.from_dict(data)
        return None
    except PyMongoError as e:
        logger.error(f"[-] Error getting bot match: {e}")
        return None


def update_bot_match_pgn(match_id: ObjectId, pgn: str) -> bool:
    try:
        result = match_col.update_one(
            {"_id": match_id},
            {"$set": {"pgn": pgn}}
        )
        return result.modified_count > 0
    except PyMongoError as e:
        logger.error(f"[-] Error updating bot match PGN: {e}")
        return False


def append_move_to_bot_pgn(match_id: ObjectId, move: str) -> bool:
    try:
        match_data = match_col.find_one({"_id": match_id})
        if not match_data:
            return False
        
        current_pgn = match_data.get("pgn", "")
        new_pgn = current_pgn + " " + move if current_pgn else move
        
        result = match_col.update_one(
            {"_id": match_id},
            {"$set": {"pgn": new_pgn.strip()}}
        )
        return result.modified_count > 0
    except PyMongoError as e:
        logger.error(f"[-] Error appending move to bot match: {e}")
        return False


def end_bot_match(match_id: ObjectId, result: str) -> bool:
    try:
        match_data = match_col.find_one({"_id": match_id})
        if not match_data or "bot_difficulty" not in match_data:
            logger.error("Not a bot match")
            return False
        
        player_data = user_col.find_one({"_id": match_data["player_id"]})
        if not player_data:
            logger.error("Player not found")
            return False
        
        player = User.from_dict(player_data)
        bot_elo = BotProfile.get_bot_elo(match_data["bot_difficulty"])
        
        if result == "player_win":
            result = f"{match_data['player_color']}_win"
            result_value = 1.0
        elif result == "bot_win":
            result = f"{'black' if match_data['player_color'] == 'white' else 'white'}_win"
            result_value = 0.0
        else:
            result = "draw"
            result_value = 0.5
        
        old_elo = player.elo
        player.update_elo(bot_elo, result_value)
        
        user_col.update_one(
            {"_id": player._id},
            {"$set": {"elo": player.elo, "status": "idle"}}
        )
        
        match_col.update_one(
            {"_id": match_id},
            {"$set": {
                "status": result,
                "end": datetime.utcnow()
            }}
        )
        
        logger.info(f"[+] Bot match ended: {match_id}")
        logger.info(f"  Result: {result}")
        logger.info(f"  Player ELO: {old_elo} → {player.elo} ({player.elo - old_elo:+d})")
        
        return True
        
    except PyMongoError as e:
        logger.error(f"[-] Error ending bot match: {e}")
        return False


def is_valid_bot_player(match_id: ObjectId, user_id: ObjectId) -> Tuple[bool, Optional[str]]:
    try:
        match = match_col.find_one({"_id": match_id})
        if not match:
            return False, "Match not found"
        
        if "bot_difficulty" not in match:
            return False, "Not a bot match"
        
        if match["status"] not in ["ongoing"]:
            return False, "Match is not ongoing"
        
        if match["player_id"] != user_id:
            return False, "You are not the player in this match"
        
        return True, None
    except Exception as e:
        logger.error(f"[-] Error validating bot player: {e}")
        return False, "Internal error"


================================================
FILE: controllers/matchs/match_controller.py
================================================
# controllers/matchs/match_controller.py 
from Models.match_model import Match
from Models.user_model import User
from DB.connect import match_col, user_col, PyMongoError
from bson import ObjectId
from datetime import datetime
import random
import logging

logger = logging.getLogger(__name__)

# ============ CREATE MATCH ============
def create_match(user1_id: ObjectId, user2_id: ObjectId) -> Match:
    """
    Create new match between two users.
    Randomly assigns white/black.
    """
    try:
        # Randomly assign colors
        if random.choice([True, False]):
            white_id, black_id = user1_id, user2_id
        else:
            white_id, black_id = user2_id, user1_id
        
        match = Match(
            white=white_id,
            black=black_id,
            status="ongoing"
        )
        
        result = match_col.insert_one(match.to_dict())
        match._id = result.inserted_id
        
        logger.info(f" Match created: {match._id}")
        logger.info(f"   White: {white_id}, Black: {black_id}")
        return match
    
    except PyMongoError as e:
        logger.error(f" Error creating match: {e}")
        raise

# ============ GET MATCH ============
def get_match(match_id: ObjectId) -> Match | None:
    """Get match by ID"""
    try:
        data = match_col.find_one({"_id": match_id})
        if data:
            return Match.from_dict(data)
        return None
    except PyMongoError as e:
        logger.error(f" Error getting match: {e}")
        return None

# ============ UPDATE MATCH ============
def update_match_pgn(match_id: ObjectId, pgn: str) -> bool:
    """Update match PGN"""
    try:
        result = match_col.update_one(
            {"_id": match_id},
            {"$set": {"pgn": pgn}}
        )
        if result.modified_count > 0:
            logger.info(f" Updated PGN for match {match_id}")
            return True
        return False
    except PyMongoError as e:
        logger.error(f" Error updating PGN: {e}")
        return False

def append_move_to_pgn(match_id: ObjectId, move: str) -> bool:
    """Append a single move to PGN"""
    try:
        match = match_col.find_one({"_id": match_id})
        if not match:
            return False
        
        current_pgn = match.get("pgn", "")
        new_pgn = current_pgn + " " + move if current_pgn else move
        
        result = match_col.update_one(
            {"_id": match_id},
            {"$set": {"pgn": new_pgn.strip()}}
        )
        return result.modified_count > 0
    except PyMongoError as e:
        logger.error(f" Error appending move: {e}")
        return False

# ============ END MATCH ============
def end_match(match_id: ObjectId, result: str) -> bool:
    """
    End match and update ELO ratings.
    result: 'white_win', 'black_win', 'draw'
    """
    try:
        match_data = match_col.find_one({"_id": match_id})
        if not match_data:
            logger.error(f"Match {match_id} not found")
            return False
        
        # Get users
        white_user_data = user_col.find_one({"_id": match_data["white"]})
        black_user_data = user_col.find_one({"_id": match_data["black"]})
        
        if not white_user_data or not black_user_data:
            logger.error("Users not found")
            return False
        
        white_user = User.from_dict(white_user_data)
        black_user = User.from_dict(black_user_data)
        
        # Calculate ELO changes
        white_result = 0.5  # draw
        if result == "white_win":
            white_result = 1.0
        elif result == "black_win":
            white_result = 0.0
        
        black_result = 1.0 - white_result
        
        # Store old ELO for logging
        old_white_elo = white_user.elo
        old_black_elo = black_user.elo
        
        # Update ELO
        white_user.update_elo(black_user.elo, white_result)
        black_user.update_elo(white_user.elo, black_result)
        
        # Save to database
        user_col.update_one(
            {"_id": white_user._id},
            {"$set": {"elo": white_user.elo, "status": "idle"}}
        )
        user_col.update_one(
            {"_id": black_user._id},
            {"$set": {"elo": black_user.elo, "status": "idle"}}
        )
        
        # Update match status
        match_col.update_one(
            {"_id": match_id},
            {"$set": {
                "status": result,
                "end": datetime.utcnow()
            }}
        )
        
        logger.info(f" Match ended: {match_id}, Result: {result}")
        logger.info(f"   White ELO: {old_white_elo} → {white_user.elo} ({white_user.elo - old_white_elo:+d})")
        logger.info(f"   Black ELO: {old_black_elo} → {black_user.elo} ({black_user.elo - old_black_elo:+d})")
        
        return True
    
    except PyMongoError as e:
        logger.error(f" Error ending match: {e}")
        return False

def resign_match(match_id: ObjectId, resigning_user_id: ObjectId) -> bool:
    """Handle resignation"""
    try:
        match_data = match_col.find_one({"_id": match_id})
        if not match_data:
            return False
        
        # Determine winner
        if match_data["white"] == resigning_user_id:
            result = "black_win"
        elif match_data["black"] == resigning_user_id:
            result = "white_win"
        else:
            return False
        
        return end_match(match_id, result)
    except Exception as e:
        logger.error(f" Error in resignation: {e}")
        return False

# ============ GET USER MATCHES ============
def get_user_matches(user_id: ObjectId, limit: int = 10, skip: int = 0) -> list[dict]:
    """Get user's match history with pagination"""
    try:
        matches = match_col.find(
            {"$or": [{"white": user_id}, {"black": user_id}]}
        ).sort("start", -1).skip(skip).limit(limit)
        
        result = []
        for match in matches:
            # Get opponent info
            opponent_id = match['black'] if match['white'] == user_id else match['white']
            opponent = user_col.find_one({"_id": opponent_id})
            
            result.append({
                "match_id": str(match["_id"]),
                "opponent_name": opponent.get("name", "Unknown") if opponent else "Unknown",
                "opponent_elo": opponent.get("elo", 1200) if opponent else 1200,
                "your_color": "white" if match['white'] == user_id else "black",
                "result": match.get("status", "ongoing"),
                "pgn": match.get("pgn", ""),
                "start": match.get("start"),
                "end": match.get("end")
            })
        
        return result
    except PyMongoError as e:
        logger.error(f" Error getting user matches: {e}")
        return []

# ============ GET MATCH STATS ============
def get_user_stats(user_id: ObjectId) -> dict:
    """Get user statistics"""
    try:
        matches = list(match_col.find(
            {"$or": [{"white": user_id}, {"black": user_id}]}
        ))
        
        total = 0
        wins = 0
        losses = 0
        draws = 0
        
        for match in matches:
            status = match.get("status")
            if status == "ongoing":
                continue
                
            total += 1
            
            if status == "draw":
                draws += 1
            elif (status == "white_win" and match["white"] == user_id) or \
                 (status == "black_win" and match["black"] == user_id):
                wins += 1
            else:
                losses += 1
        
        return {
            "total_games": total,
            "wins": wins,
            "losses": losses,
            "draws": draws,
            "win_rate": round(wins / total * 100, 2) if total > 0 else 0
        }
    
    except PyMongoError as e:
        logger.error(f" Error getting stats: {e}")
        return {
            "total_games": 0,
            "wins": 0,
            "losses": 0,
            "draws": 0,
            "win_rate": 0
        }

# ============ GET LEADERBOARD ============
def get_leaderboard(limit: int = 10) -> list[dict]:
    """Get top players by ELO"""
    try:
        users = user_col.find({
                            "$or": [
                                {"is_bot": {"$exists": False}},
                                {"is_bot": False}
                            ]
                            }).sort("elo", -1).limit(limit)
        
        leaderboard = []
        for rank, user in enumerate(users, 1):
            stats = get_user_stats(user["_id"])
            
            leaderboard.append({
                "rank": rank,
                "name": user["name"],
                "elo": user["elo"],
                "user_id": str(user["_id"]),
                "games_played": stats["total_games"],
                "win_rate": stats["win_rate"]
            })
        
        return leaderboard
    
    except PyMongoError as e:
        logger.error(f" Error getting leaderboard: {e}")
        return []

# ============ VALIDATE MOVE ============
def is_valid_player(match_id: ObjectId, user_id: ObjectId) -> tuple[bool, str | None]:
    """Check if user is a player in this match"""
    try:
        match = match_col.find_one({"_id": match_id})
        if not match:
            return False, "Match not found"
        # if match["status"] != "ongoing":
        #     return False, "Match is not ongoing"
        
        if user_id not in [match["white"], match["black"]]:
            return False, "You are not a player in this match"
        
        return True, None
    except Exception as e:
        logger.error(f" Error validating player: {e}")
        return False, "Internal error"
    


================================================
FILE: controllers/review/review_controller.py
================================================
# controller/review/review_controller.py
from chess import Board,engine,WHITE

from bson import ObjectId
from controllers.matchs.match_controller import get_match
from controllers.users.users_controller import get_user_by_id
from dotenv import load_dotenv, find_dotenv
import os
import logging
from typing import List, Dict, Any

load_dotenv(find_dotenv())
logger = logging.getLogger(__name__)
stockfish_path = os.getenv('STOCKFISH_PATH', '../../engine/stockfish.exe')
logger.info(f"stockfish path: {stockfish_path}")

# MAIN FUNCTION
def review_game(match_id:ObjectId)->dict|None:
    match = get_match(match_id)
    san_pgn = match.pgn
    if(san_pgn != ""):
        analysis = analyze_moves_simple(
            moves_san=san_pgn,
            engine_path=stockfish_path,
            depth=15
        )
        white = {
            "id": str(match.white),
            "username": get_user_by_id(match.white).name,
            "elo": get_user_by_id(match.white).elo,
        }
        black = {
            "id": str(match.black),
            "username": get_user_by_id(match.black).name,
            "elo": get_user_by_id(match.black).elo,
        }
        result = {
            "match_id": str(match_id),
            "white":white,
            "black": black,
            "pgn": match.pgn,
            "status": match.status,
            "move_count": len(analysis),
            "analysis": analysis,
        }
        return result
    elif san_pgn=="" and  match.status == "draw":
        logger.info(f"[!] Match {match_id} is a draw without moves.")
        white = {
            "id": str(match.white),
            "username": get_user_by_id(match.white).name,
            "elo": get_user_by_id(match.white).elo,
        }
        black = {
            "id": str(match.black),
            "username": get_user_by_id(match.black).name,
            "elo": get_user_by_id(match.black).elo,
        }
        result = {
            "match_id": str(match_id),
            "white": white,
            "black": black,
            "pgn": match.pgn,
            "status": match.status,
            "move_count": 0,
            "analysis": [],
        }
        return result

    return None

def analyze_moves_simple(
    moves_san: str,
    engine_path: str = "../engine/stockfish.exe",
    depth: int = 15
) -> List[Dict[str, Any]]:

    def format_eval(score) -> str:
        if score.is_mate():
            m = score.mate()
            return f"M{m}" if m > 0 else f"M{-m}"
        cp = score.score()
        if cp is None:
            return "0.00"
        return f"{cp/100:+.2f}"

    def classify(loss_cp: int) -> str:
        if loss_cp > 200:
            return "BLUNDER"
        if loss_cp > 100:
            return "MISTAKE"
        if loss_cp > 50:
            return "INACCURACY"
        return "OK"

    Engine = engine.SimpleEngine.popen_uci(engine_path)
    board = Board()
    results = []

    try:
        for ply, san in enumerate(moves_san.split(), start=1):
            board_before = board.copy()
            side = "white" if board.turn == WHITE else "black"

            info_before = Engine.analyse(
                board,
                engine.Limit(depth=depth),
                multipv=1
            )[0]

            score_before = info_before["score"].white()
            best_uci = info_before.get("pv", [None])[0]

            best_san = None
            if best_uci:
                try:
                    best_san = board_before.san(best_uci)
                except:
                    best_san = str(best_uci)

            board.push_san(san)

            info_after = Engine.analyse(
                board,
                engine.Limit(depth=depth)
            )

            score_after = info_after["score"].white()

            loss_cp = 0
            judgment = "OK"

            if score_before.is_mate() and not score_after.is_mate():
                judgment = "BLUNDER"
                loss_cp = 9999

            elif not score_before.is_mate() and not score_after.is_mate():
                before_cp = score_before.score()
                after_cp = score_after.score()

                if before_cp is not None and after_cp is not None:
                    if side == "white":
                        loss_cp = max(0, before_cp - after_cp)
                    else:
                        loss_cp = max(0, after_cp - before_cp)

                    judgment = classify(loss_cp)

            results.append({
                "ply": ply,
                "move": san,
                "color": side,
                "eval_before": format_eval(score_before),
                "eval_after": format_eval(score_after),
                "loss_cp": loss_cp,
                "loss": round(loss_cp / 100, 2),
                "judgment": judgment,
                "best_move": best_san,
            })

    finally:
        Engine.quit()

    return results


================================================
FILE: controllers/users/users_controller.py
================================================
from Models.user_model import User, UserStatus
from DB.connect import user_col,waiting_col, PyMongoError, InsertOneResult
from hashlib import sha256
from bson import ObjectId
from pymongo.errors import DuplicateKeyError


# ================= Add User =================
def add_user(user: User) -> bool:
    try:
        result: InsertOneResult = user_col.insert_one(user.to_dict())
        print(f"[+] User inserted with id: {result.inserted_id}")
        return True
    except DuplicateKeyError:
        print(f"[-] Email {user.mail} is used")
        return False
    except PyMongoError as e:
        print(f"[-] Error inserting user: {e}")
        return False


# ================= Find User =================
def find_user(user_mail: str, user_passwd: str) -> ObjectId | None:
    try:
        hash_pass = sha256(user_passwd.encode()).hexdigest()
        result = user_col.find_one(
            {"mail": user_mail, "pass": hash_pass},
            {"_id": 1}
        )

        if result:
            print(f"[+] Found user: {result}")
            return result["_id"]

        print("[-] User not found.")
        return None

    except PyMongoError as e:
        print(f"[-] Error finding user: {e}")
        return None


# ================= Change User Status =================
def change_user_status(user_id: ObjectId, status: str) -> bool:
    """
    change to one of this (idle, playing, offline).
    """
    if status not in [s.value for s in UserStatus]:
        print(f"[-] Invalid status: {status}")
        return False

    try:
        result = user_col.update_one(
            {"_id": user_id},
            {"$set": {"status": status}}
        )
        if result.matched_count == 0:
            print(f"[+] No user found with id {user_id}")
            return False
        print(f"[+] User {user_id} status changed to {status}")
        return True
    except PyMongoError as e:
        print(f"[-] Error updating user status: {e}")
        return False

# ================= Find Opponent =================
def find_opponent(elo:int)-> ObjectId | None:
    try:
        # wait for 'wait' seconds to find opponent
        
        result = waiting_col.find_one(filter={
            "elo": {"$gte": elo - 100, "$lte": elo + 100}
        })

        if result:
            print(f"[+] Found opponent: {result}")
            return result["_id"]

        print("[-] No idle opponent found.")
        return None

    except PyMongoError as e:
        print(f"[-] Error finding opponent: {e}")
        return None
    
# ================= USER BY ID =================
def get_user_by_id(user_id: ObjectId) -> User | None:
    try:
        result = user_col.find_one({"_id": user_id})
        if result:
            user = User.from_dict(result)
            print(f"[+] Retrieved user: {user}")
            return user
        print(f"[-] No user found with id: {user_id}")
        return None
    except PyMongoError as e:
        print(f"[-] Error retrieving user: {e}")
        return None


================================================
FILE: DB/connect.py
================================================
# DB/connect.py 
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import PyMongoError, ConnectionFailure
from pymongo.results import InsertOneResult, InsertManyResult
import os
from dotenv import load_dotenv, find_dotenv
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv(find_dotenv())

# Configuration
class DBConfig:
    USER = os.getenv("USER")
    PASS = os.getenv("PASS")
    HOST = os.getenv("HOST", "localhost")
    PORT = os.getenv("PORT", "27017")
    DB_NAME = os.getenv("DB", "chess_db")
    
    @classmethod
    def get_uri(cls):
        if cls.USER and cls.PASS:
            return f"mongodb://{cls.USER}:{cls.PASS}@{cls.HOST}:{cls.PORT}/{cls.DB_NAME}?authSource=admin"
        return f"mongodb://{cls.HOST}:{cls.PORT}/{cls.DB_NAME}"

# ============ DATABASE CONNECTION ============
class Database:
    _instance = None
    _client = None
    _db = None
    
    def __new__(cls):
        """Singleton pattern for database connection"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._client is None:
            self.connect()
    
    def connect(self):
        """Establish database connection"""
        try:
            uri = DBConfig.get_uri()
            self._client = MongoClient(
                uri,
                serverSelectionTimeoutMS=5000,
                connectTimeoutMS=10000,
                socketTimeoutMS=10000,
                maxPoolSize=50,
                minPoolSize=10
            )
            
            # Verify connection
            self._client.admin.command("ping")
            logger.info("Connected to MongoDB")
            
            # Get database
            self._db = self._client[DBConfig.DB_NAME]
            
            # Setup collections
            self._setup_collections()
            
        except ConnectionFailure as e:
            logger.error(f"MongoDB connection failed: {e}")
            raise
        except PyMongoError as e:
            logger.error(f"MongoDB error: {e}")
            raise
    
    def _setup_collections(self):
        """Setup collections with indexes"""
        try:
            # User collection
            self.user_col.create_index("mail", unique=True)
            self.user_col.create_index("status")
            self.user_col.create_index("elo")
            
            # Match collection
            self.match_col.create_index([("white", 1), ("black", 1)])
            self.match_col.create_index("status")
            self.match_col.create_index("start")
            
            # Pending users (TTL index)
            self.pending_col.create_index(
                "expireAt",
                expireAfterSeconds=0
            )
            
            # Waiting queue
            self.waiting_col.create_index("elo")
            self.waiting_col.create_index("created_at")
            
            logger.info("Database indexes created")
            
        except PyMongoError as e:
            logger.warning(f"Index creation warning: {e}")
    
    @property
    def client(self) -> MongoClient:
        return self._client
    
    @property
    def db(self) -> Database:
        return self._db
    
    @property
    def user_col(self) -> Collection:
        return self._db["user"]
    
    @property
    def match_col(self) -> Collection:
        return self._db["match"]
    
    @property
    def pending_col(self) -> Collection:
        return self._db["pending"]
    
    @property
    def waiting_col(self) -> Collection:
        return self._db["waiting"]
    
    def close(self):
        """Close database connection"""
        if self._client:
            self._client.close()
            logger.info("🔌 MongoDB connection closed")

# ============ SINGLETON INSTANCE ============
db_instance = Database()

# Export collections for backward compatibility
user_col = db_instance.user_col
match_col = db_instance.match_col
pending_col = db_instance.pending_col
waiting_col = db_instance.waiting_col

# Export for new usage
__all__ = [
    'Database',
    'db_instance',
    'user_col',
    'match_col',
    'pending_col',
    'waiting_col',
    'PyMongoError',
    'InsertOneResult',
    'InsertManyResult'
]


================================================
FILE: frontends/routes/auth.py
================================================
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



================================================
FILE: frontends/routes/bot.py
================================================
# frontend/routes/bot.py
from flask import Blueprint,render_template


bot_frontend_bp = Blueprint('bot_frontend', __name__, 
                                 static_folder='../../static', 
                                 template_folder='../../templates')

@bot_frontend_bp.route("/game/bot",  methods=['GET'], strict_slashes=False)
def bot_game():
    return render_template("game/bot.html")        
    



================================================
FILE: frontends/routes/index.py
================================================
# frontends/routes/index.py
from flask import Blueprint
from frontends.routes.auth import auth_frontend_bp
from frontends.routes.matching import matching_frontend_bp
from frontends.routes.review import review_frontends_bp
from frontends.routes.bot import  bot_frontend_bp

fe_bp:Blueprint = Blueprint('fe', __name__)
fe_bp.register_blueprint(auth_frontend_bp, url_prefix='/')
fe_bp.register_blueprint(matching_frontend_bp, url_prefix='/')
fe_bp.register_blueprint(review_frontends_bp, url_prefix="/")
fe_bp.register_blueprint(bot_frontend_bp, url_prefix="/")




================================================
FILE: frontends/routes/matching.py
================================================
# frontends/routes/matching.py
from flask import Blueprint, render_template

matching_frontend_bp = Blueprint('matching_frontend', __name__, 
                                 static_folder='../../static', 
                                 template_folder='../../templates')

# =========== MATCHING PAGE ============
@matching_frontend_bp.route('/home', methods=['GET'], strict_slashes=False)
def matching_page():
    return render_template('matching/index.html')

# =========== GAME PAGE ============
@matching_frontend_bp.route('/game/<match_id>', methods=['GET'], strict_slashes=False)
def game_page(match_id):
    return render_template('game/index.html', match_id=match_id)


================================================
FILE: frontends/routes/review.py
================================================
# frontend/routes/review.py
from flask import Blueprint,render_template


review_frontends_bp = Blueprint('review_frontend', __name__, 
                                 static_folder='../../static', 
                                 template_folder='../../templates')

@review_frontends_bp.route("/review/<id_match>",  methods=['GET'], strict_slashes=False)
def review(id_match):
    return render_template("review/index.html",match_id=id_match)        
    



================================================
FILE: frontends/routes/static.py
================================================



================================================
FILE: Models/bot_model.py
================================================
from enum import Enum
from bson import ObjectId
from datetime import datetime

class BotDifficulty(str, Enum):
    """Bot difficulty levels"""
    BEGINNER = "beginner"      # ELO: 400-800, Depth: 1-3
    EASY = "easy"              # ELO: 800-1200, Depth: 4-6
    MEDIUM = "medium"          # ELO: 1200-1600, Depth: 7-10
    HARD = "hard"              # ELO: 1600-2000, Depth: 11-15
    EXPERT = "expert"          # ELO: 2000+, Depth: 16-20

class BotMatch:
    """Model for bot matches"""

    def __init__(
        self,
        player_id: ObjectId,
        bot_difficulty: str,
        player_color: str,
        pgn: str = "",
        start: datetime = None,
        end: datetime = None,
        status: str = "ongoing",
        _id: ObjectId = None
    ):
        self._id = _id or ObjectId()
        self.player_id = player_id
        self.bot_difficulty = bot_difficulty
        self.player_color = player_color
        self.pgn = pgn
        self.start = start or datetime.utcnow()
        self.end = end
        self.status = status

        bot_id = self.define_bot_id()

        if player_color == "white":
            self.white = player_id
            self.black = bot_id
        else:
            self.black = player_id
            self.white = bot_id

    def define_bot_id(self) -> ObjectId:
        difficulty = BotDifficulty(self.bot_difficulty)

        bot_map = {
            BotDifficulty.BEGINNER: ObjectId("000000000000000000000000"),
            BotDifficulty.EASY: ObjectId("000000000000000000000001"),
            BotDifficulty.MEDIUM: ObjectId("000000000000000000000002"),
            BotDifficulty.HARD: ObjectId("000000000000000000000003"),
            BotDifficulty.EXPERT: ObjectId("000000000000000000000004"),
        }

        return bot_map[difficulty]

    def to_dict(self):
        return {
            "_id": self._id,
            "player_id": self.player_id,
            "bot_difficulty": self.bot_difficulty,
            "player_color": self.player_color,
            "pgn": self.pgn,
            "start": self.start,
            "end": self.end,
            "status": self.status,
            "white": self.white,
            "black": self.black,
        }


    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            player_id=data["player_id"],
            bot_difficulty=data["bot_difficulty"],
            player_color=data["player_color"],
            pgn=data.get("pgn", ""),
            start=data.get("start"),
            end=data.get("end"),
            # white=data.get("white"),
            # black=data.get("black"),
            status=data.get("status", "ongoing"),
            _id=data.get("_id")
        )

    def __repr__(self):
        return f"BotMatch(player={self.player_id}, difficulty={self.bot_difficulty}, status={self.status})"


class BotProfile:
    """Bot profile with settings"""
    
    DIFFICULTY_SETTINGS = {
        BotDifficulty.BEGINNER: {
            "depth": 2,
            "elo_range": (400, 800),
            "thinking_time": 0.5,
            "error_rate": 0.3
        },
        BotDifficulty.EASY: {
            "depth": 5,
            "elo_range": (800, 1200),
            "thinking_time": 1.0,
            "error_rate": 0.15
        },
        BotDifficulty.MEDIUM: {
            "depth": 8,
            "elo_range": (1200, 1600),
            "thinking_time": 1.5,
            "error_rate": 0.05
        },
        BotDifficulty.HARD: {
            "depth": 12,
            "elo_range": (1600, 2000),
            "thinking_time": 2.0,
            "error_rate": 0.02
        },
        BotDifficulty.EXPERT: {
            "depth": 16,
            "elo_range": (2000, 2400),
            "thinking_time": 3.0,
            "error_rate": 0.0
        }
    }
    
    @classmethod
    def get_settings(cls, difficulty: str) -> dict:
        """Get bot settings for difficulty level"""
        return cls.DIFFICULTY_SETTINGS.get(
            BotDifficulty(difficulty),
            cls.DIFFICULTY_SETTINGS[BotDifficulty.MEDIUM]
        )
    
    @classmethod
    def get_bot_name(cls, difficulty: str) -> str:
        """Get bot display name"""
        names = {
            BotDifficulty.BEGINNER: "ChessBot Junior",
            BotDifficulty.EASY: "ChessBot Novice",
            BotDifficulty.MEDIUM: "ChessBot Standard",
            BotDifficulty.HARD: "ChessBot Pro",
            BotDifficulty.EXPERT: "ChessBot Master"
        }
        return names.get(BotDifficulty(difficulty), "ChessBot")
    
    @classmethod
    def get_bot_elo(cls, difficulty: str) -> int:
        """Get average bot ELO for difficulty"""
        settings = cls.get_settings(difficulty)
        elo_range = settings["elo_range"]
        return (elo_range[0] + elo_range[1]) // 2


================================================
FILE: Models/match_model.py
================================================
from datetime import datetime
from bson import ObjectId

# =============== Match ===============
class Match:
    def __init__(self, black: ObjectId, white: ObjectId, pgn: str = "",
                 start: datetime = None, end: datetime = None,
                 status: str = "ongoing", _id: ObjectId = None):
        self._id = _id or ObjectId()
        self.black = black
        self.white = white
        self.pgn = pgn
        self.start = start or datetime.utcnow()
        self.end = end
        self.status = status

    def to_dict(self):
        return {
            "_id": self._id,
            "black": self.black,
            "white": self.white,
            "pgn": self.pgn,
            "start": self.start,
            "end": self.end,
            "status": self.status
        }

    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            black=data["black"],
            white=data["white"],
            pgn=data.get("pgn", ""),
            start=data.get("start"),
            end=data.get("end"),
            status=data.get("status", "ongoing"),
            _id=data.get("_id")
        )

    def __repr__(self):
        return f"Match(black={self.black}, white={self.white}, status={self.status})"



================================================
FILE: Models/user_model.py
================================================
from bson import ObjectId
from hashlib import sha256
from enum import Enum
import re


# =============== User ===============
class UserStatus(str, Enum):
    IDLE :str = "idle"
    PLAYING:str = "playing"
    OFFLINE:str = "offline"
    MATCHING:str = "matching"


class User:
    def __init__(self, name: str, passwd: str, mail: str,
                 elo: int = 400, status: UserStatus = UserStatus.OFFLINE,
                 _id: ObjectId = None, hashed: bool = False, is_bot: bool = False):

        self._id = _id or ObjectId()
        self.name = name
        self.passwd = passwd if hashed else sha256(passwd.encode()).hexdigest()
        self.mail = mail
        self.elo = elo
        self.is_bot = is_bot
        self.status = (
            status if isinstance(status, UserStatus)
            else UserStatus(status)
        )

        if not self.mail_valid():
            raise ValueError(f"Invalid email: {mail}")

    def mail_valid(self) -> bool:
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return re.match(pattern, self.mail) is not None

    def check_password(self, raw_passwd: str) -> bool:
        return self.passwd == sha256(raw_passwd.encode()).hexdigest()

    def update_elo(self, opponent_elo: int, result: float, k: int = 32):
        expected = 1 / (1 + 10 ** ((opponent_elo - self.elo) / 400))
        self.elo += int(k * (result - expected))

    def to_dict(self):
        return {
            "_id": self._id,
            "name": self.name,
            "pass": self.passwd,
            "mail": self.mail,
            "elo": self.elo,
            "status": self.status.value,
            "is_bot": self.is_bot
        }

    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            name=data["name"],
            passwd=data["pass"],
            mail=data["mail"],
            elo=data.get("elo", 1200),
            status=UserStatus(data.get("status", "idle")),
            is_bot=data.get("is_bot", False),
            _id=data.get("_id"),
            hashed=True
        )

    def __repr__(self):
        return f"User(name={self.name!r}, elo={self.elo}, status={self.status.value!r})"





================================================
FILE: services/mail.py
================================================
from flask_mail import Mail, Message
from flask import current_app

mail = Mail()

def send_confirmation_email(to_email: str, token: str) -> None:
    subject = "Confirm your registration"
    body = f"Hello,\n\nPlease confirm your account by using token:\n{token}\n\nThank you!"
    
    try:
        msg = Message(subject=subject, recipients=[to_email], body=body)
        mail.send(msg)
        print(f"📩 Confirmation email sent to {to_email}")
    except Exception as e:
        current_app.logger.error(f"❌ Failed to send email to {to_email}: {e}")



================================================
FILE: static/css/auth/auth.css
================================================
/* Auth Pages Styling */
* {
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: linear-gradient(135deg,rgb(169, 176, 205) 0%,rgb(195, 172, 219) 100%);
    margin: 0;
    padding: 0;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    color: #333;
}

.auth-container {
    width: 100%;
    max-width: 450px;
    padding: 20px;
}

.auth-card {
    background: white;
    border-radius: 12px;
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
    padding: 2.5rem;
    animation: slideUp 0.5s ease-out;
}

@keyframes slideUp {
    from {
        opacity: 0;
        transform: translateY(30px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

.auth-header {
    text-align: center;
    margin-bottom: 2rem;
}

.auth-header h1 {
    margin: 0 0 0.5rem 0;
    font-size: 2rem;
    font-weight: 600;
    color: #2c3e50;
}

.auth-header p {
    margin: 0;
    color: #6c757d;
    font-size: 1rem;
}

/* Form Styles */
.auth-form {
    display: flex;
    flex-direction: column;
    gap: 1.5rem;
}

.form-group {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
}

.form-group label {
    font-weight: 500;
    color: #374151;
    font-size: 0.9rem;
}

.form-group input {
    padding: 0.75rem 1rem;
    border: 2px solid #e5e7eb;
    border-radius: 8px;
    font-size: 1rem;
    transition: all 0.2s ease;
    background-color: #fff;
}

.form-group input:focus {
    outline: none;
    border-color: #667eea;
    box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
}

.form-group input::placeholder {
    color: #9ca3af;
}

.form-group.error input {
    border-color: #ef4444;
    box-shadow: 0 0 0 3px rgba(239, 68, 68, 0.1);
}

.error-message {
    color: #ef4444;
    font-size: 0.875rem;
    margin-top: 0.25rem;
    display: none;
}

/* Password Input Container */
.password-input-container {
    position: relative;
    display: flex;
    align-items: center;
}

.password-input-container input {
    padding-right: 3rem;
}

.password-toggle {
    position: absolute;
    right: 0.75rem;
    background: none;
    border: none;
    cursor: pointer;
    padding: 0.25rem;
    border-radius: 4px;
    color: #6b7280;
    transition: background-color 0.2s ease;
}

.password-toggle:hover {
    background-color: rgba(0, 0, 0, 0.1);
}

.eye-icon {
    font-size: 1.25rem;
}

/* Password Strength */
.password-strength {
    margin-top: 0.5rem;
}

.strength-meter {
    height: 4px;
    background-color: #e5e7eb;
    border-radius: 2px;
    overflow: hidden;
    margin-bottom: 0.25rem;
}

.strength-bar {
    height: 100%;
    width: 0%;
    transition: all 0.3s ease;
    border-radius: 2px;
}

.strength-weak .strength-bar {
    width: 33%;
    background-color: #ef4444;
}

.strength-medium .strength-bar {
    width: 66%;
    background-color: #f59e0b;
}

.strength-strong .strength-bar {
    width: 100%;
    background-color: #10b981;
}

.strength-text {
    font-size: 0.875rem;
    color: #6b7280;
}

/* Terms Checkbox */
.terms-group {
    margin-top: 1rem;
}

.checkbox-label {
    display: flex;
    align-items: flex-start;
    gap: 0.75rem;
    cursor: pointer;
    font-size: 0.9rem;
    line-height: 1.4;
    color: #374151;
}

.checkbox-label input[type="checkbox"] {
    width: 1.25rem;
    height: 1.25rem;
    margin-top: 0.125rem;
    accent-color: #667eea;
}

.checkmark {
    display: inline-block;
    width: 1.25rem;
    height: 1.25rem;
    background-color: #fff;
    border: 2px solid #d1d5db;
    border-radius: 4px;
    position: relative;
    margin-top: 0.125rem;
}

.checkbox-label input[type="checkbox"]:checked + .checkmark {
    background-color: #667eea;
    border-color: #667eea;
}

.checkbox-label input[type="checkbox"]:checked + .checkmark::after {
    content: '✓';
    position: absolute;
    top: -2px;
    left: 2px;
    color: white;
    font-size: 0.875rem;
    font-weight: bold;
}

.link {
    color: #667eea;
    text-decoration: none;
}

.link:hover {
    text-decoration: underline;
}

/* Buttons */
.btn {
    padding: 0.875rem 1.5rem;
    border: none;
    border-radius: 8px;
    font-size: 1rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s ease;
    text-align: center;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
}

.btn-primary {
    background-color: #667eea;
    color: white;
}

.btn-primary:hover:not(:disabled) {
    background-color: #5a67d8;
    transform: translateY(-1px);
    box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);
}

.btn-primary:disabled {
    opacity: 0.7;
    cursor: not-allowed;
    transform: none;
}

.btn-secondary {
    background-color: #6b7280;
    color: white;
}

.btn-secondary:hover {
    background-color: #4b5563;
}

/* Button Spinner */
.btn-spinner {
    width: 1rem;
    height: 1rem;
    border: 2px solid transparent;
    border-top: 2px solid currentColor;
    border-radius: 50%;
    animation: spin 1s linear infinite;
    display: none;
}

.btn-spinner.show {
    display: block;
}

@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}

/* Auth Links */
.auth-links {
    text-align: center;
    margin-top: 2rem;
    padding-top: 2rem;
    border-top: 1px solid #e5e7eb;
}

.auth-links p {
    margin: 0 0 1rem 0;
    color: #6b7280;
}

.auth-divider {
    margin: 2rem 0;
    text-align: center;
    position: relative;
}

.auth-divider::before {
    content: '';
    position: absolute;
    top: 50%;
    left: 0;
    right: 0;
    height: 1px;
    background-color: #e5e7eb;
}

.auth-divider span {
    background-color: white;
    padding: 0 1rem;
    color: #6b7280;
    font-size: 0.875rem;
}

/* Messages */
.message {
    margin-top: 1.5rem;
    padding: 1rem;
    border-radius: 8px;
    text-align: center;
    font-weight: 500;
    display: none;
}

.message.success {
    background-color: #d1fae5;
    color: #065f46;
    border: 1px solid #a7f3d0;
}

.message.error {
    background-color: #fee2e2;
    color: #991b1b;
    border: 1px solid #fecaca;
}

/* Confirmation Page Styles */
.confirmation-icon {
    text-align: center;
    margin-bottom: 1.5rem;
}

.confirmation-icon .icon {
    font-size: 4rem;
    display: inline-block;
    animation: pulse 2s infinite;
}

.confirmation-icon.loading .icon {
    animation: spin 1s linear infinite;
}

.confirmation-icon.success .icon {
    color: #10b981;
}

.confirmation-icon.error .icon {
    color: #ef4444;
}

@keyframes pulse {
    0% { transform: scale(1); }
    50% { transform: scale(1.1); }
    100% { transform: scale(1); }
}

.loading-spinner {
    text-align: center;
    margin: 2rem 0;
}

.spinner {
    width: 40px;
    height: 40px;
    border: 4px solid #f3f3f3;
    border-top: 4px solid #667eea;
    border-radius: 50%;
    animation: spin 1s linear infinite;
    margin: 0 auto;
}

.confirmation-content {
    text-align: center;
}

.manual-confirm {
    margin-top: 2rem;
    padding: 1.5rem;
    background-color: #f8f9fa;
    border-radius: 8px;
    border: 1px solid #e9ecef;
}

.manual-confirm p {
    margin-bottom: 1rem;
    color: #6c757d;
}

.confirmation-actions {
    margin-top: 2rem;
    display: flex;
    gap: 1rem;
    justify-content: center;
}

.confirmation-actions .btn {
    padding: 0.75rem 1.5rem;
    text-decoration: none;
    display: inline-block;
    border-radius: 6px;
    font-weight: 500;
    transition: all 0.2s ease;
}

/* Responsive Design */
@media (max-width: 480px) {
    .auth-container {
        padding: 15px;
    }

    .auth-card {
        padding: 2rem 1.5rem;
    }

    .auth-header h1 {
        font-size: 1.75rem;
    }

    .confirmation-actions {
        flex-direction: column;
    }

    .confirmation-actions .btn {
        width: 100%;
    }
}



================================================
FILE: static/css/game/game.css
================================================
/* ==================== RESET & BASE ==================== */
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: linear-gradient(135deg,rgb(169, 176, 205) 0%,rgb(195, 172, 219) 100%);
    color: #333;
    min-height: 100vh;
    overflow-x: hidden;
}

/* ==================== LOADING OVERLAY ==================== */
.overlay {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.9);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 10000;
    transition: opacity 0.3s ease;
}

.overlay.hidden {
    opacity: 0;
    pointer-events: none;
}

.overlay-content {
    text-align: center;
    color: white;
}

.spinner-large {
    width: 60px;
    height: 60px;
    border: 5px solid rgba(255, 255, 255, 0.2);
    border-top: 5px solid #fff;
    border-radius: 50%;
    animation: spin 1s linear infinite;
    margin: 0 auto 20px;
}

@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}

/* ==================== CONNECTION STATUS BANNER ==================== */
.connection-banner {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    background: #f59e0b;
    color: white;
    padding: 10px 20px;
    text-align: center;
    z-index: 9999;
    font-weight: 600;
    animation: slideDown 0.3s ease-out;
}

.connection-banner.hidden {
    display: none;
}

.connection-banner.error {
    background: #ef4444;
}

.connection-banner.success {
    background: #10b981;
}

@keyframes slideDown {
    from {
        transform: translateY(-100%);
    }
    to {
        transform: translateY(0);
    }
}

/* ==================== MAIN CONTAINER ==================== */
.game-container {
    max-width: 1800px;
    margin: 0 auto;
    padding: 20px;
}

/* ==================== HEADER ==================== */
.game-header {
    background: white;
    border-radius: 12px;
    padding: 1.5rem 2rem;
    margin-bottom: 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.header-left, .header-right {
    flex: 1;
}

.header-center {
    text-align: center;
    flex: 2;
}

.header-center h1 {
    font-size: 1.8rem;
    color: #1e3c72;
    margin-bottom: 0.25rem;
}

.match-id {
    font-size: 0.9rem;
    color: #6b7280;
}

.btn-back {
    background: #6b7280;
    color: white;
    border: none;
    padding: 0.5rem 1rem;
    border-radius: 8px;
    cursor: pointer;
    font-size: 0.9rem;
    transition: all 0.2s;
}

.btn-back:hover {
    background: #4b5563;
    transform: translateX(-2px);
}

/* Connection Indicator */
.connection-indicator {
    display: flex;
    align-items: center;
    gap: 8px;
    justify-content: flex-end;
}

.connection-indicator .dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: #ef4444;
    animation: pulse 2s infinite;
}

.connection-indicator.connected .dot {
    background: #10b981;
    animation: none;
}

.connection-indicator .text {
    font-size: 0.9rem;
    font-weight: 500;
    color: #6b7280;
}

@keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
}

/* ==================== GAME CONTENT LAYOUT ==================== */
.game-content {
    display: grid;
    grid-template-columns: 300px 1fr 350px;
    gap: 20px;
}

/* ==================== SIDEBARS ==================== */
.sidebar {
    display: flex;
    flex-direction: column;
    gap: 20px;
}

/* ==================== PLAYER CARDS ==================== */
.player-card {
    background: white;
    border-radius: 12px;
    padding: 1.5rem;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.opponent-card {
    border-top: 4px solid #ef4444;
}

.your-card-top {
    border-top: 4px solid #10b981;
}

.player-avatar {
    width: 80px;
    height: 80px;
    margin: 0 auto 1rem;
    position: relative;
}

.player-avatar.small {
    width: 50px;
    height: 50px;
    margin: 0 0.5rem 0 0;
}

.avatar-icon {
    width: 100%;
    height: 100%;
    background: linear-gradient(135deg, #667eea, #764ba2);
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 2.5rem;
}

.player-avatar.small .avatar-icon {
    font-size: 1.5rem;
}

.connection-status {
    position: absolute;
    bottom: 5px;
    right: 5px;
}

.status-dot {
    display: inline-block;
    width: 12px;
    height: 12px;
    border-radius: 50%;
    border: 2px solid white;
}

.status-dot.online {
    background: #10b981;
}

.status-dot.offline {
    background: #6b7280;
}

.player-info {
    text-align: center;
}

.player-name {
    font-size: 1.2rem;
    font-weight: 700;
    color: #1f2937;
    margin-bottom: 0.5rem;
}

.player-elo {
    font-size: 1rem;
    color: #6b7280;
    margin-bottom: 0.5rem;
}

.elo-value {
    font-weight: 700;
    color: #667eea;
}

.player-color {
    margin-top: 0.5rem;
}

.color-piece {
    font-size: 1.5rem;
}

/* Captured Pieces */
.captured-pieces {
    margin-top: 1rem;
    padding: 0.75rem;
    background: #f8f9fa;
    border-radius: 8px;
    min-height: 40px;
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    justify-content: center;
}

.captured-piece {
    font-size: 1.2rem;
    opacity: 0.7;
}

/* ==================== GAME CONTROLS ==================== */
.game-controls {
    background: white;
    border-radius: 12px;
    padding: 1.5rem;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.game-controls h4 {
    margin-bottom: 1rem;
    color: #1f2937;
}

.game-controls .btn {
    width: 100%;
    margin-bottom: 0.5rem;
}

/* ==================== GAME STATUS CARD ==================== */
.game-status-card {
    background: white;
    border-radius: 12px;
    padding: 1.5rem;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.game-status-card h4 {
    margin-bottom: 1rem;
    color: #1f2937;
}

.status-item {
    display: flex;
    justify-content: space-between;
    padding: 0.5rem 0;
    border-bottom: 1px solid #e5e7eb;
}

.status-item:last-child {
    border-bottom: none;
}

.status-item .label {
    color: #6b7280;
    font-weight: 500;
}

.status-item .value {
    font-weight: 700;
    color: #1f2937;
}

.status-ongoing { color: #10b981; }
.status-check { color: #f59e0b; }
.status-checkmate { color: #ef4444; }

/* ==================== BOARD AREA ==================== */
.board-area {
    display: flex;
    flex-direction: column;
    align-items: center;
}

.your-card-top {
    width: 100%;
    margin-bottom: 1rem;
    display: flex;
    align-items: center;
    padding: 1rem;
}

.board-wrapper {
    position: relative;
    width: 600px;
    height: 600px;
    margin: 0 auto;
}

#chessboard {
    width: 100%;
    height: 100%;
}

.board-overlay {
    position: absolute;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.8);
    display: none;
    align-items: center;
    justify-content: center;
    border-radius: 8px;
}

.board-overlay.active {
    display: flex;
}

.overlay-message {
    background: white;
    padding: 2rem;
    border-radius: 12px;
    text-align: center;
    font-size: 1.5rem;
    font-weight: 700;
}

/* Move Indicator */
.move-indicator {
    margin-top: 1rem;
    padding: 1rem 2rem;
    background: white;
    border-radius: 12px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
    transition: all 0.3s;
}

.move-indicator.hidden {
    opacity: 0;
}

.indicator-content {
    display: flex;
    align-items: center;
    gap: 10px;
    font-weight: 600;
    color: #6b7280;
}

.indicator-icon {
    font-size: 1.5rem;
    animation: spin 2s linear infinite;
}

.move-indicator.your-turn {
    background: #d1fae5;
    border: 2px solid #10b981;
}

.move-indicator.your-turn .indicator-content {
    color: #065f46;
}

/* ==================== MOVE HISTORY ==================== */
.move-history-card {
    background: white;
    border-radius: 12px;
    padding: 1.5rem;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
    height: 400px;
    display: flex;
    flex-direction: column;
}

.move-history-card h4 {
    margin-bottom: 1rem;
    color: #1f2937;
}

.move-history {
    flex: 1;
    overflow-y: auto;
    padding: 0.5rem;
    background: #f8f9fa;
    border-radius: 8px;
}

.move-row {
    display: grid;
    grid-template-columns: 40px 1fr 1fr;
    gap: 10px;
    padding: 0.5rem;
    margin-bottom: 0.25rem;
    background: white;
    border-radius: 6px;
    font-size: 0.9rem;
}

.move-number {
    font-weight: 700;
    color: #6b7280;
}

.move-white, .move-black {
    padding: 0.25rem 0.5rem;
    border-radius: 4px;
    font-weight: 600;
}

.move-white {
    background: #e5e7eb;
    color: #1f2937;
}

.move-black {
    background: #1f2937;
    color: white;
}

.no-moves {
    text-align: center;
    color: #9ca3af;
    padding: 2rem 0;
}

/* ==================== CHAT ==================== */
.chat-card {
    background: white;
    border-radius: 12px;
    padding: 1.5rem;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
    height: calc(100vh - 700px);
    min-height: 300px;
    display: flex;
    flex-direction: column;
}

.chat-card h4 {
    margin-bottom: 1rem;
    color: #1f2937;
}

.chat-messages {
    flex: 1;
    overflow-y: auto;
    padding: 0.5rem;
    background: #f8f9fa;
    border-radius: 8px;
    margin-bottom: 1rem;
}

.chat-info {
    text-align: center;
    color: #9ca3af;
    padding: 1rem 0;
    font-size: 0.9rem;
}

.chat-message {
    margin-bottom: 0.75rem;
    padding: 0.5rem;
    border-radius: 8px;
    animation: slideIn 0.3s ease-out;
}

@keyframes slideIn {
    from {
        opacity: 0;
        transform: translateY(10px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

.chat-message.mine {
    background: #dbeafe;
    margin-left: 2rem;
}

.chat-message.theirs {
    background: #e5e7eb;
    margin-right: 2rem;
}

.chat-sender {
    font-weight: 700;
    font-size: 0.85rem;
    margin-bottom: 0.25rem;
    color: #374151;
}

.chat-text {
    font-size: 0.9rem;
    color: #1f2937;
}

.chat-time {
    font-size: 0.75rem;
    color: #9ca3af;
    margin-top: 0.25rem;
}

.chat-input-area {
    display: flex;
    gap: 0.5rem;
}

#chatInput {
    flex: 1;
    padding: 0.75rem;
    border: 2px solid #e5e7eb;
    border-radius: 8px;
    font-size: 0.9rem;
}

#chatInput:focus {
    outline: none;
    border-color: #667eea;
}

.btn-send {
    padding: 0.75rem 1rem;
    background: #667eea;
    color: white;
    border: none;
    border-radius: 8px;
    cursor: pointer;
    font-size: 1.2rem;
    transition: all 0.2s;
}

.btn-send:hover {
    background: #5a67d8;
    transform: scale(1.05);
}

/* ==================== BUTTONS ==================== */
.btn {
    padding: 0.75rem 1.5rem;
    border: none;
    border-radius: 8px;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
}

.btn-primary {
    background: linear-gradient(135deg, #667eea, #764ba2);
    color: white;
}

.btn-primary:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(102, 126, 234, 0.4);
}

.btn-secondary {
    background: #6b7280;
    color: white;
}

.btn-secondary:hover {
    background: #4b5563;
}

.btn-danger {
    background: #ef4444;
    color: white;
}

.btn-danger:hover {
    background: #dc2626;
}

.btn-warning {
    background: #f59e0b;
    color: white;
}

.btn-warning:hover {
    background: #d97706;
}

.btn-success {
    background: #10b981;
    color: white;
}

.btn-success:hover {
    background: #059669;
}

.btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
    transform: none !important;
}

/* ==================== MODALS ==================== */
.modal {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.8);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 9999;
    animation: fadeIn 0.3s ease-out;
}

.modal.hidden {
    display: none;
}

@keyframes fadeIn {
    from { opacity: 0; }
    to { opacity: 1; }
}

.modal-content {
    background: white;
    border-radius: 16px;
    padding: 2.5rem;
    max-width: 500px;
    width: 90%;
    text-align: center;
    animation: scaleIn 0.3s ease-out;
}

@keyframes scaleIn {
    from {
        transform: scale(0.9);
        opacity: 0;
    }
    to {
        transform: scale(1);
        opacity: 1;
    }
}

.game-end-content {
    max-width: 600px;
}

.result-icon {
    font-size: 5rem;
    margin-bottom: 1rem;
}

.result-title {
    font-size: 2rem;
    margin-bottom: 1rem;
    color: #1f2937;
}

.result-message {
    font-size: 1.1rem;
    color: #6b7280;
    margin-bottom: 2rem;
}

.result-details {
    background: #f8f9fa;
    padding: 1.5rem;
    border-radius: 12px;
    margin-bottom: 2rem;
}

.elo-changes {
    display: flex;
    justify-content: space-around;
    gap: 2rem;
}

.elo-change-item {
    text-align: center;
}

.elo-change-label {
    font-size: 0.9rem;
    color: #6b7280;
    margin-bottom: 0.5rem;
}

.elo-change-value {
    font-size: 1.5rem;
    font-weight: 700;
}

.elo-increase {
    color: #10b981;
}

.elo-decrease {
    color: #ef4444;
}

.modal-actions {
    display: flex;
    gap: 1rem;
    justify-content: center;
}

.modal-actions .btn {
    min-width: 150px;
}

/* ==================== RESPONSIVE ==================== */
@media (max-width: 1400px) {
    .game-content {
        grid-template-columns: 280px 1fr 300px;
    }
    
    .board-wrapper {
        width: 500px;
        height: 500px;
    }
}

@media (max-width: 1200px) {
    .game-content {
        grid-template-columns: 1fr;
    }
    
    .sidebar-left, .sidebar-right {
        display: none;
    }
    
    .board-wrapper {
        width: 90vw;
        max-width: 600px;
        height: auto;
        aspect-ratio: 1;
    }
}

@media (max-width: 768px) {
    .game-header {
        flex-direction: column;
        gap: 1rem;
    }
    
    .header-left, .header-center, .header-right {
        flex: none;
        width: 100%;
    }
    
    .board-wrapper {
        width: 95vw;
    }
}

/* ==================== CHESSBOARD CUSTOMIZATION ==================== */
.board-b72b1 {
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.2);
    border-radius: 8px;
    overflow: hidden;
}

.highlight-square {
    box-shadow: inset 0 0 0 3px #f59e0b;
}

.selected-square {
    box-shadow: inset 0 0 0 3px #10b981 !important;
}


================================================
FILE: static/css/game/promotion.css
================================================
/* Promotion Modal */
.promotion-box {
    background: #1f2933;
    padding: 20px;
    border-radius: 12px;
    text-align: center;
    min-width: 260px;
}

.promotion-options {
    display: flex;
    justify-content: space-around;
    margin-top: 15px;
}

.promotion-options button {
    font-size: 32px;
    width: 60px;
    height: 60px;
    border-radius: 10px;
    border: none;
    cursor: pointer;
    background: #374151;
    color: white;
    transition: transform 0.15s ease, background 0.15s ease;
}

.promotion-options button:hover {
    background: #4b5563;
    transform: scale(1.1);
}



================================================
FILE: static/css/matching/matching.css
================================================
/* Matching Page Styles */
* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}
hr{
    background-color: #4b5563;
    height: 1px;
}
a{
    text-decoration: none;
    color: inherit;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: linear-gradient(135deg,rgb(169, 176, 205) 0%,rgb(195, 172, 219) 100%);
    min-height: 100vh;
    color: #333;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 20px;
}

/* Header */
.header {
    background: white;
    border-radius: 12px;
    padding: 1.5rem 2rem;
    margin-bottom: 2rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.logo {
    font-size: 1.75rem;
    font-weight: 700;
    color: #667eea;
}

.user-info {
    display: flex;
    align-items: center;
    gap: 1rem;
}

.user-info #userName {
    font-weight: 600;
    color: #2c3e50;
}

.elo-badge {
    background: linear-gradient(135deg, #667eea, #764ba2);
    color: white;
    padding: 0.5rem 1rem;
    border-radius: 20px;
    font-weight: 600;
    font-size: 0.9rem;
}

.btn-logout {
    background: #ef4444;
    color: white;
    border: none;
    padding: 0.5rem 1rem;
    border-radius: 8px;
    cursor: pointer;
    font-weight: 600;
    font-size: 0.9rem;
    transition: all 0.2s;
}

.btn-logout:hover {
    background: #dc2626;
    transform: translateY(-1px);
}

/* Main Content */
.main-content {
    display: grid;
    grid-template-columns: 2fr 1fr;
    column-gap:2rem ;
}

.state-container {
    grid-column: 1 / 2;
}

/* Cards */
.welcome-card,
.waiting-card,
.matched-card,
.stats-card,
.recent-matches,
.leaderboard,
.bot-fight {
    background: white;
    border-radius: 12px;
    padding: 2rem;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
    margin-bottom: 2rem;
}

.welcome-card {
    text-align: center;
    padding: 3rem 2rem;
}

.welcome-card h1 {
    font-size: 2.5rem;
    margin-bottom: 1rem;
    color: #2c3e50;
}

.welcome-card p {
    font-size: 1.1rem;
    color: #6b7280;
    margin-bottom: 2rem;
}

/* Buttons */
.btn {
    padding: 0.75rem 1.5rem;
    border: none;
    border-radius: 8px;
    font-size: 1rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
}

.btn-primary {
    background: linear-gradient(135deg, #667eea, #764ba2);
    color: white;
}

.btn-primary:hover {
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(102, 126, 234, 0.4);
}

.btn-large {
    padding: 1rem 2.5rem;
    font-size: 1.2rem;
}

.btn-secondary {
    background: #6b7280;
    color: white;
}

.btn-secondary:hover {
    background: #4b5563;
}

/* Stats */
.stats-card h2 {
    margin-bottom: 1.5rem;
    color: #2c3e50;
}

.stats-grid {
    display: grid;
    grid-template-columns: repeat(5, 1fr);
    gap: 1.5rem;
}

.stat-item {
    text-align: center;
    padding: 1rem;
    background:rgb(233, 235, 237);;
    border-radius: 8px;
}

.stat-label {
    display: block;
    font-size: 0.9rem;
    color: #6b7280;
    margin-bottom: 0.5rem;
}

.stat-value {
    display: block;
    font-size: 2rem;
    font-weight: 700;
    color: #667eea;
}

/* Waiting State */
.waiting-card {
    text-align: center;
    padding: 3rem 2rem;
}

.spinner-large {
    width: 80px;
    height: 80px;
    border: 6px solid #f3f3f3;
    border-top: 6px solid #667eea;
    border-radius: 50%;
    animation: spin 1s linear infinite;
    margin: 0 auto 2rem;
}

@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}

.waiting-card h2 {
    margin-bottom: 1.5rem;
    color: #2c3e50;
}

.waiting-card p {
    font-size: 1.1rem;
    color: #6b7280;
    margin-bottom: 1rem;
}

/* Matched State */
.matched-card {
    text-align: center;
    padding: 3rem 2rem;
}

.success-icon {
    width: 100px;
    height: 100px;
    background: linear-gradient(135deg, #10b981, #059669);
    color: white;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 3rem;
    margin: 0 auto 2rem;
    animation: scaleIn 0.5s ease-out;
}

@keyframes scaleIn {
    0% {
        transform: scale(0);
        opacity: 0;
    }
    100% {
        transform: scale(1);
        opacity: 1;
    }
}

.opponent-info {
    background: #f8f9fa;
    padding: 2rem;
    border-radius: 8px;
    margin: 2rem 0;
}

.opponent-info h3 {
    color: #6b7280;
    font-size: 0.9rem;
    margin-bottom: 0.5rem;
}

.opponent-name {
    font-size: 1.5rem;
    font-weight: 700;
    color: #2c3e50;
    margin-bottom: 0.5rem;
}

.opponent-elo {
    font-size: 1.1rem;
    color: #667eea;
    font-weight: 600;
}

.color-badge {
    display: inline-block;
    padding: 0.5rem 1rem;
    border-radius: 20px;
    font-weight: 600;
    text-transform: uppercase;
}

.color-badge.white {
    background: #f3f4f6;
    color: #1f2937;
}

.color-badge.black {
    background: #1f2937;
    color: white;
}

/* Match History */
.recent-matches {
    grid-column: 1 / 2;
    height: fit-content;
    align-self: start;
}

.recent-matches h2 {
    margin-bottom: 1.5rem;
    color: #2c3e50;
}

.match-list {
    display: flex;
    flex-direction: column;
    gap: 1rem;
}

.match-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 1rem;
    background: #f8f9fa;
    border-radius: 8px;
    transition: all 0.2s;
}

.match-item:hover {
    background: #e9ecef;
    transform: translateX(5px);
}

.match-opponent {
    font-weight: 600;
    color: #2c3e50;
}

.match-result {
    padding: 0.25rem 0.75rem;
    border-radius: 12px;
    font-size: 0.85rem;
    font-weight: 600;
}

.match-result.win {
    background: #d1fae5;
    color: #065f46;
}

.match-result.loss {
    background: #fee2e2;
    color: #991b1b;
}

.match-result.draw {
    background: #e5e7eb;
    color: #374151;
}

/* --- Leaderboard Component --- */
.leaderboard {
    grid-column: 2 / 3;
    grid-row: 1 / 4;
    height: fit-content;
    align-self: start;
    
    background: white;
    border-radius: 12px;
    padding: 20px;
}

.leaderboard h2 {
    margin-bottom: 1.5rem;
    color: #2c3e50;
    font-size: 1.25rem;
    font-weight: 700;
}

.leaderboard-list {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
}

/* Individual Rank Item Card */
.leaderboard-item {
    display: flex;
    align-items: center;
    gap: 1rem;
    padding: 1rem;
     background:rgb(233, 235, 237);
    border-radius: 12px; /* Smoother corners */
    transition: transform 0.2s ease, box-shadow 0.2s ease, background 0.2s ease;
    border: 1px solid transparent;
}

.leaderboard-item:hover {
    background: #ffffff;
    transform: translateX(5px); /* Subtle slide effect on hover */
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);
    border-color: #e5e7eb;
}

/* Rank Number Styling */
.rank {
    font-size: 1.5rem;
    font-weight: 800;
    color: #6366f1; /* Modern Indigo */
    min-width: 45px;
    text-align: center;
}

/* Podium Colors for Top Performers */
.rank.top1 { color: #FFD63A; } /* Gold */
.rank.top2 { color: #94a3b8; } /* Silver */
.rank.top3 { color: #F75A5A; } /* Bronze */

.player-info {
    flex: 1;
}

.player-name {
    font-weight: 600;
    color: #1f2937;
    margin-bottom: 0.125rem;
    display: block;
}

/* Secondary Information (ELO, Win Rate, etc.) */
.player-stats {
    font-size: 0.85rem;
    color: #6b7280;
    display: flex;
    gap: 8px;
}

/* Status Indicators */
.loading {
    text-align: center;
    color: #9ca3af;
    padding: 3rem;
    font-style: italic;
}

.empty-state {
    text-align: center;
    padding: 2rem;
    color: #6b7280;
    background: #f3f4f6;
    border-radius: 8px;
}

/* Responsive */
@media (max-width: 968px) {
    .main-content {
        grid-template-columns: 1fr;
    }

    .state-container,
    .recent-matches,
    .leaderboard {
        grid-column: 1 / 2;
    }

    .stats-grid {
        grid-template-columns: repeat(2, 1fr);
    }
}

@media (max-width: 480px) {
    .header {
        flex-direction: column;
        gap: 1rem;
        text-align: center;
    }

    .stats-grid {
        grid-template-columns: 1fr;
    }
}

.match-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px 16px;
    background:rgb(233, 235, 237);
    border-radius: 12px;
    margin-bottom: 10px;
    border: 1px solid #f0f0f0;
    transition: all 0.2s ease;
    box-shadow: 0 2px 4px rgba(0,0,0,0.02);
}

.match-item:hover {
    box-shadow: 0 4px 12px rgba(0,0,0,0.08);
    transform: translateY(-2px);
    border-color: #e5e7eb;
}


.match-main-info {
    display: flex;
    align-items: center;
    gap: 12px;
}

.piece-color-indicator {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    border: 2px solid #ddd;
}
.piece-color-indicator.white { background: #fff; border-color: #d1d5db; }
.piece-color-indicator.black { background: #374151; border-color: #111827; }

.opponent-row {
    display: flex;
    align-items: baseline;
    gap: 6px;
    margin-bottom: 2px;
}

.opponent-name {
    font-weight: 600;
    color: #1f2937;
    font-size: 1rem;
}

.opponent-elo {
    font-size: 0.8rem;
    color: #9ca3af;
}

.match-time {
    font-size: 0.75rem;
    color: #6b7280;
    display: flex;
    gap: 4px;
}

.match-result-badge {
    padding: 6px 12px;
    border-radius: 20px;
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.025em;
    min-width: 70px;
    text-align: center;
}

.win { background-color:rgb(170, 224, 189); color:rgb(7, 125, 52); }
.loss { background-color:rgb(227, 163, 163); color:rgb(135, 15, 15); }
.draw { background-color:rgb(255, 255, 255); color:rgb(43, 58, 82); }

.pagination-nav {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 12px;
    margin-top: 20px;
}

.pagination-buttons {
    display: flex;
    gap: 8px;
}

.pagination-btn {
    width: 40px;
    height: 40px;
    border-radius: 10px;
    border: 1px solid #e5e7eb;
    background: white;
    cursor: pointer;
    font-weight: 600;
    transition: all 0.2s;
}

.pagination-btn:hover:not(:disabled) {
    background-color: #3b82f6;
    color: white;
    border-color: #3b82f6;
}

.bot-fight {
    text-align: center;
    padding: 3rem 2rem;
}

.bot-fight h1 {
    font-size: 2.5rem;
    margin-bottom: 1rem;
    color: #2c3e50;
}

.bot-fight p {
    font-size: 1.1rem;
    color: #6b7280;
    margin-bottom: 2rem;
}

/* Bot Fight Section */
.bot-fight-section {
    background: white;
    border-radius: 12px;
    padding: 2rem;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
    margin-bottom: 2rem;
}

.bot-difficulty-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
    gap: 1.5rem;
    margin-top: 1.5rem;
}

.bot-card {
    background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
    border-radius: 12px;
    padding: 1.5rem;
    transition: all 0.3s ease;
    border: 2px solid transparent;
}

.bot-card:hover {
    transform: translateY(-5px);
    box-shadow: 0 8px 24px rgba(0, 0, 0, 0.15);
}

.bot-card[data-difficulty="beginner"]:hover { border-color: #10b981; }
.bot-card[data-difficulty="easy"]:hover { border-color: #3b82f6; }
.bot-card[data-difficulty="medium"]:hover { border-color: #f59e0b; }
.bot-card[data-difficulty="hard"]:hover { border-color: #ef4444; }
.bot-card[data-difficulty="expert"]:hover { border-color: #8b5cf6; }

.bot-header {
    display: flex;
    align-items: center;
    gap: 1rem;
    margin-bottom: 1rem;
}

.bot-icon {
    font-size: 3rem;
    width: 60px;
    height: 60px;
    display: flex;
    align-items: center;
    justify-content: center;
    background: white;
    border-radius: 12px;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
}

.bot-info { flex: 1; }

.bot-name {
    font-size: 1.1rem;
    font-weight: 700;
    color: #1f2937;
    margin: 0 0 0.25rem 0;
}

.bot-elo {
    font-size: 0.9rem;
    color: #6b7280;
    font-weight: 600;
}

.bot-description {
    color: #4b5563;
    font-size: 0.9rem;
    line-height: 1.5;
    margin-bottom: 1rem;
    min-height: 60px;
}

.bot-stats {
    display: flex;
    gap: 0.5rem;
    margin-bottom: 1rem;
}

.bot-stats .stat-badge {
    background: white;
    padding: 0.25rem 0.75rem;
    border-radius: 20px;
    font-size: 0.8rem;
    color: #6b7280;
    font-weight: 600;
}

.btn-play-bot {
    width: 100%;
    padding: 0.75rem;
    font-size: 1rem;
    font-weight: 600;
    border: none;
    border-radius: 8px;
    transition: all 0.2s;
    cursor: pointer;
    color: white;
}

.bot-card[data-difficulty="beginner"] .btn-play-bot {
    background: linear-gradient(135deg, #10b981, #059669);
}

.bot-card[data-difficulty="easy"] .btn-play-bot {
    background: linear-gradient(135deg, #3b82f6, #2563eb);
}

.bot-card[data-difficulty="medium"] .btn-play-bot {
    background: linear-gradient(135deg, #f59e0b, #d97706);
}

.bot-card[data-difficulty="hard"] .btn-play-bot {
    background: linear-gradient(135deg, #ef4444, #dc2626);
}

.bot-card[data-difficulty="expert"] .btn-play-bot {
    background: linear-gradient(135deg, #8b5cf6, #7c3aed);
}

.btn-play-bot:hover {
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
}

@media (max-width: 768px) {
    .bot-difficulty-grid {
        grid-template-columns: 1fr;
    }
}


================================================
FILE: static/css/review/review.css
================================================
/* ==================== RESET & BASE ==================== */
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: linear-gradient(135deg, rgb(169, 176, 205) 0%, rgb(195, 172, 219) 100%);
    color: #333;
    min-height: 100vh;
}

/* ==================== LOADING OVERLAY ==================== */
.overlay {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.9);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 10000;
    transition: opacity 0.3s ease;
}

.overlay.hidden {
    opacity: 0;
    pointer-events: none;
}

.overlay-content {
    text-align: center;
    color: white;
}

.overlay-content h2 {
    margin: 1rem 0 0.5rem 0;
}

.overlay-content p {
    color: rgba(255, 255, 255, 0.8);
}

.spinner-large {
    width: 60px;
    height: 60px;
    border: 5px solid rgba(255, 255, 255, 0.2);
    border-top: 5px solid #fff;
    border-radius: 50%;
    animation: spin 1s linear infinite;
    margin: 0 auto;
}

@keyframes spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
}

/* ==================== CONTAINER ==================== */
.review-container {
    max-width: 1800px;
    margin: 0 auto;
    padding: 20px;
}

/* ==================== HEADER ==================== */
.review-header {
    background: white;
    border-radius: 12px;
    padding: 1.5rem 2rem;
    margin-bottom: 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.header-left, .header-right {
    flex: 1;
}

.header-center {
    text-align: center;
    flex: 2;
}

.header-center h1 {
    font-size: 1.8rem;
    color: #1e3c72;
    margin-bottom: 0.25rem;
}

.match-id {
    font-size: 0.9rem;
    color: #6b7280;
}

.btn-back {
    background: #6b7280;
    color: white;
    border: none;
    padding: 0.5rem 1rem;
    border-radius: 8px;
    cursor: pointer;
    font-size: 0.9rem;
    transition: all 0.2s;
}

.btn-back:hover {
    background: #4b5563;
    transform: translateX(-2px);
}

.header-right {
    display: flex;
    gap: 0.5rem;
    justify-content: flex-end;
}

.btn-secondary {
    background: #667eea;
    color: white;
    border: none;
    padding: 0.5rem 1rem;
    border-radius: 8px;
    cursor: pointer;
    font-size: 0.9rem;
    transition: all 0.2s;
}

.btn-secondary:hover {
    background: #5a67d8;
}

/* ==================== GAME INFO BANNER ==================== */
.game-info-banner {
    background: white;
    border-radius: 12px;
    padding: 2rem;
    margin-bottom: 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.player-info-card {
    flex: 1;
    display: flex;
    align-items: center;
    gap: 1rem;
}

.player-info-card.white {
    border-left: 4px solid #f3f4f6;
    padding-left: 1rem;
}

.player-info-card.black {
    border-right: 4px solid #1f2937;
    padding-right: 1rem;
    flex-direction: row-reverse;
}

.piece-icon {
    font-size: 3rem;
}

.player-details {
    flex: 1;
}

.player-name {
    font-size: 1.2rem;
    font-weight: 700;
    color: #1f2937;
}

.player-elo {
    color: #6b7280;
    font-size: 0.9rem;
}

.player-stats {
    display: flex;
    gap: 0.5rem;
    flex-wrap: wrap;
}

.stat-badge {
    background: #f8f9fa;
    padding: 0.5rem 0.75rem;
    border-radius: 8px;
    text-align: center;
}

.stat-badge .stat-label {
    display: block;
    font-size: 0.75rem;
    color: #6b7280;
}

.stat-badge .stat-value {
    display: block;
    font-size: 1.2rem;
    font-weight: 700;
    margin-top: 0.25rem;
}

.stat-badge.blunders .stat-value { color: #ef4444; }
.stat-badge.mistakes .stat-value { color: #f59e0b; }
.stat-badge.inaccuracies .stat-value { color: #f59e0b; }
.stat-badge.avg-loss .stat-value { color: #6b7280; }

.vs-divider {
    text-align: center;
    padding: 0 2rem;
}

.result-badge {
    background: linear-gradient(135deg, #667eea, #764ba2);
    color: white;
    padding: 0.75rem 1.5rem;
    border-radius: 20px;
    font-size: 1.5rem;
    font-weight: 700;
    margin-bottom: 0.5rem;
}

.game-date {
    color: #6b7280;
    font-size: 0.9rem;
}

/* ==================== CONTENT LAYOUT ==================== */
.review-content {
    display: grid;
    grid-template-columns: 650px 1fr;
    gap: 20px;
}

/* ==================== BOARD PANEL ==================== */
.board-panel {
    display: flex;
    flex-direction: column;
    gap: 1rem;
}

.board-wrapper {
    background: white;
    border-radius: 12px;
    padding: 1rem;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

#reviewBoard {
    width: 100%;
    height: auto;
}

/* Board Controls */
.board-controls {
    display: flex;
    gap: 0.5rem;
    justify-content: center;
    background: white;
    padding: 1rem;
    border-radius: 12px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.control-btn {
    background: #667eea;
    color: white;
    border: none;
    padding: 0.75rem 1.25rem;
    border-radius: 8px;
    cursor: pointer;
    font-size: 1.2rem;
    transition: all 0.2s;
}

.control-btn:hover {
    background: #5a67d8;
    transform: translateY(-2px);
}

.control-btn:active {
    transform: translateY(0);
}

/* Current Move Card */
.current-move-card {
    background: white;
    border-radius: 12px;
    padding: 1.5rem;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.move-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1rem;
}

.move-header h3 {
    font-size: 1.2rem;
    color: #1f2937;
}

.judgment-badge {
    padding: 0.5rem 1rem;
    border-radius: 20px;
    font-weight: 700;
    font-size: 0.9rem;
}

.judgment-badge.ok {
    background: #d1fae5;
    color: #065f46;
}

.judgment-badge.inaccuracy {
    background: #fef3c7;
    color: #92400e;
}

.judgment-badge.mistake {
    background: #fed7aa;
    color: #9a3412;
}

.judgment-badge.blunder {
    background: #fee2e2;
    color: #991b1b;
}

.eval-display {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 1rem;
    padding: 1rem;
    background: #f8f9fa;
    border-radius: 8px;
    margin-bottom: 1rem;
}

.eval-item {
    text-align: center;
}

.eval-label {
    display: block;
    font-size: 0.85rem;
    color: #6b7280;
    margin-bottom: 0.25rem;
}

.eval-value {
    display: block;
    font-size: 1.5rem;
    font-weight: 700;
    color: #1f2937;
}

.eval-arrow {
    font-size: 1.5rem;
    color: #6b7280;
}

.best-move-container {
    background: #fef3c7;
    border: 2px solid #f59e0b;
    border-radius: 8px;
    padding: 1rem;
}

.best-move-header {
    font-weight: 700;
    color: #92400e;
    margin-bottom: 0.5rem;
}

.best-move-content {
    display: flex;
    align-items: center;
    gap: 0.5rem;
    font-size: 0.95rem;
}

.best-move-content .label {
    color: #92400e;
    font-weight: 600;
}

.best-move-content .move {
    font-family: monospace;
    font-size: 1.2rem;
    font-weight: 700;
    color: #1f2937;
}

.best-move-content .loss {
    color: #ef4444;
    font-weight: 600;
}

/* Evaluation Graph */
.eval-graph-card {
    background: white;
    border-radius: 12px;
    padding: 1.5rem;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
    height: 350px;
}

.eval-graph-card h3 {
    margin-bottom: 1rem;
    color: #1f2937;
}
.eval-graph-card canvas {
    max-height: 280px !important; /* Để trống cho title */
    height: 280px !important;
}

/* ==================== ANALYSIS PANEL ==================== */
.analysis-panel {
    display: flex;
    flex-direction: column;
    gap: 1rem;
}

/* Stats Summary */
.stats-summary-card {
    background: white;
    border-radius: 12px;
    padding: 1.5rem;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.stats-summary-card h3 {
    margin-bottom: 1rem;
    color: #1f2937;
}

.summary-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1rem;
}

.summary-item {
    text-align: center;
    padding: 1rem;
    background: #f8f9fa;
    border-radius: 8px;
}

.summary-item .label {
    display: block;
    font-size: 0.85rem;
    color: #6b7280;
    margin-bottom: 0.5rem;
}

.summary-item .value {
    display: block;
    font-size: 2rem;
    font-weight: 700;
    color: #1f2937;
}

.summary-item .value.accurate { color: #10b981; }
.summary-item .value.errors { color: #ef4444; }
.summary-item .value.critical { color: #f59e0b; }

/* Move List */
.move-list-card {
    background: white;
    border-radius: 12px;
    padding: 1.5rem;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
    /* flex: 1; */
    display: flex;
    flex-direction: column;
}

.move-list-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1rem;
}

.move-list-header h3 {
    color: #1f2937;
}

.filter-buttons {
    display: flex;
    gap: 0.5rem;
}

.filter-btn {
    background: #f3f4f6;
    border: none;
    padding: 0.5rem 1rem;
    border-radius: 6px;
    cursor: pointer;
    font-size: 0.85rem;
    transition: all 0.2s;
}

.filter-btn:hover {
    background: #e5e7eb;
}

.filter-btn.active {
    background: #667eea;
    color: white;
}

.move-list-container {
    flex: 1;
    overflow-y: auto;
    max-height: 600px;
}

.move-item {
    padding: 1rem;
    margin-bottom: 0.5rem;
    background: #f8f9fa;
    border-radius: 8px;
    cursor: pointer;
    transition: all 0.2s;
}

.move-item:hover {
    background: #e5e7eb;
    transform: translateX(5px);
}

.move-item.active {
    background: #667eea;
    color: white;
}

.move-item-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 0.5rem;
}

.move-number {
    font-weight: 700;
    font-size: 1.1rem;
}

.move-eval {
    font-family: monospace;
    font-size: 0.9rem;
}

.move-item-body {
    display: flex;
    justify-content: space-between;
    align-items: center;
}

.move-san {
    font-family: monospace;
    font-size: 1rem;
    font-weight: 600;
}

.move-judgment {
    padding: 0.25rem 0.75rem;
    border-radius: 12px;
    font-size: 0.75rem;
    font-weight: 700;
}

.move-judgment.ok { background: rgba(16, 185, 129, 0.2); }
.move-judgment.inaccuracy { background: rgba(245, 158, 11, 0.2); }
.move-judgment.mistake { background: rgba(249, 115, 22, 0.2); }
.move-judgment.blunder { background: rgba(239, 68, 68, 0.2); }

.move-item.active .move-judgment {
    background: rgba(255, 255, 255, 0.3);
    color: white;
}

/* Key Moments */
.key-moments-card {
    background: white;
    border-radius: 12px;
    padding: 1.5rem;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
    height: 550px;
    
}

.key-moments-card h3 {
    margin-bottom: 1rem;
    color: #1f2937;
}

.key-moments-list {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
    height: 90%;
    overflow-y: auto;     
    overflow-x: hidden;
    scrollbar-width: thin;
}

.key-moment-item {
    padding: 1rem;
    background: #fef3c7;
    border-left: 4px solid #f59e0b;
    border-radius: 8px;
    cursor: pointer;
    transition: all 0.2s;
}

.key-moment-item:hover {
    background: #fde68a;
}

.key-moment-header {
    display: flex;
    justify-content: space-between;
    margin-bottom: 0.5rem;
}

.key-moment-move {
    font-weight: 700;
    color: #92400e;
}

.key-moment-type {
    font-size: 0.85rem;
    padding: 0.25rem 0.5rem;
    background: #ef4444;
    color: white;
    border-radius: 6px;
}

.key-moment-description {
    font-size: 0.9rem;
    color: #92400e;
}

/* ==================== MODALS ==================== */
.modal {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.8);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 9999;
}

.modal.hidden {
    display: none;
}

.modal-content {
    background: white;
    border-radius: 16px;
    padding: 2rem;
    max-width: 500px;
    width: 90%;
    position: relative;
}

.modal-content.error {
    text-align: center;
}

.modal-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1.5rem;
}

.modal-header h3 {
    color: #1f2937;
}

.modal-close {
    background: none;
    border: none;
    font-size: 2rem;
    cursor: pointer;
    color: #6b7280;
    line-height: 1;
}

.modal-close:hover {
    color: #1f2937;
}

.error-icon {
    font-size: 4rem;
    margin-bottom: 1rem;
}

.share-link-container {
    display: flex;
    gap: 0.5rem;
    margin-top: 1rem;
}

.share-link-container input {
    flex: 1;
    padding: 0.75rem;
    border: 2px solid #e5e7eb;
    border-radius: 8px;
    font-family: monospace;
}

.btn-primary {
    background: #667eea;
    color: white;
    border: none;
    padding: 0.75rem 1.5rem;
    border-radius: 8px;
    cursor: pointer;
    font-weight: 600;
    transition: all 0.2s;
}

.btn-primary:hover {
    background: #5a67d8;
}

/* ==================== RESPONSIVE ==================== */
@media (max-width: 1400px) {
    .review-content {
        grid-template-columns: 1fr;
    }
    
    .summary-grid {
        grid-template-columns: repeat(2, 1fr);
    }
}

@media (max-width: 768px) {
    .review-header {
        flex-direction: column;
        gap: 1rem;
    }
    
    .header-left, .header-center, .header-right {
        flex: none;
        width: 100%;
    }
    
    .game-info-banner {
        flex-direction: column;
        gap: 1.5rem;
    }
    
    .player-info-card {
        width: 100%;
    }
    
    .vs-divider {
        padding: 1rem 0;
    }
    
    .summary-grid {
        grid-template-columns: 1fr;
    }
}

/* ==================== SCROLLBAR ==================== */
.move-list-container::-webkit-scrollbar {
    width: 8px;
}

.move-list-container::-webkit-scrollbar-track {
    background: #f1f1f1;
    border-radius: 4px;
}

.move-list-container::-webkit-scrollbar-thumb {
    background: #888;
    border-radius: 4px;
}

.move-list-container::-webkit-scrollbar-thumb:hover {
    background: #555;
}


================================================
FILE: static/js/auth/confirm.js
================================================

// DOM Elements
const manualConfirmForm = document.getElementById('manualConfirmForm');
const tokenInput = document.getElementById('tokenInput');
const confirmBtn = document.getElementById('confirmBtn');
const btnSpinner = document.getElementById('btnSpinner');
const messageDiv = document.getElementById('message');

// Handle manual confirmation form
manualConfirmForm.addEventListener('submit', async function(e) {
    e.preventDefault();

    const token = tokenInput.value.trim();

    if (!token) {
        showMessage('Please enter a confirmation token', 'error');
        return;
    }

    // Show loading state
    setLoadingState(true);

    try {
        const response = await fetch(`/api/auth/confirm/${token}`, {
            method: 'GET',
        });

        const result = await response.json();

        if (response.ok) {
            showMessage('Email confirmed successfully! Redirecting to login...', 'success');
            // Redirect to login after success
            setTimeout(() => {
                window.location.href = '/login';
            }, 2000);
        } else {
            showMessage(result.message || 'Confirmation failed. Please check your token.', 'error');
        }
    } catch (error) {
        console.error('Confirmation error:', error);
        showMessage('Network error. Please try again.', 'error');
    } finally {
        setLoadingState(false);
    }
});

function setLoadingState(loading) {
    confirmBtn.disabled = loading;
    btnSpinner.classList.toggle('show', loading);

    const btnText = confirmBtn.querySelector('.btn-text');
    if (loading) {
        btnText.textContent = 'Confirming...';
    } else {
        btnText.textContent = 'Confirm Email';
    }
}

function showMessage(message, type) {
    messageDiv.textContent = message;
    messageDiv.className = `message ${type}`;
    messageDiv.style.display = 'block';

    // Scroll to message
    messageDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}



================================================
FILE: static/js/auth/login.js
================================================
document.getElementById('loginForm').addEventListener('submit', async function(e) {
    e.preventDefault();

    const messageDiv = document.getElementById('message');
    const submitBtn = this.querySelector('button[type="submit"]');

    // Clear previous messages
    messageDiv.style.display = 'none';
    messageDiv.className = 'message';

    // Get form data
    const formData = new FormData(this);
    const data = {
        mail: formData.get('mail').trim(),
        password: formData.get('password')
    };

    // Basic validation
    if (!data.mail || !data.password) {
        showMessage('Please fill in all fields', 'error');
        return;
    }

    // Disable button
    submitBtn.disabled = true;
    submitBtn.textContent = 'Logging in...';

    try {
        const response = await fetch('/api/auth/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include', // Include cookies
            body: JSON.stringify(data)
        });

        const result = await response.json();

        if (response.ok) {
            showMessage('Login successful! Redirecting...', 'success');
            // Redirect to home page
            setTimeout(() => {
                window.location.href = '/home'; 
            }, 1000);
        } else {
            showMessage(result.message || 'Login failed', 'error');
        }
    } catch (error) {
        console.error('Login error:', error);
        showMessage('Network error. Please try again.', 'error');
    } finally {
        // Re-enable button
        submitBtn.disabled = false;
        submitBtn.textContent = 'Login';
    }
});

function showMessage(message, type) {
    const messageDiv = document.getElementById('message');
    messageDiv.textContent = message;
    messageDiv.className = `message ${type}`;
    messageDiv.style.display = 'block';
}



================================================
FILE: static/js/auth/register.js
================================================
// DOM Elements
const registerForm = document.getElementById('registerForm');
const nameInput = document.getElementById('name');
const mailInput = document.getElementById('mail');
const passwordInput = document.getElementById('password');
const confirmPasswordInput = document.getElementById('confirmPassword');

const registerBtn = document.getElementById('registerBtn');
const btnSpinner = document.getElementById('btnSpinner');
const passwordToggle = document.getElementById('passwordToggle');
const strengthBar = document.getElementById('strengthBar');
const strengthText = document.getElementById('strengthText');

// Error message elements
const nameError = document.getElementById('nameError');
const mailError = document.getElementById('mailError');
const passwordError = document.getElementById('passwordError');
const confirmPasswordError = document.getElementById('confirmPasswordError');

// Password visibility toggle
passwordToggle.addEventListener('click', function() {
    const type = passwordInput.type === 'password' ? 'text' : 'password';
    passwordInput.type = type;
    this.querySelector('.eye-icon').textContent = type === 'password' ? '👁️' : '🙈';
});

// Password strength checker
passwordInput.addEventListener('input', function() {
    const password = this.value;
    const strength = checkPasswordStrength(password);
    updatePasswordStrength(strength);
});

function checkPasswordStrength(password) {
    let score = 0;

    // Length check
    if (password.length >= 8) score++;
    if (password.length >= 12) score++;

    // Character variety
    if (/[a-z]/.test(password)) score++;
    if (/[A-Z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;

    return score;
}

function updatePasswordStrength(score) {
    const strengthMeter = strengthBar.parentElement.parentElement;

    // Remove existing classes
    strengthMeter.classList.remove('strength-weak', 'strength-medium', 'strength-strong');

    if (score < 3) {
        strengthMeter.classList.add('strength-weak');
        strengthText.textContent = 'Weak password';
    } else if (score < 5) {
        strengthMeter.classList.add('strength-medium');
        strengthText.textContent = 'Medium password';
    } else {
        strengthMeter.classList.add('strength-strong');
        strengthText.textContent = 'Strong password';
    }
}

// Real-time validation
nameInput.addEventListener('blur', () => validateName());
mailInput.addEventListener('blur', () => validateEmail());
passwordInput.addEventListener('blur', () => validatePassword());
confirmPasswordInput.addEventListener('blur', () => validateConfirmPassword());

function validateName() {
    const name = nameInput.value.trim();
    if (!name) {
        showError(nameError, 'Name is required');
        return false;
    }
    if (name.length < 2) {
        showError(nameError, 'Name must be at least 2 characters');
        return false;
    }
    if (name.length > 50) {
        showError(nameError, 'Name must be less than 50 characters');
        return false;
    }
    hideError(nameError);
    return true;
}

function validateEmail() {
    const email = mailInput.value.trim();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!email) {
        showError(mailError, 'Email is required');
        return false;
    }
    if (!emailRegex.test(email)) {
        showError(mailError, 'Please enter a valid email address');
        return false;
    }
    hideError(mailError);
    return true;
}

function validatePassword() {
    const password = passwordInput.value;

    if (!password) {
        showError(passwordError, 'Password is required');
        return false;
    }
    if (password.length < 8) {
        showError(passwordError, 'Password must be at least 8 characters');
        return false;
    }

    // Check for at least one lowercase, one uppercase, one number
    const hasLower = /[a-z]/.test(password);
    const hasUpper = /[A-Z]/.test(password);
    const hasNumber = /[0-9]/.test(password);

    if (!hasLower || !hasUpper || !hasNumber) {
        showError(passwordError, 'Password must contain at least one lowercase letter, one uppercase letter, and one number');
        return false;
    }

    hideError(passwordError);
    return true;
}

function validateConfirmPassword() {
    const password = passwordInput.value;
    const confirmPassword = confirmPasswordInput.value;

    if (!confirmPassword) {
        showError(confirmPasswordError, 'Please confirm your password');
        return false;
    }
    if (password !== confirmPassword) {
        showError(confirmPasswordError, 'Passwords do not match');
        return false;
    }
    hideError(confirmPasswordError);
    return true;
}

function validateTerms() {
    if (!termsCheckbox.checked) {
        showError(document.querySelector('.terms-group'), 'You must agree to the Terms of Service and Privacy Policy');
        return false;
    }
    hideError(document.querySelector('.terms-group'));
    return true;
}

function showError(element, message) {
    element.textContent = message;
    element.style.display = 'block';
    element.parentElement.classList.add('error');
}

function hideError(element) {
    element.textContent = '';
    element.style.display = 'none';
    element.parentElement.classList.remove('error');
}

// Form submission
registerForm.addEventListener('submit', async function(e) {
    e.preventDefault();

    // Validate all fields
    const isNameValid = validateName();
    const isEmailValid = validateEmail();
    const isPasswordValid = validatePassword();
    const isConfirmPasswordValid = validateConfirmPassword();

    if (!isNameValid || !isEmailValid || !isPasswordValid || !isConfirmPasswordValid) {
        showMessage('Please correct the errors above', 'error');
        return;
    }

    // Show loading state
    setLoadingState(true);

    // Prepare data
    const formData = {
        name: nameInput.value.trim(),
        mail: mailInput.value.trim().toLowerCase(),
        password: passwordInput.value
    };

    try {
        const response = await fetch('/api/auth/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(formData)
        });

        const result = await response.json();

        if (response.ok) {
            showMessage('Registration successful! Please check your email to confirm your account.', 'success');

            // Clear form
            registerForm.reset();

            // Reset password strength
            updatePasswordStrength(0);

            // Redirect to confirm after success
            setTimeout(() => {
                window.location.href = '/confirm';
            }, 3000);

        } else {
            showMessage(result.message || 'Registration failed', 'error');
        }
    } catch (error) {
        console.error('Registration error:', error);
        showMessage('Network error. Please try again.', 'error');
    } finally {
        setLoadingState(false);
    }
});

function setLoadingState(loading) {
    registerBtn.disabled = loading;
    btnSpinner.classList.toggle('show', loading);

    const btnText = registerBtn.querySelector('.btn-text');
    if (loading) {
        btnText.textContent = 'Creating Account...';
    } else {
        btnText.textContent = 'Create Account';
    }
}

function showMessage(message, type) {
    const messageDiv = document.getElementById('message');
    messageDiv.textContent = message;
    messageDiv.className = `message ${type}`;
    messageDiv.style.display = 'block';

    // Scroll to message
    messageDiv.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// Initialize password strength on page load
updatePasswordStrength(0);



================================================
FILE: static/js/game/bot_game.js
================================================
// ==================== BOT GAME STATE ====================
let socket = null;
let game = null;
let board = null;
let matchId = null;
let userId = null;
let playerColor = null;
let botDifficulty = null;
let isMyTurn = false;
let gameActive = true;

// ==================== INITIALIZATION ====================
document.addEventListener('DOMContentLoaded', async () => {
    const urlParams = new URLSearchParams(window.location.search);
    matchId = urlParams.get('match_id');
    botDifficulty = urlParams.get('difficulty') || 'medium';
    
    setTimeout(() => {
        document.getElementById('loadingOverlay').classList.add('hidden');
    }, 1000);
    
    await loadUserInfo();
    initializeSocket();
    game = new Chess();
    setupEventListeners();
    initPromotionHandlers();
});

// ==================== LOAD USER INFO ====================
async function loadUserInfo() {
    try {
        const response = await fetch('/api/auth/me', {
            credentials: 'include'
        });
        
        if (response.ok) {
            const data = await response.json();
            userId = data.user_id;
            document.getElementById('yourName').textContent = data.name;
            document.getElementById('yourElo').textContent = data.elo;
        } else {
            window.location.href = '/login';
        }
    } catch (error) {
        console.error('Failed to load user info:', error);
    }
}

// ==================== WEBSOCKET SETUP ====================
function initializeSocket() {
    socket = io({
        transports: ['websocket', 'polling'],
        reconnection: true
    });
    
    socket.on('connect', () => {
        console.log('[+] Connected to server');
        updateConnectionStatus(true);
        
        if (matchId && matchId !== 'null' && matchId !== 'undefined') {
            // Join existing match
            console.log('[+] Joining existing match:', matchId);
            socket.emit('join_bot_match', {
                match_id: matchId,
                user_id: userId
            });
        } else {
            // Create new match
            console.log('[+] Creating new bot match, difficulty:', botDifficulty);
            socket.emit('create_bot_match', {
                user_id: userId,
                difficulty: botDifficulty
            });
        }
    });
    
    socket.on('disconnect', () => {
        console.log('[-] Disconnected');
        updateConnectionStatus(false);
    });
    
    socket.on('bot_match_created', (data) => {
        console.log('[+] Bot match created:', data);
        
        matchId = data.match_id;
        playerColor = data.your_color;
        botDifficulty = data.bot.difficulty;
        
        // Update URL without reloading
        const newUrl = `/game/bot?match_id=${matchId}&difficulty=${botDifficulty}`;
        window.history.pushState({}, '', newUrl);
        
        // Update UI
        updateBotMatchUI(data);
        
        // Initialize board AFTER getting match info
        initializeBoard();
        updateTurnIndicator();
        
        console.log('[+] Board initialized, player color:', playerColor);
    });
    
    socket.on('bot_match_joined', (data) => {
        console.log('[+] Bot match joined:', data);
        
        playerColor = data.your_color;
        botDifficulty = data.bot.difficulty;
        
        // Update UI
        updateBotMatchUI(data);
        
        // Initialize board
        initializeBoard();
        
        // Load existing moves if any
        if (data.pgn && data.pgn.trim() !== '') {
            loadPGN(data.pgn);
        }
        
        updateTurnIndicator();
    });
    
    socket.on('move_accepted', (data) => {
        console.log('[+] Move accepted:', data.move);
        isMyTurn = false;
        updateTurnIndicator();
        showNotification('Waiting for bot...', 'info');
    });
    
    socket.on('bot_move', (data) => {
        console.log('[+] Bot moved:', data.move);
        
        const move = game.move(data.move);
        
        if (move) {
            board.position(game.fen());
            addMoveToHistory(move);
            updateCapturedPieces();
            updateTurnIndicator();
            
            checkGameState();
            playMoveSound();
            
            isMyTurn = true;
            showNotification('Your turn!', 'success');
        } else {
            console.error('[-] Failed to apply bot move:', data.move);
        }
    });
    
    socket.on('move_error', (data) => {
        console.error('[-] Move error:', data.message);
        showError(data.message);
    });
    
    socket.on('bot_game_ended', (data) => {
        console.log('[+] Bot game ended:', data);
        gameActive = false;
        showBotGameEndModal(data);
    });
    
    socket.on('error', (data) => {
        console.error('[-] Socket error:', data.message);
        showError(data.message);
    });
}

// ==================== UPDATE UI ====================
function updateBotMatchUI(data) {
    document.getElementById('yourColor').innerHTML = 
        `<span class="color-piece">${playerColor === 'white' ? '♔' : '♚'}</span> ${playerColor}`;
    
    document.getElementById('opponentName').textContent = data.bot.name;
    document.getElementById('opponentElo').textContent = data.bot.elo;
    document.getElementById('opponentColor').innerHTML = 
        `<span class="color-piece">${playerColor === 'white' ? '♚' : '♔'}</span> ${playerColor === 'white' ? 'black' : 'white'}`;
    
    document.querySelector('#opponentStatus .status-dot').classList.add('online');
    document.getElementById('matchIdDisplay').textContent = matchId;
}

// ==================== BOARD INITIALIZATION ====================
function initializeBoard() {
    const config = {
        position: 'start',
        orientation: playerColor,
        draggable: true,
        onDragStart: onDragStart,
        onDrop: onDrop,
        onSnapEnd: onSnapEnd,
        pieceTheme: 'https://chessboardjs.com/img/chesspieces/wikipedia/{piece}.png'
    };
    
    board = Chessboard('chessboard', config);
    $(window).resize(() => board.resize());
}

// ==================== CHESS LOGIC ====================
function onDragStart(source, piece, position, orientation) {
    if (!gameActive) {
        showNotification("Game is over", 'warning');
        return false;
    }
    
    if (!isMyTurn) {
        showNotification("Wait for bot's move!", 'warning');
        return false;
    }
    
    if ((playerColor === 'white' && piece.search(/^b/) !== -1) ||
        (playerColor === 'black' && piece.search(/^w/) !== -1)) {
        return false;
    }
    
    return true;
}

function onDrop(source, target) {
    if (isPromotionMove(source, target)) {
        showPromotionModal(source, target, (promotionPiece) => {
            executeMoveWithPromotion(source, target, promotionPiece);
        });
        return 'snapback';
    }
    
    return executeMove(source, target);
}

function executeMove(source, target, promotion = null) {
    const moveConfig = { from: source, to: target };
    if (promotion) moveConfig.promotion = promotion;
    
    const move = game.move(moveConfig);
    
    if (!move) {
        return 'snapback';
    }
    
    socket.emit('bot_player_move', {
        match_id: matchId,
        user_id: userId,
        move: move.san,
        fen: game.fen()
    });
    
    addMoveToHistory(move);
    updateCapturedPieces();
    checkGameState();
    
    return null;
}

function executeMoveWithPromotion(source, target, promotionPiece) {
    const move = game.move({
        from: source,
        to: target,
        promotion: promotionPiece
    });
    
    if (move) {
        board.position(game.fen());
        
        socket.emit('bot_player_move', {
            match_id: matchId,
            user_id: userId,
            move: move.san,
            fen: game.fen()
        });
        
        addMoveToHistory(move);
        updateCapturedPieces();
        checkGameState();
        playPromotionSound();
    }
}

function onSnapEnd() {
    board.position(game.fen());
}

// ==================== GAME STATE ====================
function checkGameState() {
    updateTurnIndicator();
    
    if (game.game_over()) {
        gameActive = false;
    } else if (game.in_check()) {
        const turn = game.turn() === 'w' ? 'White' : 'Black';
        showNotification(`${turn} is in check!`, 'warning');
    }
}

function updateTurnIndicator() {
    const currentTurn = game.turn();
    const turnColor = currentTurn === 'w' ? 'White' : 'Black';
    
    document.getElementById('turnIndicator').textContent = turnColor;
    const moveCount = Math.floor(game.history().length / 2) + 1;
    document.getElementById('moveNumber').textContent = moveCount;
    
    const indicator = document.getElementById('moveIndicator');
    const indicatorText = indicator.querySelector('.indicator-text');
    
    if ((currentTurn === 'w' && playerColor === 'white') ||
        (currentTurn === 'b' && playerColor === 'black')) {
        isMyTurn = true;
        indicator.classList.add('your-turn');
        indicatorText.textContent = 'Your turn!';
    } else {
        isMyTurn = false;
        indicator.classList.remove('your-turn');
        indicatorText.textContent = 'Bot is thinking...';
    }
}

function addMoveToHistory(move) {
    const history = document.getElementById('moveHistory');
    const noMoves = history.querySelector('.no-moves');
    if (noMoves) noMoves.remove();
    
    const moveNumber = Math.ceil(game.history().length / 2);
    const isWhiteMove = move.color === 'w';
    
    let currentRow = history.querySelector(`[data-move="${moveNumber}"]`);
    
    if (isWhiteMove) {
        currentRow = document.createElement('div');
        currentRow.className = 'move-row';
        currentRow.dataset.move = moveNumber;
        currentRow.innerHTML = `
            <div class="move-number">${moveNumber}.</div>
            <div class="move-white">${move.san}</div>
            <div class="move-black">-</div>
        `;
        history.appendChild(currentRow);
    } else {
        if (currentRow) {
            currentRow.querySelector('.move-black').textContent = move.san;
        }
    }
    
    history.scrollTop = history.scrollHeight;
}

function updateCapturedPieces() {
    const history = game.history({ verbose: true });
    const capturedByWhite = [];
    const capturedByBlack = [];
    
    history.forEach(move => {
        if (move.captured) {
            if (move.color === 'w') {
                capturedByWhite.push(move.captured);
            } else {
                capturedByBlack.push(move.captured);
            }
        }
    });
    
    const pieceSymbols = {
        'p': '♟', 'n': '♞', 'b': '♝', 'r': '♜', 'q': '♛', 'k': '♚'
    };
    
    const yourCaptured = playerColor === 'white' ? capturedByWhite : capturedByBlack;
    const opponentCaptured = playerColor === 'white' ? capturedByBlack : capturedByWhite;
    
    document.getElementById('yourCaptured').innerHTML = yourCaptured
        .map(p => `<span class="captured-piece">${pieceSymbols[p]}</span>`)
        .join('');
    
    document.getElementById('opponentCaptured').innerHTML = opponentCaptured
        .map(p => `<span class="captured-piece">${pieceSymbols[p]}</span>`)
        .join('');
}

function loadPGN(pgn) {
    try {
        if (game.load_pgn(pgn)) {
            board.position(game.fen());
            const moves = game.history({ verbose: true });
            moves.forEach(move => addMoveToHistory(move));
            updateCapturedPieces();
            updateTurnIndicator();
        }
    } catch (error) {
        console.error('Failed to load PGN:', error);
    }
}

// ==================== EVENT LISTENERS ====================
function setupEventListeners() {
    document.getElementById('resignBtn').addEventListener('click', () => {
        if (!gameActive) return;
        if (confirm('Are you sure you want to resign?')) {
            socket.emit('bot_resign', {
                match_id: matchId,
                user_id: userId
            });
        }
    });
    
    document.getElementById('flipBoardBtn').addEventListener('click', () => {
        board.flip();
        showNotification('Board flipped', 'info');
    });
}

// ==================== GAME END MODAL ====================
function showBotGameEndModal(data) {
    const modal = document.getElementById('gameEndModal');
    const icon = document.getElementById('resultIcon');
    const title = document.getElementById('resultTitle');
    const message = document.getElementById('resultMessage');
    const eloChanges = document.getElementById('eloChanges');
    
    let resultText, iconEmoji, messageText;
    
    if (data.result === 'draw') {
        resultText = "Draw";
        iconEmoji = "🤝";
        messageText = `Game ended in a draw by ${data.reason}`;
    } else if (data.result === 'player_win') {
        resultText = "You Won!";
        iconEmoji = "🏆";
        messageText = `You defeated the bot by ${data.reason}`;
    } else {
        resultText = "You Lost";
        iconEmoji = "😔";
        messageText = `Bot won by ${data.reason}`;
    }
    
    icon.textContent = iconEmoji;
    title.textContent = resultText;
    message.textContent = messageText;
    
    if (data.player_elo) {
        eloChanges.innerHTML = `
            <div class="elo-change-item">
                <div class="elo-change-label">Your New ELO</div>
                <div class="elo-change-value">${data.player_elo}</div>
            </div>
        `;
    }
    
    modal.classList.remove('hidden');
}

// ==================== UTILITIES ====================
function updateConnectionStatus(connected) {
    const indicator = document.getElementById('connectionIndicator');
    const text = indicator.querySelector('.text');
    
    if (connected) {
        indicator.classList.add('connected');
        text.textContent = 'Connected';
    } else {
        indicator.classList.remove('connected');
        text.textContent = 'Disconnected';
    }
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 80px;
        right: 20px;
        background: ${type === 'error' ? '#ef4444' : type === 'warning' ? '#f59e0b' : '#10b981'};
        color: white;
        padding: 1rem 1.5rem;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        z-index: 9998;
        animation: slideInRight 0.3s ease-out;
    `;
    document.body.appendChild(notification);
    setTimeout(() => {
        notification.style.animation = 'slideOutRight 0.3s ease-out';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

function showError(message) {
    showNotification(message, 'error');
}

function playMoveSound() {
    try {
        const audio = new Audio('/static/sounds/move.mp3');
        audio.volume = 0.5;
        audio.play().catch(() => {});
    } catch (e) {}
}

function playPromotionSound() {
    try {
        const audio = new Audio('/static/sounds/promote.mp3');
        audio.volume = 0.5;
        audio.play().catch(() => {});
    } catch (e) {}
}

window.addEventListener('beforeunload', () => {
    if (socket) {
        socket.emit('leave_bot_match', {
            match_id: matchId,
            user_id: userId
        });
        socket.disconnect();
    }
});

console.log('[+] Bot game initialized');


================================================
FILE: static/js/game/game.js
================================================
// ==================== GAME STATE ====================
let socket = null;
let game = null;
let board = null;
let matchId = null;
let userId = null;
let playerColor = null;
let opponentColor = null;
let isMyTurn = false;
let gameActive = true;

// Reconnection
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 5;
const RECONNECT_DELAY = 2000;

// ==================== INITIALIZATION ====================
document.addEventListener('DOMContentLoaded', async () => {
    matchId = document.getElementById('matchId').value;
    
    // Hide loading after init
    setTimeout(() => {
        document.getElementById('loadingOverlay').classList.add('hidden');
    }, 1000);
    
    // Get user info
    await loadUserInfo();
    
    // Initialize Socket.IO
    initializeSocket();
    
    // Initialize Chess.js
    game = new Chess();
    
    // Setup event listeners
    setupEventListeners();
    initPromotionHandlers(); 
    
    // Initialize board after socket connects
    // Board will be initialized in handle_match_joined
});

// ==================== LOAD USER INFO ====================
async function loadUserInfo() {
    try {
        const response = await fetch('/api/auth/me', {
            credentials: 'include'
        });
        
        if (response.ok) {
            const data = await response.json();
            userId = data.user_id;
            document.getElementById('yourName').textContent = data.name;
            document.getElementById('yourElo').textContent = data.elo;
        } else {
            window.location.href = '/login';
        }
    } catch (error) {
        console.error('Failed to load user info:', error);
        showError('Failed to load user information');
    }
}

// ==================== WEBSOCKET SETUP ====================
function initializeSocket() {
    // Connect to Socket.IO server
    socket = io({
        transports: ['websocket', 'polling'],
        reconnection: true,
        reconnectionAttempts: MAX_RECONNECT_ATTEMPTS,
        reconnectionDelay: RECONNECT_DELAY
    });
    
    // ===== CONNECTION EVENTS =====
    socket.on('connect', () => {
        console.log('[+] Connected to server');
        updateConnectionStatus(true);
        reconnectAttempts = 0;
        
        // Join match room
        socket.emit('join_match', {
            match_id: matchId,
            user_id: userId
        });
    });
    
    socket.on('disconnect', (reason) => {
        console.log('[-] Disconnected:', reason);
        updateConnectionStatus(false);
        
        if (reason === 'io server disconnect') {
            // Server initiated disconnect, try to reconnect
            socket.connect();
        }
    });
    
    socket.on('connect_error', (error) => {
        console.error('Connection error:', error);
        updateConnectionStatus(false, 'Connection error');
    });
    
    socket.on('reconnect_attempt', (attemptNumber) => {
        console.log(`Reconnection attempt ${attemptNumber}...`);
        showConnectionBanner('Reconnecting...', 'warning');
    });
    
    socket.on('reconnect', (attemptNumber) => {
        console.log('[+] Reconnected after', attemptNumber, 'attempts');
        showConnectionBanner('Reconnected!', 'success');
        setTimeout(() => hideConnectionBanner(), 2000);
        
        // Rejoin match
        socket.emit('join_match', {
            match_id: matchId,
            user_id: userId
        });
    });
    
    socket.on('reconnect_failed', () => {
        console.error('[-] Reconnection failed');
        showConnectionBanner('Connection lost. Please refresh.', 'error');
    });
    
    // ===== MATCH EVENTS =====
    socket.on('match_joined', (data) => {
        console.log('[+] Match joined:', data);
        
        playerColor = data.your_color;
        opponentColor = playerColor === 'white' ? 'black' : 'white';
        
        // Update UI
        document.getElementById('yourColor').innerHTML = 
            `<span class="color-piece">${playerColor === 'white' ? '♔' : '♚'}</span> ${playerColor}`;
        document.getElementById('opponentColor').innerHTML = 
            `<span class="color-piece">${opponentColor === 'white' ? '♔' : '♚'}</span> ${opponentColor}`;
        
        // Update opponent info
        document.getElementById('opponentName').textContent = data.opponent.name;
        document.getElementById('opponentElo').textContent = data.opponent.elo;
        
        if (data.opponent.connected) {
            document.querySelector('#opponentStatus .status-dot').classList.add('online');
            document.querySelector('#opponentStatus .status-dot').classList.remove('offline');
        }
        
        // Initialize board with correct orientation
        initializeBoard();
        
        // Load existing moves if any
        if (data.pgn) {
            loadPGN(data.pgn);
        }
        
        // Check if it's my turn
        updateTurnIndicator();
    });
    
    socket.on('opponent_connected', (data) => {
        console.log('[+] Opponent connected');
        document.querySelector('#opponentStatus .status-dot').classList.add('online');
        document.querySelector('#opponentStatus .status-dot').classList.remove('offline');
        showNotification('Your opponent has joined!');
    });
    
    socket.on('opponent_disconnected', (data) => {
        console.log('[*] Opponent disconnected');
        document.querySelector('#opponentStatus .status-dot').classList.remove('online');
        document.querySelector('#opponentStatus .status-dot').classList.add('offline');
        showNotification('Your opponent disconnected', 'warning');
    });
    
    // ===== MOVE EVENTS =====
    socket.on('move_accepted', (data) => {
        console.log('[+] Move accepted:', data.move);
        isMyTurn = false;
        updateTurnIndicator();
    });
    
    socket.on('opponent_move', (data) => {
        console.log('[+] Opponent moved:', data.move);
        
        // Make the move on the board
        const move = game.move(data.move);
        
        if (move) {
            board.position(game.fen());
            addMoveToHistory(move);
            updateCapturedPieces();
            updateTurnIndicator();
            
            // Check game state
            checkGameState();
            
            // Play sound (optional)
            playMoveSound();
            
            isMyTurn = true;
        }
    });
    
    socket.on('move_error', (data) => {
        console.error('[-] Move error:', data.message);
        showError(data.message);
    });
    
    // ===== GAME END EVENTS =====
    socket.on('game_ended', (data) => {
        console.log('[+] Game ended:', data);
        gameActive = false;
        showGameEndModal(data);
    });
    
    socket.on('player_resigned', (data) => {
        console.log('[+] Player resigned:', data);
        gameActive = false;
        showGameEndModal({
            result: data.result,
            reason: 'resignation',
            white: data.white,
            black: data.black
        });
    });
    
    // ===== DRAW EVENTS =====
    socket.on('draw_offered', (data) => {
        console.log('[+] Draw offered');
        showDrawOfferModal();
    });
    
    socket.on('draw_accepted', (data) => {
        console.log('[+] Draw accepted');
        gameActive = false;
        showGameEndModal({
            result: 'draw',
            reason: 'agreement',
            white: data.white,
            black: data.black
        });
    });
    
    socket.on('draw_declined', (data) => {
        console.log('[-] Draw declined');
        showNotification('Draw offer declined', 'info');
    });
    
    // ===== CHAT EVENTS =====
    socket.on('chat_message', (data) => {
        addChatMessage(data);
    });
    
    // ===== UTILITY EVENTS =====
    socket.on('pong', (data) => {
        // Heartbeat response
    });
    
    socket.on('error', (data) => {
        console.error('[-] Socket error:', data.message);
        showError(data.message);
    });
}

// ==================== BOARD INITIALIZATION ====================
function initializeBoard() {
    const config = {
        position: 'start',
        orientation: playerColor,
        draggable: true,
        onDragStart: onDragStart,
        onDrop: onDrop,
        onSnapEnd: onSnapEnd,
        pieceTheme: 'https://chessboardjs.com/img/chesspieces/wikipedia/{piece}.png'
    };
    
    board = Chessboard('chessboard', config);
    
    // Fit board to container
    $(window).resize(() => board.resize());
}

// ==================== CHESS LOGIC ====================
function onDragStart(source, piece, position, orientation) {
    // Don't allow moves if game is over
    if (gameActive === false) {
        showNotification("Game is over", 'warning');
        return false;
    }
    
    // Don't allow moves if not your turn
    if (!isMyTurn) {
        showNotification("It's not your turn!", 'warning');
        return false;
    }
    
    // Only pick up pieces for the player's color
    if ((playerColor === 'white' && piece.search(/^b/) !== -1) ||
        (playerColor === 'black' && piece.search(/^w/) !== -1)) {
        return false;
    }
    
    return true;
}

function onDrop(source, target) {
    console.log('[+] Drop:', source, '→', target);
    
    // [+] CHECK FOR PROMOTION
    if (isPromotionMove(source, target)) {
        console.log('[+] Showing promotion modal');
        
        // Show modal and wait for user selection
        showPromotionModal(source, target, (promotionPiece) => {
            console.log('[+] Selected piece:', promotionPiece);
            executeMoveWithPromotion(source, target, promotionPiece);
        });
        
        // Temporarily snap back until promotion is selected
        return 'snapback';
    }
    
    // Normal move (not promotion)
    return executeMove(source, target);
}

function executeMove(source, target, promotion = null) {
    const moveConfig = {
        from: source,
        to: target
    };
    
    if (promotion) {
        moveConfig.promotion = promotion;
    }
    
    const move = game.move(moveConfig);
    
    if (!move) {
        console.warn('[-] Invalid move:', source, '→', target);
        return 'snapback';
    }
    
    console.log('[+] Move successful:', move.san);
    
    // Send move to server
    socket.emit('make_move', {
        match_id: matchId,
        user_id: userId,
        move: move.san,
        fen: game.fen()
    });
    
    // Update UI
    addMoveToHistory(move);
    updateCapturedPieces();
    checkGameState();
    
    return null; // Success
}

function executeMoveWithPromotion(source, target, promotionPiece) {
    const move = game.move({
        from: source,
        to: target,
        promotion: promotionPiece
    });
    
    if (move) {
        console.log('♕ Promotion successful:', move.san);
        
        // Update board position
        board.position(game.fen());
        
        // Send to server
        socket.emit('make_move', {
            match_id: matchId,
            user_id: userId,
            move: move.san,
            fen: game.fen()
        });
        
        // Update UI
        addMoveToHistory(move);
        updateCapturedPieces();
        checkGameState();
        
        // Play promotion sound
        playPromotionSound();
    } else {
        console.error('[-] Promotion move failed:', source, target, promotionPiece);
        showError('Invalid promotion move');
    }
}

function onSnapEnd() {
    board.position(game.fen());
}

// ==================== GAME STATE CHECKING ====================
function checkGameState() {
    updateTurnIndicator();
    
    if (game.game_over()) {
        gameActive = false;
        
        let result, reason;
        
        if (game.in_checkmate()) {
            result = game.turn() === 'w' ? 'black_win' : 'white_win';
            reason = 'checkmate';
            showNotification('Checkmate!', 'error');
        } else if (game.in_draw()) {
            result = 'draw';
            if (game.in_stalemate()) {
                reason = 'stalemate';
            } else if (game.in_threefold_repetition()) {
                reason = 'repetition';
            } else if (game.insufficient_material()) {
                reason = 'insufficient material';
            } else {
                reason = '50-move rule';
            }
            showNotification(`Draw by ${reason}!`, 'info');
        }
        
        // Send game end to server
        socket.emit('game_end', {
            match_id: matchId,
            user_id: userId,
            result: result,
            reason: reason
        });
    } else if (game.in_check()) {
        const turn = game.turn() === 'w' ? 'White' : 'Black';
        showNotification(`${turn} is in check!`, 'warning');
        
        const statusEl = document.getElementById('gameStatus');
        if (statusEl) {
            statusEl.textContent = 'Check!';
            statusEl.className = 'value status-check';
        }
    }
}

// ==================== UI UPDATES ====================
function updateTurnIndicator() {
    const currentTurn = game.turn(); // 'w' or 'b'
    const turnColor = currentTurn === 'w' ? 'White' : 'Black';
    
    document.getElementById('turnIndicator').textContent = turnColor;
    
    const moveCount = Math.floor(game.history().length / 2) + 1;
    document.getElementById('moveNumber').textContent = moveCount;
    
    // Update move indicator
    const indicator = document.getElementById('moveIndicator');
    const indicatorText = indicator.querySelector('.indicator-text');
    
    if ((currentTurn === 'w' && playerColor === 'white') ||
        (currentTurn === 'b' && playerColor === 'black')) {
        isMyTurn = true;
        indicator.classList.add('your-turn');
        indicatorText.textContent = 'Your turn!';
    } else {
        isMyTurn = false;
        indicator.classList.remove('your-turn');
        indicatorText.textContent = 'Waiting for opponent...';
    }
}

function addMoveToHistory(move) {
    const history = document.getElementById('moveHistory');
    
    // Remove "no moves" message
    const noMoves = history.querySelector('.no-moves');
    if (noMoves) noMoves.remove();
    
    const moveNumber = Math.ceil(game.history().length / 2);
    const isWhiteMove = move.color === 'w';
    
    // Create or get current row
    let currentRow = history.querySelector(`[data-move="${moveNumber}"]`);
    
    if (isWhiteMove) {
        currentRow = document.createElement('div');
        currentRow.className = 'move-row';
        currentRow.dataset.move = moveNumber;
        currentRow.innerHTML = `
            <div class="move-number">${moveNumber}.</div>
            <div class="move-white">${formatMove(move)}</div>
            <div class="move-black">-</div>
        `;
        history.appendChild(currentRow);
    } else {
        if (currentRow) {
            currentRow.querySelector('.move-black').textContent = formatMove(move);
        }
    }
    
    // Scroll to bottom
    history.scrollTop = history.scrollHeight;
}

function formatMove(move) {
    let formatted = move.san;
    
    // Add visual indicators
    if (move.san.includes('#')) {
        formatted = `<strong>${formatted}</strong> ✓`; // Checkmate
    } else if (move.san.includes('+')) {
        formatted = `${formatted} ⚠`; // Check
    }
    
    if (move.captured) {
        formatted = `<strong>${formatted}</strong>`; // Bold captures
    }
    
    return formatted;
}

// ==================== CAPTURED PIECES ====================
function updateCapturedPieces() {
    const history = game.history({ verbose: true });
    const capturedByWhite = [];
    const capturedByBlack = [];
    
    history.forEach(move => {
        if (move.captured) {
            if (move.color === 'w') {
                capturedByWhite.push(move.captured);
            } else {
                capturedByBlack.push(move.captured);
            }
        }
    });
    
    // Update UI
    const pieceSymbols = {
        'p': '♟', 'n': '♞', 'b': '♝', 'r': '♜', 'q': '♛', 'k': '♚'
    };
    
    const yourCaptured = playerColor === 'white' ? capturedByWhite : capturedByBlack;
    const opponentCaptured = playerColor === 'white' ? capturedByBlack : capturedByWhite;
    
    document.getElementById('yourCaptured').innerHTML = yourCaptured
        .map(p => `<span class="captured-piece">${pieceSymbols[p]}</span>`)
        .join('');
    
    document.getElementById('opponentCaptured').innerHTML = opponentCaptured
        .map(p => `<span class="captured-piece">${pieceSymbols[p]}</span>`)
        .join('');
}

// ==================== LOAD PGN ====================
function loadPGN(pgn) {
    try {
        if (game.load_pgn(pgn)) {
            board.position(game.fen());
            
            // Rebuild move history
            const moves = game.history({ verbose: true });
            moves.forEach(move => addMoveToHistory(move));
            
            updateCapturedPieces();
            updateTurnIndicator();
        }
    } catch (error) {
        console.error('Failed to load PGN:', error);
    }
}

// ==================== EVENT LISTENERS ====================
function setupEventListeners() {
    // Resign button
    document.getElementById('resignBtn').addEventListener('click', () => {
        if (!gameActive) return;
        
        if (confirm('Are you sure you want to resign?')) {
            socket.emit('resign', {
                match_id: matchId,
                user_id: userId
            });
        }
    });
    
    // Offer draw button
    document.getElementById('offerDrawBtn').addEventListener('click', () => {
        if (!gameActive) return;
        
        socket.emit('offer_draw', {
            match_id: matchId,
            user_id: userId
        });
        
        showNotification('Draw offer sent', 'info');
    });
    
    // Flip board button
    document.getElementById('flipBoardBtn').addEventListener('click', () => {
        board.flip();
        showNotification('Board flipped', 'info');
    });
    
    // Chat input
    const chatInput = document.getElementById('chatInput');
    const sendChatBtn = document.getElementById('sendChatBtn');
    
    sendChatBtn.addEventListener('click', sendChatMessage);
    chatInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            sendChatMessage();
        }
    });
    
    // Draw offer modal
    document.getElementById('acceptDrawBtn').addEventListener('click', () => {
        socket.emit('respond_draw', {
            match_id: matchId,
            user_id: userId,
            accepted: true
        });
        hideDrawOfferModal();
    });
    
    document.getElementById('declineDrawBtn').addEventListener('click', () => {
        socket.emit('respond_draw', {
            match_id: matchId,
            user_id: userId,
            accepted: false
        });
        hideDrawOfferModal();
    });
    
    // Heartbeat every 30 seconds
    setInterval(() => {
        if (socket && socket.connected) {
            socket.emit('ping');
        }
    }, 30000);
}

// ==================== CHAT FUNCTIONS ====================
function sendChatMessage() {
    const input = document.getElementById('chatInput');
    const message = input.value.trim();
    
    if (!message) return;
    
    socket.emit('chat_message', {
        match_id: matchId,
        user_id: userId,
        message: message
    });
    
    input.value = '';
}

function addChatMessage(data) {
    const chatMessages = document.getElementById('chatMessages');
    
    // Remove info message if exists
    const chatInfo = chatMessages.querySelector('.chat-info');
    if (chatInfo) chatInfo.remove();
    
    const isMine = data.sender_id === userId;
    const messageDiv = document.createElement('div');
    messageDiv.className = `chat-message ${isMine ? 'mine' : 'theirs'}`;
    
    const time = new Date(data.timestamp).toLocaleTimeString([], { 
        hour: '2-digit', 
        minute: '2-digit' 
    });
    
    messageDiv.innerHTML = `
        <div class="chat-sender">${isMine ? 'You' : data.sender_name}</div>
        <div class="chat-text">${escapeHtml(data.message)}</div>
        <div class="chat-time">${time}</div>
    `;
    
    chatMessages.appendChild(messageDiv);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

// ==================== MODALS ====================
function showGameEndModal(data) {
    const modal = document.getElementById('gameEndModal');
    const icon = document.getElementById('resultIcon');
    const title = document.getElementById('resultTitle');
    const message = document.getElementById('resultMessage');
    const eloChanges = document.getElementById('eloChanges');
    
    let resultText, iconEmoji, messageText;
    
    if (data.result === 'draw') {
        resultText = "Draw";
        iconEmoji = "🤝";
        messageText = `Game ended in a draw by ${data.reason}`;
    } else {
        const winner = data.result === 'white_win' ? 'White' : 'Black';
        const didIWin = (data.result === 'white_win' && playerColor === 'white') ||
                       (data.result === 'black_win' && playerColor === 'black');
        
        resultText = didIWin ? "You Won!" : "You Lost";
        iconEmoji = didIWin ? "🏆" : "😔";
        messageText = `${winner} wins by ${data.reason}`;
    }
    
    icon.textContent = iconEmoji;
    title.textContent = resultText;
    message.textContent = messageText;
    
    // Show ELO changes if available
    if (data.white && data.black) {
        eloChanges.innerHTML = `
            <div class="elo-change-item">
                <div class="elo-change-label">White (${data.white.name})</div>
                <div class="elo-change-value">${data.white.elo}</div>
            </div>
            <div class="elo-change-item">
                <div class="elo-change-label">Black (${data.black.name})</div>
                <div class="elo-change-value">${data.black.elo}</div>
            </div>
        `;
    }
    
    modal.classList.remove('hidden');
}

function showDrawOfferModal() {
    document.getElementById('drawOfferModal').classList.remove('hidden');
}

function hideDrawOfferModal() {
    document.getElementById('drawOfferModal').classList.add('hidden');
}

// ==================== CONNECTION STATUS ====================
function updateConnectionStatus(connected, message) {
    const indicator = document.getElementById('connectionIndicator');
    const text = indicator.querySelector('.text');
    
    if (connected) {
        indicator.classList.add('connected');
        text.textContent = 'Connected';
    } else {
        indicator.classList.remove('connected');
        text.textContent = message || 'Disconnected';
    }
}

function showConnectionBanner(message, type = 'warning') {
    const banner = document.getElementById('connectionStatus');
    const text = banner.querySelector('.status-text');
    
    text.textContent = message;
    banner.className = `connection-banner ${type}`;
    banner.classList.remove('hidden');
}

function hideConnectionBanner() {
    document.getElementById('connectionStatus').classList.add('hidden');
}

// ==================== NOTIFICATIONS ====================
function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.textContent = message;
    
    notification.style.cssText = `
        position: fixed;
        top: 80px;
        right: 20px;
        background: ${type === 'error' ? '#ef4444' : type === 'warning' ? '#f59e0b' : '#10b981'};
        color: white;
        padding: 1rem 1.5rem;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        z-index: 9998;
        animation: slideInRight 0.3s ease-out;
        max-width: 300px;
    `;
    
    document.body.appendChild(notification);
    
    // Remove after 3 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOutRight 0.3s ease-out';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

function showError(message) {
    showNotification(message, 'error');
}

// ==================== UTILITY FUNCTIONS ====================
function escapeHtml(text) {
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    return text.replace(/[&<>"']/g, m => map[m]);
}

function playMoveSound() {
    // Optional: Add move sound
    try {
        const audio = new Audio('/static/sounds/move.mp3');
        audio.volume = 0.5;
        audio.play().catch(() => {});
    } catch (e) {
        // Sound not available
    }
}

function playPromotionSound() {
    console.log('♕ Pawn promoted!');
    try {
        const audio = new Audio('/static/sounds/promote.mp3');
        audio.volume = 0.5;
        audio.play().catch(() => {});
    } catch (e) {
        // Sound not available
    }
}

// ==================== KEYBOARD SHORTCUTS ====================
document.addEventListener('keydown', (e) => {
    // Don't interfere with chat input
    if (document.activeElement.id === 'chatInput') return;
    
    // ESC to close modals
    if (e.key === 'Escape') {
        document.querySelectorAll('.modal').forEach(modal => {
            if (!modal.classList.contains('hidden')) {
                // Don't close promotion modal with ESC - it auto-selects Queen
                if (modal.id !== 'promotionModal') {
                    modal.classList.add('hidden');
                }
            }
        });
    }
    
    // F to flip board
    if (e.key === 'f' || e.key === 'F') {
        if (board) {
            board.flip();
            showNotification('Board flipped', 'info');
        }
    }
});

// ==================== PAGE VISIBILITY ====================
document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
        console.log('📱 Page hidden');
    } else {
        console.log('📱 Page visible');
        // Sync game state when user returns
        if (socket && socket.connected) {
            socket.emit('join_match', {
                match_id: matchId,
                user_id: userId
            });
        }
    }
});

// ==================== CLEANUP ====================
window.addEventListener('beforeunload', () => {
    if (socket) {
        socket.emit('leave_match', {
            match_id: matchId,
            user_id: userId
        });
        socket.disconnect();
    }
});

// ==================== ADD CSS ANIMATIONS ====================
const style = document.createElement('style');
style.textContent = `
    @keyframes slideInRight {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOutRight {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);

console.log('[+] Chess game initialized');


================================================
FILE: static/js/game/promotion.js
================================================
// ==================== PROMOTION MODULE (FIXED) ====================
let promotionSource = null;
let promotionTarget = null;
let promotionCallback = null;

// ==================== CHECK IF MOVE IS PROMOTION ====================
function isPromotionMove(source, target) {
    // Get piece at source square
    const piece = game.get(source);
    
    if (!piece) return false;
    
    // Check if it's a pawn
    if (piece.type !== 'p') return false;
    
    // Check if moving to last rank
    const targetRank = target[1];
    const isWhitePromotion = piece.color === 'w' && targetRank === '8';
    const isBlackPromotion = piece.color === 'b' && targetRank === '1';
    
    return isWhitePromotion || isBlackPromotion;
}

// ==================== SHOW PROMOTION MODAL ====================
function showPromotionModal(source, target, callback) {
    promotionSource = source;
    promotionTarget = target;
    promotionCallback = callback;
    
    const modal = document.getElementById('promotionModal');
    const piece = game.get(source);
    
    // Update button icons based on color
    updatePromotionPieces(piece.color);
    
    modal.classList.remove('hidden');
}

function updatePromotionPieces(color) {
    const pieces = {
        'q': { white: '♕', black: '♛', name: 'Queen' },
        'r': { white: '♖', black: '♜', name: 'Rook' },
        'b': { white: '♗', black: '♝', name: 'Bishop' },
        'n': { white: '♘', black: '♞', name: 'Knight' }
    };
    
    document.querySelectorAll('#promotionModal button[data-piece]').forEach(btn => {
        const pieceType = btn.dataset.piece;
        const pieceData = pieces[pieceType];
        btn.textContent = color === 'w' ? pieceData.white : pieceData.black;
        btn.title = pieceData.name;
    });
}

function hidePromotionModal() {
    document.getElementById('promotionModal').classList.add('hidden');
    promotionSource = null;
    promotionTarget = null;
    promotionCallback = null;
}

// ==================== HANDLE PROMOTION SELECTION ====================
function handlePromotionChoice(pieceType) {
    if (!promotionSource || !promotionTarget) return;
    
    // Execute the promotion callback
    if (promotionCallback) {
        promotionCallback(pieceType);
    }
    
    hidePromotionModal();
}

// ==================== INIT PROMOTION HANDLERS ====================
function initPromotionHandlers() {
    const buttons = document.querySelectorAll('#promotionModal button[data-piece]');
    
    buttons.forEach(btn => {
        btn.addEventListener('click', () => {
            const piece = btn.dataset.piece;
            handlePromotionChoice(piece);
        });
    });
    
    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        const modal = document.getElementById('promotionModal');
        if (modal.classList.contains('hidden')) return;
        
        const key = e.key.toLowerCase();
        const pieceMap = { 'q': 'q', 'r': 'r', 'b': 'b', 'n': 'n' };
        
        if (pieceMap[key]) {
            e.preventDefault();
            handlePromotionChoice(pieceMap[key]);
        } else if (e.key === 'Escape') {
            e.preventDefault();
            handlePromotionChoice('q'); // Default to Queen on ESC
        }
    });
}


================================================
FILE: static/js/matching/bot_selection.js
================================================
// Bot Selection Logic

document.addEventListener('DOMContentLoaded', () => {
    setupBotButtons();
});

function setupBotButtons() {
    const botButtons = document.querySelectorAll('.btn-play-bot');
    
    botButtons.forEach(button => {
        button.addEventListener('click', function() {
            const difficulty = this.dataset.difficulty;
            startBotMatch(difficulty);
        });
    });
}

async function startBotMatch(difficulty) {
    try {
        const validDifficulties = ['beginner', 'easy', 'medium', 'hard', 'expert'];
        if (!validDifficulties.includes(difficulty)) {
            showNotification('Invalid difficulty level', 'error');
            return;
        }
        
        showBotMatchLoading(difficulty);
        window.location.href = `/game/bot?difficulty=${difficulty}`;
        
    } catch (error) {
        console.error('Error starting bot match:', error);
        showNotification('Failed to start bot match. Please try again.', 'error');
        hideBotMatchLoading();
    }
}

function showBotMatchLoading(difficulty) {
    const botNames = {
        'beginner': 'ChessBot Junior',
        'easy': 'ChessBot Novice',
        'medium': 'ChessBot Standard',
        'hard': 'ChessBot Pro',
        'expert': 'ChessBot Master'
    };
    
    const botIcons = {
        'beginner': '🐣',
        'easy': '🐥',
        'medium': '🦅',
        'hard': '🦁',
        'expert': '👑'
    };
    
    const overlay = document.createElement('div');
    overlay.id = 'botMatchLoading';
    overlay.style.cssText = `
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: rgba(0, 0, 0, 0.9);
        display: flex;
        align-items: center;
        justify-content: center;
        z-index: 10000;
    `;
    
    overlay.innerHTML = `
        <div style="text-align: center; color: white;">
            <div style="font-size: 5rem; margin-bottom: 1rem; animation: bounce 1s infinite;">
                ${botIcons[difficulty]}
            </div>
            <h2 style="font-size: 2rem; margin-bottom: 0.5rem;">
                Starting match vs ${botNames[difficulty]}
            </h2>
            <p style="color: rgba(255, 255, 255, 0.8);">
                Preparing the board...
            </p>
            <div style="width: 60px; height: 60px; border: 5px solid rgba(255, 255, 255, 0.2); border-top: 5px solid #fff; border-radius: 50%; animation: spin 1s linear infinite; margin: 2rem auto;"></div>
        </div>
    `;
    
    document.body.appendChild(overlay);
    
    const style = document.createElement('style');
    style.textContent = `
        @keyframes bounce {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-20px); }
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    `;
    document.head.appendChild(style);
}

function hideBotMatchLoading() {
    const overlay = document.getElementById('botMatchLoading');
    if (overlay) {
        overlay.remove();
    }
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.textContent = message;
    
    const bgColors = {
        'info': '#3b82f6',
        'success': '#10b981',
        'error': '#ef4444',
        'warning': '#f59e0b'
    };
    
    notification.style.cssText = `
        position: fixed;
        top: 80px;
        right: 20px;
        background: ${bgColors[type] || bgColors.info};
        color: white;
        padding: 1rem 1.5rem;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        z-index: 9998;
        animation: slideInRight 0.3s ease-out;
        max-width: 300px;
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideOutRight 0.3s ease-out';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

console.log('✓ Bot selection initialized');


================================================
FILE: static/js/matching/matching.js
================================================
// Matching Page JavaScript - Enhanced with auto-redirect
let currentState = 'idle';
let pollingInterval = null;
let waitStartTime = null;
let currentMatchId = null;
let autoRedirectTimeout = null;

// Configuration
const AUTO_REDIRECT_DELAY = 3000; // 3 seconds delay before auto-redirect
const POLLING_INTERVAL = 2000; // Poll every 2 seconds

// DOM Elements
const idleState = document.getElementById('idleState');
const waitingState = document.getElementById('waitingState');
const matchedState = document.getElementById('matchedState');

const findMatchBtn = document.getElementById('findMatchBtn');
const cancelMatchBtn = document.getElementById('cancelMatchBtn');
const startGameBtn = document.getElementById('startGameBtn');

// Initialize
document.addEventListener('DOMContentLoaded', async () => {
    await loadUserInfo();
    await loadStats();
    await loadMatchHistory();
    await loadLeaderboard();
    
    // Check if already in a match
    await checkCurrentMatch();
    
    setupEventListeners();
});

// Event Listeners
function setupEventListeners() {
    findMatchBtn.addEventListener('click', findMatch);
    cancelMatchBtn.addEventListener('click', cancelMatch);
    startGameBtn.addEventListener('click', () => startGame(false)); // Manual start
}

// Load User Info
async function loadUserInfo() {
    try {
        const response = await fetch('/api/auth/me', {
            credentials: 'include'
        });
        
        if (response.ok) {
            const data = await response.json();
            document.getElementById('userName').textContent = data.name;
            document.getElementById('userElo').textContent = `ELO: ${data.elo}`;
        } else {
            window.location.href = '/login';
        }
    } catch (error) {
        console.error('Failed to load user info:', error);
    }
}

// Load Stats
async function loadStats() {
    try {
        const response = await fetch('/api/match/stats', {
            credentials: 'include'
        });
        
        if (response.ok) {
            const stats = await response.json();
            document.getElementById('totalGames').textContent = stats.total_games;
            document.getElementById('draws').textContent = stats.draws;
            document.getElementById('wins').textContent = stats.wins;
            document.getElementById('losses').textContent = stats.losses;
            document.getElementById('winRate').textContent = `${parseFloat(stats.win_rate.toFixed(1)).toPrecision()}%`;
        }
    } catch (error) {
        console.error('Failed to load stats:', error);
    }
}

// Load Match History
async function loadMatchHistory() {
    try {
        const response = await fetch('/api/match/history?limit=5', {
            credentials: 'include'
        });
        
        if (response.ok) {
            const data = await response.json();
            displayMatchHistory(data.matches);
        }
    } catch (error) {
        console.error('Failed to load match history:', error);
    }
}

function displayMatchHistory(matches) {
    const container = document.getElementById('matchHistory');
    
    if (matches.length === 0) {
        container.innerHTML = '<p class="loading">No matches yet</p>';
        return;
    }
    
    container.innerHTML = matches.map(match => {
        const resultClass = getResultClass(match.result, match.your_color);
        const resultText = getResultText(match.result, match.your_color);
        
        return `
            <div class="match-item">
                <div>
                    <div class="match-opponent">
                    ${match.opponent_name} <span style="font-size: 0.85rem; color: #6b7280;">(${match.opponent_elo}) </span><br>
                    Started at: <span style="font-size: 0.85rem; color: #6b7280;">${new Date(match.start).toLocaleDateString()}</span>
                    &nbsp; &nbsp; &nbsp;&nbsp;&nbsp;
                    Ended at: <span style="font-size: 0.85rem; color: #6b7280;">${new Date(match.end).toLocaleDateString()}</span>
                    </div>
                    <div style="font-size: 0.85rem; color: #6b7280;">
                        You played as ${match.your_color}
                    </div>
                </div>
                <span class="match-result ${resultClass}">${resultText}</span>
            </div>
        `;
    }).join('');
}

function getResultClass(result, yourColor) {
    if (result === 'draw') return 'draw';
    if ((result === 'white_win' && yourColor === 'white') ||
        (result === 'black_win' && yourColor === 'black')) {
        return 'win';
    }
    return 'loss';
}

function getResultText(result, yourColor) {
    if (result === 'draw') return 'Draw';
    if ((result === 'white_win' && yourColor === 'white') ||
        (result === 'black_win' && yourColor === 'black')) {
        return 'Win';
    }
    return 'Loss';
}

// Load Leaderboard
async function loadLeaderboard() {
    try {
        const response = await fetch('/api/match/leaderboard?limit=10');
        
        if (response.ok) {
            const data = await response.json();
            displayLeaderboard(data.leaderboard);
        }
    } catch (error) {
        console.error('Failed to load leaderboard:', error);
    }
}

function displayLeaderboard(players) {
    const container = document.getElementById('leaderboardList');
    
    if (players.length === 0) {
        container.innerHTML = '<p class="loading">No players yet</p>';
        return;
    }
    
    container.innerHTML = players.map(player => {
        let rankClass = '';
        if (player.rank === 1) rankClass = 'top1';
        else if (player.rank === 2) rankClass = 'top2';
        else if (player.rank === 3) rankClass = 'top3';
        
        return `
            <div class="leaderboard-item">
                <div class="rank ${rankClass}">#${player.rank}</div>
                <div class="player-info">
                    <div class="player-name">${player.name}</div>
                    <div class="player-stats">
                        ELO: ${player.elo} | Games: ${player.games_played} | Win Rate: ${parseFloat(player.win_rate.toFixed(1)).toPrecision()}%
                    </div>
                </div>
            </div>
        `;
    }).join('');
}

// Find Match
async function findMatch() {
    try {
        findMatchBtn.disabled = true;
        findMatchBtn.textContent = 'Searching...';
        
        const response = await fetch('/api/matching/find_match', {
            method: 'POST',
            credentials: 'include'
        });
        
        const data = await response.json();
        
        if (data.status === 'matched') {
            // Immediately found a match
            showMatchedState(data, true); // Pass autoRedirect = true
        } else if (data.status === 'waiting') {
            // Added to queue
            showWaitingState(data);
            startPolling();
        } else {
            alert(data.message || 'Failed to find match');
            findMatchBtn.disabled = false;
            findMatchBtn.textContent = '🎯 Find Match';
        }
    } catch (error) {
        console.error('Find match error:', error);
        alert('Network error. Please try again.');
        findMatchBtn.disabled = false;
        findMatchBtn.textContent = '🎯 Find Match';
    }
}

// Cancel Match
async function cancelMatch() {
    try {
        const response = await fetch('/api/matching/cancel_match', {
            method: 'POST',
            credentials: 'include'
        });
        
        if (response.ok) {
            stopPolling();
            clearAutoRedirect();
            showIdleState();
        }
    } catch (error) {
        console.error('Cancel match error:', error);
    }
}

// Start Polling
function startPolling() {
    waitStartTime = Date.now();
    updateWaitTime();
    
    pollingInterval = setInterval(async () => {
        await checkMatch();
        updateWaitTime();
    }, POLLING_INTERVAL);
}

function stopPolling() {
    if (pollingInterval) {
        clearInterval(pollingInterval);
        pollingInterval = null;
    }
}

function updateWaitTime() {
    if (waitStartTime) {
        const seconds = Math.floor((Date.now() - waitStartTime) / 1000);
        document.getElementById('waitTime').textContent = `${seconds}s`;
    }
}

// Check Match Status (called by polling)
async function checkMatch() {
    try {
        const response = await fetch('/api/matching/check_match', {
            credentials: 'include'
        });
        
        if (response.ok) {
            const data = await response.json();
            
            if (data.status === 'matched') {
                stopPolling();
                showMatchedState(data, true); // Auto-redirect enabled
            }
        }
    } catch (error) {
        console.error('Check match error:', error);
    }
}

// Check Current Match (on page load)
async function checkCurrentMatch() {
    try {
        const response = await fetch('/api/matching/check_match', {
            credentials: 'include'
        });
        
        if (response.ok) {
            const data = await response.json();
            
            if (data.status === 'matched') {
                // Found existing match on page load
                showMatchedState(data, true); // Auto-redirect enabled
            } else if (data.status === 'waiting') {
                showWaitingState(data);
                startPolling();
            }
        }
    } catch (error) {
        console.error('Check current match error:', error);
    }
}

// State Management
function showIdleState() {
    currentState = 'idle';
    idleState.style.display = 'block';
    waitingState.style.display = 'none';
    matchedState.style.display = 'none';
    
    findMatchBtn.disabled = false;
    findMatchBtn.textContent = '🎯 Find Match';
}

function showWaitingState(data) {
    currentState = 'waiting';
    idleState.style.display = 'none';
    waitingState.style.display = 'block';
    matchedState.style.display = 'none';
    
    if (data.elo) {
        const min = data.elo - 100;
        const max = data.elo + 100;
        document.getElementById('eloRange').textContent = `${min} - ${max}`;
    }
    
    if (data.queue_position) {
        document.getElementById('queuePosition').textContent = data.queue_position;
    }
}

function showMatchedState(data, autoRedirect = false) {
    currentState = 'matched';
    idleState.style.display = 'none';
    waitingState.style.display = 'none';
    matchedState.style.display = 'block';
    
    currentMatchId = data.match_id;
    
    document.getElementById('opponentName').textContent = data.opponent.name;
    document.getElementById('opponentElo').textContent = data.opponent.elo;
    
    const colorBadge = document.getElementById('yourColor');
    colorBadge.textContent = data.your_color;
    colorBadge.className = `color-badge ${data.your_color}`;
    
    // Auto-redirect if enabled
    if (autoRedirect) {
        startAutoRedirectCountdown();
    }
}

// Auto-redirect functionality
function startAutoRedirectCountdown() {
    let countdown = Math.floor(AUTO_REDIRECT_DELAY / 1000);
    
    // Update button text with countdown
    updateStartButtonCountdown(countdown);
    
    // Create countdown interval
    const countdownInterval = setInterval(() => {
        countdown--;
        if (countdown > 0) {
            updateStartButtonCountdown(countdown);
        } else {
            clearInterval(countdownInterval);
        }
    }, 1000);
    
    // Set timeout for actual redirect
    autoRedirectTimeout = setTimeout(() => {
        clearInterval(countdownInterval);
        startGame(true); // Auto start
    }, AUTO_REDIRECT_DELAY);
}

function updateStartButtonCountdown(seconds) {
    if (startGameBtn) {
        startGameBtn.textContent = `Starting in ${seconds}s... (Click to start now)`;
        startGameBtn.classList.add('countdown');
    }
}

function clearAutoRedirect() {
    if (autoRedirectTimeout) {
        clearTimeout(autoRedirectTimeout);
        autoRedirectTimeout = null;
    }
    
    // Reset button text
    if (startGameBtn) {
        startGameBtn.textContent = 'Start Game';
        startGameBtn.classList.remove('countdown');
    }
}

// Start Game
function startGame(isAutoStart = false) {
    if (currentMatchId) {
        // Clear auto-redirect if user clicked manually
        if (!isAutoStart) {
            clearAutoRedirect();
        }
        
        console.log(`${isAutoStart ? 'Auto-' : 'Manual '}starting game:`, currentMatchId);
        
        // Redirect to game page
        window.location.href = `/game/${currentMatchId}`;
    } else {
        console.error('No match ID available');
        alert('Error: No match found. Please try again.');
    }
}

// Logout
async function logout() {
    // Clear any pending redirects
    clearAutoRedirect();
    stopPolling();
    
    try {
        const response = await fetch('/api/auth/logout', {
            method: 'POST',
            credentials: 'include'
        });
        
        if (response.ok) {
            window.location.href = '/login';
        }
    } catch (error) {
        console.error('Logout error:', error);
    }
}

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    stopPolling();
    clearAutoRedirect();
});

// Add visual feedback styles dynamically
const style = document.createElement('style');
style.textContent = `
    .btn.countdown {
        animation: pulse 1s infinite;
        background: linear-gradient(135deg, #10b981, #059669) !important;
    }
    
    @keyframes pulse {
        0%, 100% {
            transform: scale(1);
            box-shadow: 0 6px 20px rgba(16, 185, 129, 0.4);
        }
        50% {
            transform: scale(1.05);
            box-shadow: 0 8px 25px rgba(16, 185, 129, 0.6);
        }
    }
    
    .matched-card .countdown-notice {
        margin-top: 1rem;
        padding: 0.75rem;
        background: #d1fae5;
        border: 2px solid #10b981;
        border-radius: 8px;
        color: #065f46;
        font-weight: 600;
        animation: fadeIn 0.3s ease-out;
    }
    
    @keyframes fadeIn {
        from {
            opacity: 0;
            transform: translateY(-10px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
`;
document.head.appendChild(style);


================================================
FILE: static/js/matching/recent_matches.js
================================================
let matchSkip = 0;
const MATCHES_PER_PAGE = 5;
let hasNextPage = true;

// Load match history
async function loadMatchHistory(skip = 0) {
    try {
        const response = await fetch(
            `/api/match/history?skip=${skip}&limit=${MATCHES_PER_PAGE}`,
            { credentials: 'include' }
        );

        if (!response.ok) {
            throw new Error('Failed to load matches');
        }

        const data = await response.json();

        // Update state
        matchSkip = skip;
        hasNextPage = data.count === MATCHES_PER_PAGE;

        // Render matches
        displayMatchHistory(data.matches);

        // Update buttons
        updatePaginationButtons();

    } catch (error) {
        console.error('Error loading match history:', error);
        document.getElementById('matchHistory').innerHTML =
            '<p class="loading">Failed to load matches. Please try again.</p>';
    }
}

// Render match list
function displayMatchHistory(matches) {
    const container = document.getElementById('matchHistory');

    if (!matches || matches.length === 0) {
        container.innerHTML = '<p class="loading">No matches yet</p>';
        return;
    }

    container.innerHTML = matches.map(match => {
        const resultClass = getResultClass(match.result, match.your_color);
        const resultText = getResultText(match.result, match.your_color);

        return `
            <a class="match-item" href="/review/${match.match_id}">
                <div class="match-main-info">
                    <div class="piece-color-indicator ${match.your_color.toLowerCase()}" title="You played as ${match.your_color}"></div>
                    
                    <div class="match-details">
                        <div class="opponent-row">
                            <span class="opponent-name">${match.opponent_name}</span>
                            <span class="opponent-elo">${match.opponent_elo}</span>
                        </div>
                        <div class="match-time">
                            <span>${match.start}</span>
                            <span class="time-separator">→</span>
                            <span>${match.end}</span>
                        </div>
                    </div>
                </div>

                <div class="match-status-wrapper">
                    <span class="match-result-badge ${resultClass}">
                        ${resultText}
                    </span>
                </div>
            </a>
        `;
    }).join('');
}

// Result helpers
function getResultClass(result, yourColor) {
    if (result === 'draw') return 'draw';
    if (
        (result === 'white_win' && yourColor === 'white') ||
        (result === 'black_win' && yourColor === 'black')
    ) return 'win';
    return 'loss';
}

function getResultText(result, yourColor) {
    if (result === 'draw') return 'Draw';
    if (
        (result === 'white_win' && yourColor === 'white') ||
        (result === 'black_win' && yourColor === 'black')
    ) return 'Win';
    return 'Loss';
}

// Pagination buttons
function prevPage() {
    if (matchSkip > 0) {
        loadMatchHistory(matchSkip - MATCHES_PER_PAGE);
    }
}

function nextPage() {
    if (hasNextPage) {
        loadMatchHistory(matchSkip + MATCHES_PER_PAGE);
    }
}

function updatePaginationButtons() {
    document.getElementById('prevPageBtn').disabled = matchSkip === 0;
    document.getElementById('nextPageBtn').disabled = !hasNextPage;
}



================================================
FILE: static/js/review/review.js
================================================
// ==================== GAME STATE ====================
let analysis = null;
let game = null;
let board = null;
let currentPly = 0;
let autoPlayInterval = null;
let evalChart = null;

// ==================== INITIALIZATION ====================
document.addEventListener('DOMContentLoaded', async () => {
    const matchId = document.getElementById('matchId').value;
    
    // Load analysis data
    await loadAnalysis(matchId);
    
    // Setup event listeners
    setupEventListeners();
});

// ==================== LOAD ANALYSIS ====================
async function loadAnalysis(matchId) {
    try {
        const response = await fetch(`/api/review/${matchId}`, {
            credentials: 'include'
        });
        
        if (!response.ok) {
            throw new Error('Failed to load analysis');
        }
        
        analysis = await response.json();
        
        // Hide loading
        document.getElementById('loadingOverlay').classList.add('hidden');
        
        // Initialize display
        initializeBoard();
        displayGameInfo();
        displayMoveList();
        displayStats();
        createEvalChart();
        findKeyMoments();
        
    } catch (error) {
        console.error('Error loading analysis:', error);
        showError('Failed to load game analysis. Please try again.');
    }
}

// ==================== INITIALIZE BOARD ====================
function initializeBoard() {
    game = new Chess();
    
    const config = {
        position: 'start',
        draggable: false,
        pieceTheme: 'https://chessboardjs.com/img/chesspieces/wikipedia/{piece}.png'
    };
    
    board = Chessboard('reviewBoard', config);
    
    // Fit board to container
    $(window).resize(() => board.resize());
}

// ==================== DISPLAY GAME INFO ====================
function displayGameInfo() {
    // Update player names
    document.getElementById('whiteName').textContent = analysis.white.username;
    document.getElementById('blackName').textContent = analysis.black.username;
    
    // Calculate and display stats
    const whiteStats = calculatePlayerStats('white');
    const blackStats = calculatePlayerStats('black');
    
    // White stats
    document.getElementById('whiteBlunders').textContent = whiteStats.blunders;
    document.getElementById('whiteMistakes').textContent = whiteStats.mistakes;
    document.getElementById('whiteElo').textContent = analysis.white.elo;
    document.getElementById('whiteInaccuracies').textContent = whiteStats.inaccuracies;
    document.getElementById('whiteAvgLoss').textContent = whiteStats.avgLoss.toFixed(2);
    
    // Black stats
    document.getElementById('blackBlunders').textContent = blackStats.blunders;
    document.getElementById('blackMistakes').textContent = blackStats.mistakes;
    document.getElementById('blackElo').textContent = analysis.black.elo;
    document.getElementById('blackInaccuracies').textContent = blackStats.inaccuracies;
    document.getElementById('blackAvgLoss').textContent = blackStats.avgLoss.toFixed(2);
    
    // Game result
    const resultMap = {
        'white_win': '1-0',
        'black_win': '0-1',
        'draw': '½-½',
        'ongoing': '?'
    };
    document.getElementById('gameResult').textContent = resultMap[analysis.status] || '?';
}

// ==================== CALCULATE PLAYER STATS ====================
function calculatePlayerStats(color) {
    const moves = analysis.analysis.filter(m => m.color === color);
    
    const stats = {
        blunders: 0,
        mistakes: 0,
        inaccuracies: 0,
        avgLoss: 0
    };
    
    moves.forEach(move => {
        if (move.judgment === 'BLUNDER') stats.blunders++;
        if (move.judgment === 'MISTAKE') stats.mistakes++;
        if (move.judgment === 'INACCURACY') stats.inaccuracies++;
        stats.avgLoss += move.loss;
    });
    
    stats.avgLoss = moves.length > 0 ? stats.avgLoss / moves.length : 0;
    
    return stats;
}

// ==================== DISPLAY STATS ====================
function displayStats() {
    const totalMoves = analysis.move_count;
    const accurateMoves = analysis.analysis.filter(m => m.judgment === 'OK').length;
    const totalErrors = analysis.analysis.filter(m => m.judgment !== 'OK').length;
    const criticalMoments = analysis.analysis.filter(m => 
        m.judgment === 'BLUNDER' || m.loss_cp > 200
    ).length;
    
    document.getElementById('totalMoves').textContent = totalMoves;
    document.getElementById('accurateMoves').textContent = accurateMoves;
    document.getElementById('totalErrors').textContent = totalErrors;
    document.getElementById('criticalMoments').textContent = criticalMoments;
}

// ==================== DISPLAY MOVE LIST ====================
function displayMoveList() {
    const container = document.getElementById('moveList');
    container.innerHTML = '';
    
    analysis.analysis.forEach((move, index) => {
        const moveItem = createMoveItem(move, index);
        container.appendChild(moveItem);
    });
}

function createMoveItem(move, index) {
    const div = document.createElement('div');
    div.className = `move-item ${index === currentPly ? 'active' : ''}`;
    div.dataset.ply = index;
    
    const judgmentClass = move.judgment.toLowerCase().replace('_', '-');
    
    div.innerHTML = `
        <div class="move-item-header">
            <span class="move-number">${move.ply}.</span>
            <span class="move-eval">${move.eval_after}</span>
        </div>
        <div class="move-item-body">
            <span class="move-san">${move.move}</span>
            <span class="move-judgment ${judgmentClass}">${move.judgment}</span>
        </div>
    `;
    
    div.addEventListener('click', () => goToPly(index));
    
    return div;
}

// ==================== NAVIGATION ====================
function goToPly(ply) {
    if (ply < 0 || ply >= analysis.analysis.length) return;
    
    currentPly = ply;
    
    // Reset game and replay moves up to current ply
    game.reset();
    for (let i = 0; i <= ply; i++) {
        game.move(analysis.analysis[i].move);
    }
    
    // Update board
    board.position(game.fen());
    
    // Update UI
    updateCurrentMoveDisplay();
    updateMoveListActive();
}

function updateCurrentMoveDisplay() {
    const move = analysis.analysis[currentPly];
    
    document.getElementById('currentMoveNumber').textContent = move.ply;
    document.getElementById('currentMove').textContent = move.move;
    document.getElementById('evalBefore').textContent = move.eval_before;
    document.getElementById('evalAfter').textContent = move.eval_after;
    
    // Update judgment badge
    const badge = document.getElementById('moveBadge');
    badge.textContent = move.judgment;
    badge.className = `judgment-badge ${move.judgment.toLowerCase()}`;
    
    // Show/hide best move container
    const bestMoveContainer = document.getElementById('bestMoveContainer');
    if (move.judgment !== 'OK') {
        bestMoveContainer.style.display = 'block';
        document.getElementById('bestMove').textContent = move.best_move;
        document.getElementById('moveLoss').textContent = move.loss.toFixed(2);
    } else {
        bestMoveContainer.style.display = 'none';
    }
}

function updateMoveListActive() {
    document.querySelectorAll('.move-item').forEach(item => {
        item.classList.toggle('active', parseInt(item.dataset.ply) === currentPly);
    });
}

// ==================== EVENT LISTENERS ====================
function setupEventListeners() {
    // Navigation buttons
    document.getElementById('startBtn').addEventListener('click', () => goToPly(0));
    document.getElementById('prevBtn').addEventListener('click', () => goToPly(currentPly - 1));
    document.getElementById('nextBtn').addEventListener('click', () => goToPly(currentPly + 1));
    document.getElementById('endBtn').addEventListener('click', () => goToPly(analysis.analysis.length - 1));
    
    // Auto-play button
    document.getElementById('playBtn').addEventListener('click', toggleAutoPlay);
    
    // Flip board
    document.getElementById('flipBtn').addEventListener('click', () => {
        board.flip();
    });
    
    // Filter buttons
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.addEventListener('click', () => filterMoves(btn.dataset.filter));
    });
    
    // Export button
    document.getElementById('exportBtn').addEventListener('click', exportAnalysis);
    
    // Share button
    document.getElementById('shareBtn').addEventListener('click', showShareModal);
    
    // Keyboard shortcuts
    document.addEventListener('keydown', handleKeyPress);
}

function handleKeyPress(e) {
    switch(e.key) {
        case 'ArrowLeft':
            goToPly(currentPly - 1);
            break;
        case 'ArrowRight':
            goToPly(currentPly + 1);
            break;
        case 'Home':
            goToPly(0);
            break;
        case 'End':
            goToPly(analysis.analysis.length - 1);
            break;
        case ' ':
            e.preventDefault();
            toggleAutoPlay();
            break;
        case 'f':
            board.flip();
            break;
    }
}

// ==================== AUTO-PLAY ====================
function toggleAutoPlay() {
    const btn = document.getElementById('playBtn');
    
    if (autoPlayInterval) {
        clearInterval(autoPlayInterval);
        autoPlayInterval = null;
        btn.textContent = '▶️';
    } else {
        btn.textContent = '⏸️';
        autoPlayInterval = setInterval(() => {
            if (currentPly < analysis.analysis.length - 1) {
                goToPly(currentPly + 1);
            } else {
                toggleAutoPlay(); // Stop at end
            }
        }, 1000);
    }
}

// ==================== FILTER MOVES ====================
function filterMoves(filter) {
    // Update active button
    document.querySelectorAll('.filter-btn').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.filter === filter);
    });
    
    // Filter move items
    document.querySelectorAll('.move-item').forEach(item => {
        const ply = parseInt(item.dataset.ply);
        const move = analysis.analysis[ply];
        
        let show = true;
        if (filter === 'blunders') {
            show = move.judgment === 'BLUNDER';
        } else if (filter === 'mistakes') {
            show = move.judgment === 'MISTAKE';
        } else if (filter === 'inaccuracies') {
            show = move.judgment === 'INACCURACY';
        }
        
        item.style.display = show ? 'block' : 'none';
    });
}

// ==================== EVALUATION CHART ====================
const evalBackgroundPlugin = {
    id: 'evalBackground',
    beforeDraw(chart) {
        const { ctx, chartArea, scales } = chart;
        if (!chartArea) return;

        ctx.save();
        
        // White advantage area (top half, green)
        const zeroY = scales.y.getPixelForValue(0);
        ctx.fillStyle = 'rgba(34, 197, 94, 0.08)';
        ctx.fillRect(
            chartArea.left,
            chartArea.top,
            chartArea.right - chartArea.left,
            zeroY - chartArea.top
        );
        
        // Black advantage area (bottom half, red)
        ctx.fillStyle = 'rgba(239, 68, 68, 0.08)';
        ctx.fillRect(
            chartArea.left,
            zeroY,
            chartArea.right - chartArea.left,
            chartArea.bottom - zeroY
        );
        
        ctx.restore();
    }
};

const blunderMarkersPlugin = {
    id: 'blunderMarkers',
    afterDatasetsDraw(chart) {
        const { ctx, chartArea, scales } = chart;
        if (!chartArea || !analysis) return;

        ctx.save();
        
        analysis.analysis.forEach((move, index) => {
            if (move.judgment === 'BLUNDER' || move.loss_cp > 200) {
                const x = scales.x.getPixelForValue(index + 1);
                const y = scales.y.getPixelForValue(parseEval(move.eval_after));
                
                if (x >= chartArea.left && x <= chartArea.right &&
                    y >= chartArea.top && y <= chartArea.bottom) {
                    
                    // Draw pulsing circle
                    const gradient = ctx.createRadialGradient(x, y, 0, x, y, 8);
                    gradient.addColorStop(0, 'rgba(239, 68, 68, 0.8)');
                    gradient.addColorStop(1, 'rgba(239, 68, 68, 0.2)');
                    
                    ctx.fillStyle = gradient;
                    ctx.beginPath();
                    ctx.arc(x, y, 8, 0, Math.PI * 2);
                    ctx.fill();
                    
                    // Draw inner dot
                    ctx.fillStyle = '#ef4444';
                    ctx.beginPath();
                    ctx.arc(x, y, 4, 0, Math.PI * 2);
                    ctx.fill();
                }
            }
        });
        
        ctx.restore();
    }
};

const currentMoveIndicatorPlugin = {
    id: 'currentMoveIndicator',
    afterDatasetsDraw(chart) {
        const { ctx, chartArea, scales } = chart;
        if (!chartArea || currentPly === undefined) return;

        const x = scales.x.getPixelForValue(currentPly + 1);
        
        if (x >= chartArea.left && x <= chartArea.right) {
            ctx.save();
            
            // Draw vertical line
            ctx.strokeStyle = 'rgba(59, 130, 246, 0.6)';
            ctx.lineWidth = 2;
            ctx.setLineDash([5, 5]);
            ctx.beginPath();
            ctx.moveTo(x, chartArea.top);
            ctx.lineTo(x, chartArea.bottom);
            ctx.stroke();
            ctx.setLineDash([]);
            
            // Draw marker at top
            ctx.fillStyle = '#3b82f6';
            ctx.beginPath();
            ctx.moveTo(x, chartArea.top - 5);
            ctx.lineTo(x - 5, chartArea.top - 12);
            ctx.lineTo(x + 5, chartArea.top - 12);
            ctx.closePath();
            ctx.fill();
            
            ctx.restore();
        }
    }
};

function createEvalChart() {
    const canvas = document.getElementById('evalChart');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');

    if (evalChart) evalChart.destroy();

    const values = analysis.analysis.map(m => parseEval(m));
    const labels = values.map((_, i) => i + 1);

    evalChart = new Chart(ctx, {
        type: 'line',
        plugins: [evalBackgroundPlugin, blunderMarkersPlugin, currentMoveIndicatorPlugin],
        data: {
            labels,
            datasets: [{
                data: values,
                borderWidth: 3,
                pointRadius: 0,
                pointHoverRadius: 6,
                pointHoverBorderWidth: 3,
                pointHoverBackgroundColor: '#fff',
                tension: 0.2,
                spanGaps: true,

                segment: {
                    borderColor: ctx => {
                        const y0 = ctx.p0.parsed.y;
                        const y1 = ctx.p1.parsed.y;
                        if (y0 >= 0 && y1 >= 0) return '#22c55e';
                        if (y0 <= 0 && y1 <= 0) return '#ef4444';
                        return '#f59e0b';
                    }
                },

                fill: { target: 'origin' },
                backgroundColor: ctx => {
                    const chart = ctx.chart;
                    const {chartArea} = chart;
                    if (!chartArea) return 'transparent';
                    
                    const y = ctx.raw;
                    const gradient = chart.ctx.createLinearGradient(0, chartArea.top, 0, chartArea.bottom);
                    
                    if (y > 0) {
                        gradient.addColorStop(0, 'rgba(34, 197, 94, 0.3)');
                        gradient.addColorStop(1, 'rgba(34, 197, 94, 0.05)');
                    } else if (y < 0) {
                        gradient.addColorStop(0, 'rgba(239, 68, 68, 0.05)');
                        gradient.addColorStop(1, 'rgba(239, 68, 68, 0.3)');
                    } else {
                        gradient.addColorStop(0, 'transparent');
                        gradient.addColorStop(1, 'transparent');
                    }
                    
                    return gradient;
                }
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                intersect: false,
                mode: 'index'
            },
            onClick: (event, elements) => {
                if (elements.length > 0) {
                    const index = elements[0].index;
                    goToPly(index);
                }
            },
            onHover: (event, elements) => {
                event.native.target.style.cursor = elements.length > 0 ? 'pointer' : 'default';
            },
            scales: {
                x: {
                    title: {
                        display: true,
                        text: 'Move Number',
                        font: { size: 12, weight: '600' },
                        color: '#64748b'
                    },
                    grid: {
                        display: false
                    },
                    ticks: {
                        font: { size: 11 },
                        color: '#94a3b8'
                    }
                },
                y: {
                    min: -15,
                    max: 15,
                    title: {
                        display: true,
                        text: 'Evaluation (pawns)',
                        font: { size: 12, weight: '600' },
                        color: '#64748b'
                    },
                    grid: {
                        color: ctx => ctx.tick.value === 0 ? '#94a3b8' : 'rgba(148, 163, 184, 0.15)',
                        lineWidth: ctx => ctx.tick.value === 0 ? 2 : 1
                    },
                    ticks: {
                        font: { size: 11 },
                        color: '#94a3b8',
                        callback: value => {
                            if (value === 10) return '+10 (Win)';
                            if (value === -10) return '-10 (Win)';
                            return value > 0 ? `+${value}` : value;
                        }
                    }
                }
            },
            plugins: {
                legend: { display: false },
                tooltip: {
                    enabled: true,
                    backgroundColor: 'rgba(0, 0, 0, 0.85)',
                    titleColor: '#fff',
                    bodyColor: '#fff',
                    borderColor: 'rgba(255, 255, 255, 0.2)',
                    borderWidth: 1,
                    padding: 12,
                    cornerRadius: 8,
                    displayColors: false,
                    callbacks: {
                        title: ctx => {
                            const index = ctx[0].dataIndex;
                            const move = analysis.analysis[index];
                            return `Move ${move.ply}: ${move.move}`;
                        },
                        label: ctx => {
                            const index = ctx.dataIndex;
                            const move = analysis.analysis[index];
                            const lines = [`Evaluation: ${move.eval_after}`];
                            
                            if (move.judgment !== 'OK') {
                                lines.push(`Judgment: ${move.judgment}`);
                                lines.push(`Loss: ${move.loss.toFixed(2)} pawns`);
                            }
                            
                            return lines;
                        }
                    }
                }
            },
            animation: {
                duration: 750,
                easing: 'easeInOutQuart'
            }
        }
    });
}

function parseEval( move) {
    if (!move.eval_after) return NaN;

    // Mate detected
    if (move.eval_after.startsWith('M')) {
        // black just move → white win
        return move.color === 'white' ? 10 : -10;
    }

    const v = parseFloat(move.eval_after);
    return isNaN(v) ? NaN : v;
}


// ==================== KEY MOMENTS ====================
function findKeyMoments() {
    const keyMoments = analysis.analysis.filter(move => 
        move.judgment === 'BLUNDER' || move.loss_cp > 150
    );
    
    const container = document.getElementById('keyMoments');
    
    if (keyMoments.length === 0) {
        container.innerHTML = '<p style="color: #6b7280; text-align: center;">No critical mistakes found</p>';
        return;
    }
    
    container.innerHTML = '';
    
    keyMoments.forEach(move => {
        const item = document.createElement('div');
        item.className = 'key-moment-item';
        item.innerHTML = `
            <div class="key-moment-header">
                <span class="key-moment-move">Move ${move.ply}: ${move.move}</span>
                <span class="key-moment-type">${move.judgment}</span>
            </div>
            <div class="key-moment-description">
                Better: ${move.best_move} (Loss: ${move.loss.toFixed(2)} pawns)
            </div>
        `;
        
        item.addEventListener('click', () => {
            const ply = analysis.analysis.findIndex(m => m.ply === move.ply);
            goToPly(ply);
        });
        
        container.appendChild(item);
    });
}

// ==================== EXPORT ANALYSIS ====================
function exportAnalysis() {
    const report = {
        match_id: analysis.match_id,
        white: analysis.white,
        black: analysis.black,
        result: analysis.status,
        date: new Date().toISOString(),
        summary: {
            white: calculatePlayerStats('white'),
            black: calculatePlayerStats('black')
        },
        moves: analysis.analysis,
        pgn: analysis.pgn
    };
    
    const blob = new Blob([JSON.stringify(report, null, 2)], { 
        type: 'application/json' 
    });
    
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `analysis_${analysis.match_id}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    showNotification('Analysis exported successfully!');
}

// ==================== SHARE MODAL ====================
function showShareModal() {
    const modal = document.getElementById('shareModal');
    const shareLink = `${window.location.origin}/review/${analysis.match_id}`;
    document.getElementById('shareLink').value = shareLink;
    modal.classList.remove('hidden');
}

function closeShareModal() {
    document.getElementById('shareModal').classList.add('hidden');
}

function copyShareLink() {
    const input = document.getElementById('shareLink');
    input.select();
    document.execCommand('copy');
    showNotification('Link copied to clipboard!');
}

// ==================== ERROR HANDLING ====================
function showError(message) {
    document.getElementById('loadingOverlay').classList.add('hidden');
    document.getElementById('errorMessage').textContent = message;
    document.getElementById('errorModal').classList.remove('hidden');
}

// ==================== NOTIFICATIONS ====================
function showNotification(message) {
    const notification = document.createElement('div');
    notification.className = 'notification';
    notification.textContent = message;
    notification.style.cssText = `
        position: fixed;
        top: 80px;
        right: 20px;
        background: #10b981;
        color: white;
        padding: 1rem 1.5rem;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        z-index: 9998;
        animation: slideInRight 0.3s ease-out;
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.style.animation = 'slideOutRight 0.3s ease-out';
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// ==================== CLEANUP ====================
window.addEventListener('beforeunload', () => {
    if (autoPlayInterval) {
        clearInterval(autoPlayInterval);
    }
    if (evalChart) {
        evalChart.destroy();
    }
});

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideInRight {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }
    
    @keyframes slideOutRight {
        from {
            transform: translateX(0);
            opacity: 1;
        }
        to {
            transform: translateX(100%);
            opacity: 0;
        }
    }
`;
document.head.appendChild(style);

console.log('Review page initialized');


================================================
FILE: templates/auth/confirm.html
================================================
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Confirmation - Chess App</title>
    <link rel="stylesheet" href="/static/css/auth/auth.css">
</head>
<body>
    <div class="auth-container">
        <div class="auth-card">
            <div class="auth-header">
                <h1>Email Confirmation</h1>
                <p>Enter your confirmation token to verify your email address</p>
            </div>

            <form id="manualConfirmForm" class="auth-form">
                <div class="form-group">
                    <label for="tokenInput">Confirmation Token</label>
                    <input type="text" id="tokenInput" name="token" placeholder="Enter your confirmation token" required>
                    <div class="error-message" id="tokenError"></div>
                </div>
                <button type="submit" class="btn btn-primary" id="confirmBtn">
                    <span class="btn-text">Confirm Email</span>
                    <div class="btn-spinner" id="btnSpinner"></div>
                </button>
            </form>

            <div class="auth-links">
                <p>Didn't receive the token? <a href="/register" class="link">Register again</a></p>
                <p>Already confirmed? <a href="/login" class="link">Go to Login</a></p>
            </div>

            <div id="message" class="message"></div>
        </div>
    </div>

    <script src="/static/js/auth/confirm.js"></script>
</body>
</html>



================================================
FILE: templates/auth/login.html
================================================
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login - Chess App</title>
    <link rel="stylesheet" href="/static/css/auth/auth.css">
</head>
<body>
    <div class="auth-container">
        <div class="auth-card">
            <h1>Login to Chess App</h1>
            <form id="loginForm">
                <div class="form-group">
                    <label for="mail">Email:</label>
                    <input type="email" id="mail" name="mail" required>
                </div>
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <br>
                <button type="submit"style="width: 100%;" class="btn btn-primary">Login</button>
            </form>
            <div class="auth-links">
                <p>Don't have an account? <a href="/register">Register here</a></p>
            </div>
            <div id="message" class="message"></div>
        </div>
    </div>
    <script src="/static/js/auth/login.js"></script>
</body>
</html>



================================================
FILE: templates/auth/register.html
================================================
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register - Chess App</title>
    <link rel="stylesheet" href="/static/css/auth/auth.css">
</head>
<body>
    <div class="auth-container">
        <div class="auth-card">
            <div class="auth-header">
                <h1>Join Chess App</h1>
                <p>Create your account to start playing</p>
            </div>

            <form id="registerForm" class="auth-form">
                <div class="form-group">
                    <label for="name">Full Name</label>
                    <input type="text" id="name" name="name" placeholder="Enter your full name" required>
                    <div class="error-message" id="nameError"></div>
                </div>

                <div class="form-group">
                    <label for="mail">Email Address</label>
                    <input type="email" id="mail" name="mail" placeholder="Enter your email" required>
                    <div class="error-message" id="mailError"></div>
                </div>

                <div class="form-group">
                    <label for="password">Password</label>
                    <div class="password-input-container">
                        <input type="password" id="password" name="password" placeholder="Create a password" required>
                        <button type="button" class="password-toggle" id="passwordToggle">
                            <span class="eye-icon">👁️</span>
                        </button>
                    </div>
                    <div class="password-strength">
                        <div class="strength-meter">
                            <div class="strength-bar" id="strengthBar"></div>
                        </div>
                        <span class="strength-text" id="strengthText">Password strength</span>
                    </div>
                    <div class="error-message" id="passwordError"></div>
                </div>

                <div class="form-group">
                    <label for="confirmPassword">Confirm Password</label>
                    <input type="password" id="confirmPassword" name="confirmPassword" placeholder="Confirm your password" required>
                    <div class="error-message" id="confirmPasswordError"></div>
                </div>

                <button type="submit" class="btn btn-primary" id="registerBtn">
                    <span class="btn-text">Create Account</span>
                    <div class="btn-spinner" id="btnSpinner"></div>
                </button>
            </form>

            <div class="auth-divider">
                <span>or</span>
            </div>

            <div class="auth-links">
                <p>Already have an account? <a href="/login" class="link">Sign in here</a></p>
            </div>

            <div id="message" class="message"></div>
        </div>
    </div>

    <script src="/static/js/auth/register.js"></script>
</body>
</html>



================================================
FILE: templates/game/bot.html
================================================
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Chess vs Bot - Chess App</title>
    
    <!-- Chessboard CSS -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/chessboard-js/1.0.0/chessboard-1.0.0.min.css">
    
    <!-- Custom CSS (reuse game CSS) -->
    <link rel="stylesheet" href="/static/css/game/game.css">
    <link rel="stylesheet" href="/static/css/game/promotion.css">
    
    <!-- jQuery -->
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    
    <!-- Chess.js -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/chess.js/0.10.3/chess.min.js"></script>
    
    <!-- Chessboard.js -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/chessboard-js/1.0.0/chessboard-1.0.0.min.js"></script>
    
    <!-- Socket.IO -->
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
</head>
<body>
    <!-- Loading Overlay -->
    <div id="loadingOverlay" class="overlay">
        <div class="overlay-content">
            <div class="spinner-large"></div>
            <h2>Preparing bot match...</h2>
        </div>
    </div>
    
    <!-- Connection Status Banner -->
    <div id="connectionStatus" class="connection-banner hidden">
        <span class="status-icon">⚠️</span>
        <span class="status-text">Connecting...</span>
    </div>
    
    <div class="game-container">
        <!-- Header -->
        <header class="game-header">
            <div class="header-left">
                <button class="btn-back" onclick="window.location.href='/home'">
                    ← Back to Lobby
                </button>
            </div>
            <div class="header-center">
                <h1>♔ Chess vs Bot</h1>
                <div class="match-id">Match ID: <span id="matchIdDisplay">Loading...</span></div>
            </div>
            <div class="header-right">
                <div class="connection-indicator connected" id="connectionIndicator">
                    <span class="dot"></span>
                    <span class="text">Connected</span>
                </div>
            </div>
        </header>
        
        <div class="game-content">
            <!-- Left Sidebar - Bot Info & Controls -->
            <aside class="sidebar sidebar-left">
                <!-- Bot Info -->
                <div class="player-card opponent-card">
                    <div class="player-avatar">
                        <div class="avatar-icon">🤖</div>
                        <div class="connection-status" id="opponentStatus">
                            <span class="status-dot online"></span>
                        </div>
                    </div>
                    <div class="player-info">
                        <h3 class="player-name" id="opponentName">ChessBot</h3>
                        <div class="player-elo">
                            <span class="elo-label">ELO:</span>
                            <span class="elo-value" id="opponentElo">---</span>
                        </div>
                        <div class="player-color" id="opponentColor">
                            <span class="color-piece">♟</span>
                        </div>
                    </div>
                    <div class="captured-pieces" id="opponentCaptured">
                        <!-- Captured pieces will be added here -->
                    </div>
                </div>
                
                <!-- Game Controls -->
                <div class="game-controls">
                    <h4>Game Controls</h4>
                    <button class="btn btn-danger" id="resignBtn">
                        🏳️ Resign
                    </button>
                    <button class="btn btn-secondary" id="flipBoardBtn">
                        🔄 Flip Board
                    </button>
                    <button class="btn btn-warning" id="offerDrawBtn" disabled title="Draw offers not available vs bot">
                        🤝 Offer Draw
                    </button>
                </div>
                
                <!-- Game Status -->
                <div class="game-status-card">
                    <h4>Game Status</h4>
                    <div class="status-item">
                        <span class="label">Turn:</span>
                        <span class="value" id="turnIndicator">White</span>
                    </div>
                    <div class="status-item">
                        <span class="label">Move:</span>
                        <span class="value" id="moveNumber">1</span>
                    </div>
                    <div class="status-item">
                        <span class="label">Status:</span>
                        <span class="value status-ongoing" id="gameStatus">Ongoing</span>
                    </div>
                </div>
            </aside>
            
            <!-- Center - Chessboard -->
            <main class="board-area">
                <!-- Your Info -->
                <div class="player-card your-card your-card-top">
                    <div class="player-avatar small">
                        <div class="avatar-icon">👤</div>
                    </div>
                    <div class="player-info">
                        <h3 class="player-name" id="yourName">You</h3>
                        <div class="player-elo">
                            ELO: <span id="yourElo">---</span>
                        </div>
                        <div class="player-color" id="yourColor">
                            <span class="color-piece">♟</span>
                        </div>
                    </div>
                    <div class="captured-pieces small" id="yourCaptured">
                        <!-- Your captured pieces -->
                    </div>
                </div>
                
                <!-- Chessboard -->
                <div class="board-wrapper">
                    <div id="chessboard"></div>
                    <div class="board-overlay" id="boardOverlay">
                        <div class="overlay-message" id="overlayMessage"></div>
                    </div>
                </div>
                
                <!-- Move Indicator -->
                <div class="move-indicator" id="moveIndicator">
                    <div class="indicator-content">
                        <span class="indicator-icon">⏳</span>
                        <span class="indicator-text">Waiting for bot...</span>
                    </div>
                </div>
            </main>
            
            <!-- Right Sidebar - Move History -->
            <aside class="sidebar sidebar-right">
                <!-- Move History -->
                <div class="move-history-card">
                    <h4>Move History</h4>
                    <div class="move-history" id="moveHistory">
                        <p class="no-moves">No moves yet</p>
                    </div>
                </div>
                
                <!-- Bot Info Card -->
                <div class="chat-card" style="height: auto;">
                    <h4>🤖 Bot Information</h4>
                    <div style="padding: 1rem; background: #f8f9fa; border-radius: 8px;">
                        <p id="botDescription" style="color: #6b7280; font-size: 0.9rem; margin-bottom: 1rem;">
                            You are playing against an AI opponent powered by Stockfish engine.
                        </p>
                        <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
                            <span class="stat-badge" id="botDepth">Analyzing moves...</span>
                            <span class="stat-badge" id="botThinking">Thinking...</span>
                        </div>
                    </div>
                </div>
            </aside>
        </div>
    </div>
    
    <!-- Game End Modal -->
    <div id="gameEndModal" class="modal hidden">
        <div class="modal-content game-end-content">
            <div class="result-icon" id="resultIcon">🏆</div>
            <h2 class="result-title" id="resultTitle">Game Over</h2>
            <p class="result-message" id="resultMessage"></p>
            
            <div class="result-details">
                <div class="elo-changes" id="eloChanges">
                    <!-- ELO changes will be shown here -->
                </div>
            </div>
            
            <div class="modal-actions">
                <button class="btn btn-primary" onclick="window.location.href='/home'">
                    Back to Lobby
                </button>
            </div>
        </div>
    </div>
    
    <!-- Promotion Modal -->
    <div id="promotionModal" class="modal hidden">
        <div class="promotion-box">
            <h3>Promote pawn to</h3>
            <div class="promotion-options">
                <button data-piece="q">♕</button>
                <button data-piece="r">♖</button>
                <button data-piece="b">♗</button>
                <button data-piece="n">♘</button>
            </div>
        </div>
    </div>
    
    <!-- Custom Scripts -->
    <script src="/static/js/game/promotion.js"></script>
    <script src="/static/js/game/bot_game.js"></script>
    
    <style>
        .stat-badge {
            background: white;
            padding: 0.5rem 1rem;
            border-radius: 8px;
            font-size: 0.85rem;
            color: #6b7280;
            font-weight: 600;
            display: inline-block;
        }
    </style>
</body>
</html>


================================================
FILE: templates/game/index.html
================================================
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Chess Game - {{ match_id }}</title>
    
    <!-- Chessboard CSS -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/chessboard-js/1.0.0/chessboard-1.0.0.min.css">
    
    <!-- Custom CSS -->
    <link rel="stylesheet" href="/static/css/game/game.css">
    <link rel="stylesheet" href="/static/css/game/promotion.css">
    <!-- jQuery (required by chessboard.js) -->
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    
    <!-- Chess.js - Game logic -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/chess.js/0.10.3/chess.min.js"></script>
    
    <!-- Chessboard.js - Board UI -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/chessboard-js/1.0.0/chessboard-1.0.0.min.js"></script>
    
    <!-- Socket.IO Client -->
    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
</head>
<body>
    <!-- Loading Overlay -->
    <div id="loadingOverlay" class="overlay">
        <div class="overlay-content">
            <div class="spinner-large"></div>
            <h2>Loading game...</h2>
        </div>
    </div>
    
    <!-- Connection Status Banner -->
    <div id="connectionStatus" class="connection-banner hidden">
        <span class="status-icon">⚠️</span>
        <span class="status-text">Connecting...</span>
    </div>
    
    <div class="game-container">
        <!-- Header -->
        <header class="game-header">
            <div class="header-left">
                <button class="btn-back" onclick="window.location.href='/home'">
                    ← Back to Lobby
                </button>
            </div>
            <div class="header-center">
                <h1>♔ Chess Game</h1>
                <div class="match-id">Match ID: <span id="matchIdDisplay">{{ match_id }}</span></div>
            </div>
            <div class="header-right">
                <div class="connection-indicator" id="connectionIndicator">
                    <span class="dot"></span>
                    <span class="text">Connecting...</span>
                </div>
            </div>
        </header>
        
        <div class="game-content">
            <!-- Left Sidebar - Opponent Info & Controls -->
            <aside class="sidebar sidebar-left">
                <!-- Opponent Info -->
                <div class="player-card opponent-card">
                    <div class="player-avatar">
                        <div class="avatar-icon">👤</div>
                        <div class="connection-status" id="opponentStatus">
                            <span class="status-dot offline"></span>
                        </div>
                    </div>
                    <div class="player-info">
                        <h3 class="player-name" id="opponentName">Opponent</h3>
                        <div class="player-elo">
                            <span class="elo-label">ELO:</span>
                            <span class="elo-value" id="opponentElo">---</span>
                        </div>
                        <div class="player-color" id="opponentColor">
                            <span class="color-piece">♟</span>
                        </div>
                    </div>
                    <div class="captured-pieces" id="opponentCaptured">
                        <!-- Captured pieces will be added here -->
                    </div>
                </div>
                
                <!-- Game Controls -->
                <div class="game-controls">
                    <h4>Game Controls</h4>
                    <button class="btn btn-danger" id="resignBtn">
                        🏳️ Resign
                    </button>
                    <button class="btn btn-warning" id="offerDrawBtn">
                        🤝 Offer Draw
                    </button>
                    <button class="btn btn-secondary" id="flipBoardBtn">
                        🔄 Flip Board
                    </button>
                </div>
                
                <!-- Game Status -->
                <div class="game-status-card">
                    <h4>Game Status</h4>
                    <div class="status-item">
                        <span class="label">Turn:</span>
                        <span class="value" id="turnIndicator">White</span>
                    </div>
                    <div class="status-item">
                        <span class="label">Move:</span>
                        <span class="value" id="moveNumber">1</span>
                    </div>
                    <div class="status-item">
                        <span class="label">Status:</span>
                        <span class="value status-ongoing" id="gameStatus">Ongoing</span>
                    </div>
                </div>
            </aside>
            
            <!-- Center - Chessboard -->
            <main class="board-area">
                <!-- Your Info (above board) -->
                <div class="player-card your-card your-card-top">
                    <div class="player-avatar small">
                        <div class="avatar-icon">👤</div>
                    </div>
                    <div class="player-info">
                        <h3 class="player-name" id="yourName">You</h3>
                        <div class="player-elo">
                            ELO: <span id="yourElo">---</span>
                        </div>
                        <div class="player-color" id="yourColor">
                            <span class="color-piece">♟</span>
                        </div>
                    </div>
                    <div class="captured-pieces small" id="yourCaptured">
                        <!-- Your captured pieces -->
                    </div>
                </div>
                
                <!-- Chessboard -->
                <div class="board-wrapper">
                    <div id="chessboard"></div>
                    <div class="board-overlay" id="boardOverlay">
                        <div class="overlay-message" id="overlayMessage"></div>
                    </div>
                </div>
                
                <!-- Move Indicator -->
                <div class="move-indicator" id="moveIndicator">
                    <div class="indicator-content">
                        <span class="indicator-icon">⏳</span>
                        <span class="indicator-text">Waiting for opponent...</span>
                    </div>
                </div>
            </main>
            
            <!-- Right Sidebar - Move History & Chat -->
            <aside class="sidebar sidebar-right">
                <!-- Move History -->
                <div class="move-history-card">
                    <h4>Move History</h4>
                    <div class="move-history" id="moveHistory">
                        <p class="no-moves">No moves yet</p>
                    </div>
                </div>
                
                <!-- Chat -->
                <div class="chat-card">
                    <h4>Chat</h4>
                    <div class="chat-messages" id="chatMessages">
                        <p class="chat-info">Chat with your opponent</p>
                    </div>
                    <div class="chat-input-area">
                        <input 
                            type="text" 
                            id="chatInput" 
                            placeholder="Type a message..."
                            maxlength="200"
                        >
                        <button class="btn-send" id="sendChatBtn">📤</button>
                    </div>
                </div>
            </aside>
        </div>
    </div>
    
    <!-- Game End Modal -->
    <div id="gameEndModal" class="modal hidden">
        <div class="modal-content game-end-content">
            <div class="result-icon" id="resultIcon">🏆</div>
            <h2 class="result-title" id="resultTitle">Game Over</h2>
            <p class="result-message" id="resultMessage"></p>
            
            <div class="result-details">
                <div class="elo-changes" id="eloChanges">
                    <!-- ELO changes will be shown here -->
                </div>
            </div>
            
            <div class="modal-actions">
                <button class="btn btn-primary" onclick="window.location.href='/home'">
                    Back to Lobby
                </button>
                <button class="btn btn-secondary" onclick="location.reload()">
                    View Game
                </button>
            </div>
        </div>
    </div>
    
    <!-- Draw Offer Modal -->
    <div id="drawOfferModal" class="modal hidden">
        <div class="modal-content">
            <h3>🤝 Draw Offer</h3>
            <p>Your opponent offers a draw. Do you accept?</p>
            <div class="modal-actions">
                <button class="btn btn-success" id="acceptDrawBtn">Accept</button>
                <button class="btn btn-danger" id="declineDrawBtn">Decline</button>
            </div>
        </div>
    </div>
    <!-- Promotion Modal -->
    <div id="promotionModal" class="modal hidden">
        <div class="promotion-box">
            <h3>Promote pawn to</h3>
            <div class="promotion-options">
                <button data-piece="q">♕</button>
                <button data-piece="r">♖</button>
                <button data-piece="b">♗</button>
                <button data-piece="n">♘</button>
            </div>
        </div>
    </div>
    <!-- Hidden data for JS -->
    <input type="hidden" id="matchId" value="{{ match_id }}">
    
    <!-- Custom Game Script -->
    <script src="/static/js/game/promotion.js"></script>
    <script src="/static/js/game/game.js"></script>
</body>
</html>


================================================
FILE: templates/matching/index.html
================================================
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Find Match - Chess App</title>
    <link rel="stylesheet" href="/static/css/matching/matching.css">
</head>

<body>
    <div class="container">
        <header class="header">
            <div class="logo">♔ Chess App</div>
            <div class="user-info">
                <span id="userName">Loading...</span>
                <span id="userElo" class="elo-badge">ELO: ---</span>
                <button class="btn-logout" onclick="logout()">Logout</button>
            </div>
        </header>

        <main class="main-content">
            <!-- Idle State -->
            <div id="idleState" class="state-container">
                <div class="welcome-card">
                    <h1>Ready to Play?</h1>
                    <hr>
                    <br>
                    <p>Find an opponent and start your chess game</p>
                    <button id="findMatchBtn" class="btn btn-primary btn-large">
                        🎯 Find Match
                    </button>
                </div>
                <!-- Xóa phần cũ và thay bằng: -->
                <div class="bot-fight-section">
                    <h2>🤖 Play vs Computer</h2>
                    <hr><br>
                    <p style="color: #6b7280; margin-bottom: 1rem;">
                        Practice your skills against AI opponents of varying difficulty levels
                    </p>
                    <!-- Bot fight -->
                    <div class="bot-difficulty-grid">
                        <!-- Beginner Bot -->
                        <div class="bot-card" data-difficulty="beginner">
                            <div class="bot-header">
                                <div class="bot-icon">🐣</div>
                                <div class="bot-info">
                                    <h3 class="bot-name">ChessBot Junior</h3>
                                    <div class="bot-elo">ELO: 400-800</div>
                                </div>
                            </div>
                            <div class="bot-description">
                                Perfect for beginners. Makes occasional mistakes and plays simple strategies.
                            </div>
                            <div class="bot-stats">
                                <span class="stat-badge">Depth: 2</span>
                                <span class="stat-badge">Thinking: 0.5s</span>
                            </div>
                            <button class="btn btn-primary btn-play-bot" data-difficulty="beginner">
                                ▶️ Play
                            </button>
                        </div>

                        <!-- Easy Bot -->
                        <div class="bot-card" data-difficulty="easy">
                            <div class="bot-header">
                                <div class="bot-icon">🐥</div>
                                <div class="bot-info">
                                    <h3 class="bot-name">ChessBot Hard</h3>
                                    <div class="bot-elo">ELO: 800-1200</div>
                                </div>
                            </div>
                            <div class="bot-description">
                                Good for learning. Plays decent openings but can be exploited in the middlegame.
                            </div>
                            <div class="bot-stats">
                                <span class="stat-badge">Depth: 5</span>
                                <span class="stat-badge">Thinking: 1.0s</span>
                            </div>
                            <button class="btn btn-primary btn-play-bot" data-difficulty="easy">
                                ▶️ Play
                            </button>
                        </div>

                        <!-- Medium Bot -->
                        <div class="bot-card" data-difficulty="medium">
                            <div class="bot-header">
                                <div class="bot-icon">🦅</div>
                                <div class="bot-info">
                                    <h3 class="bot-name">ChessBot Super</h3>
                                    <div class="bot-elo">ELO: 1200-1600</div>
                                </div>
                            </div>
                            <div class="bot-description">
                                Intermediate level. Solid tactical play and reasonable strategic understanding.
                            </div>
                            <div class="bot-stats">
                                <span class="stat-badge">Depth: 8</span>
                                <span class="stat-badge">Thinking: 1.5s</span>
                            </div>
                            <button class="btn btn-primary btn-play-bot" data-difficulty="medium">
                                ▶️ Play
                            </button>
                        </div>

                        <!-- Hard Bot -->
                        <div class="bot-card" data-difficulty="hard">
                            <div class="bot-header">
                                <div class="bot-icon">🦁</div>
                                <div class="bot-info">
                                    <h3 class="bot-name">ChessBot Master</h3>
                                    <div class="bot-elo">ELO: 1600-2000</div>
                                </div>
                            </div>
                            <div class="bot-description">
                                Advanced opponent. Strong tactical vision and positional understanding.
                            </div>
                            <div class="bot-stats">
                                <span class="stat-badge">Depth: 12</span>
                                <span class="stat-badge">Thinking: 2.0s</span>
                            </div>
                            <button class="btn btn-primary btn-play-bot" data-difficulty="hard">
                                ▶️ Play
                            </button>
                        </div>

                        <!-- Expert Bot -->
                        <div class="bot-card" data-difficulty="expert">
                            <div class="bot-header">
                                <div class="bot-icon">👑</div>
                                <div class="bot-info">
                                    <h3 class="bot-name">ChessBot Godlike</h3>
                                    <div class="bot-elo">ELO: 2000+</div>
                                </div>
                            </div>
                            <div class="bot-description">
                                Master level. Extremely strong play with deep calculation and perfect tactics.
                            </div>
                            <div class="bot-stats">
                                <span class="stat-badge">Depth: 16</span>
                                <span class="stat-badge">Thinking: 3.0s</span>
                            </div>
                            <button class="btn btn-primary btn-play-bot" data-difficulty="expert">
                                ▶️ Play
                            </button>
                        </div>
                    </div>
                </div>

                <!-- Thêm script trước </body> -->
                <script src="/static/js/matching/bot_selection.js"></script>
                <!-- User Stats -->
                <div class="stats-card">
                    <h2>Your Statistics</h2>
                    <hr>
                    <br>
                    <div id="userStats" class="stats-grid">
                        <div class="stat-item">
                            <span class="stat-label">Total Games</span>
                            <span class="stat-value" id="totalGames">0</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-label">Wins</span>
                            <span class="stat-value" style="color:#5A9CB5" id="wins">0</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-label">Draws</span>
                            <span class="stat-value" style="color:#FACE68" id="draws">0</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-label">Losses</span>
                            <span class="stat-value" style="color:#FAAC68" id="losses">0</span>
                        </div>
                        <div class="stat-item">
                            <span class="stat-label">Win Rate</span>
                            <span class="stat-value" style="color:#FA6868" id="winRate">0%</span>
                        </div>
                    </div>
                </div>
            </div>

            <!-- Waiting State -->
            <div id="waitingState" class="state-container" style="display: none;">
                <div class="waiting-card">
                    <div class="spinner-large"></div>
                    <h2>Searching for Opponent...</h2>
                    <p>ELO Range: <span id="eloRange">---</span></p>
                    <p>Queue Position: <span id="queuePosition">---</span></p>
                    <p>Wait Time: <span id="waitTime">0s</span></p>
                    <button id="cancelMatchBtn" class="btn btn-secondary">
                        Cancel Search
                    </button>
                </div>
            </div>

            <!-- Matched State -->
            <div id="matchedState" class="state-container" style="display: none;">
                <div class="matched-card">
                    <div class="success-icon">✓</div>
                    <h2>Match Found!</h2>

                    <div class="opponent-info">
                        <h3>Opponent</h3>
                        <p class="opponent-name" id="opponentName">---</p>
                        <p class="opponent-elo">ELO: <span id="opponentElo">---</span></p>
                    </div>

                    <div class="match-info">
                        <p>You are playing as: <span class="color-badge" id="yourColor">---</span></p>
                    </div>

                    <!-- Auto-redirect notice will be added here dynamically -->
                    <div id="autoRedirectNotice"></div>

                    <button id="startGameBtn" class="btn btn-primary btn-large">
                        Start Game
                    </button>

                    <p style="margin-top: 1rem; font-size: 0.9rem; color: #6b7280;">
                        The game will start automatically, or click the button to start now
                    </p>
                </div>
            </div>

            <!-- Recent Matches -->
            <div class="recent-matches">
                <h2>Recent Matches</h2>
                <hr>
                <br>
                <div id="matchHistory" class="match-list">...</div>

                <div class="pagination-nav">
                    <!-- <div class="pagination-info">1-5 of 20</div> -->
                    <div class="pagination-buttons">
                        <button class="pagination-btn" id="prevPageBtn" onclick="prevPage()">
                            < </button>
                                <button class="pagination-btn" id="nextPageBtn" onclick="nextPage()"> > </button>
                    </div>
                </div>
            </div>
            <!-- Leaderboard -->
            <div class="leaderboard">
                <h2>🏆 Top Players</h2>
                <hr>
                <br>
                <div id="leaderboardList" class="leaderboard-list">
                    <p class="loading">Loading leaderboard...</p>
                </div>
            </div>


        </main>
    </div>
    <script src="/static/js/matching/bot_selection.js"></script>
    <script src="/static/js/matching/matching.js"></script>
    <script src="/static/js/matching/recent_matches.js"></script>
</body>

</html>


================================================
FILE: templates/review/index.html
================================================
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Game Review - Chess App</title>
    
    <!-- Chessboard CSS -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/chessboard-js/1.0.0/chessboard-1.0.0.min.css">
    
    <!-- Custom CSS -->
    <link rel="stylesheet" href="/static/css/review/review.css">
    
    <!-- jQuery (required by chessboard.js) -->
    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    
    <!-- Chess.js -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/chess.js/0.10.3/chess.min.js"></script>
    
    <!-- Chessboard.js -->
    <script src="https://cdnjs.cloudflare.com/ajax/libs/chessboard-js/1.0.0/chessboard-1.0.0.min.js"></script>
    
    <!-- Chart.js for evaluation graph -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
</head>
<body>
    <!-- Loading Overlay -->
    <div id="loadingOverlay" class="overlay">
        <div class="overlay-content">
            <div class="spinner-large"></div>
            <h2>Analyzing game...</h2>
            <p>Please wait while we process the analysis</p>
        </div>
    </div>

    <div class="review-container">
        <!-- Header -->
        <header class="review-header">
            <div class="header-left">
                <button class="btn-back" onclick="window.location.href='/home'">
                    ← Back to Lobby
                </button>
            </div>
            <div class="header-center">
                <h1>📊 Game Analysis</h1>
                <div class="match-id">Match ID: <span id="matchIdDisplay">{{ match_id }}</span></div>
            </div>
            <div class="header-right">
                <button class="btn-secondary" id="exportBtn">
                    📥 Export Report
                </button>
            </div>
        </header>

        <!-- Game Info Banner -->
        <div class="game-info-banner">
            <div class="player-info-card white">
                <div class="piece-icon">♔</div>
                <div class="player-details">
                    <div class="player-name" id="whiteName">White Player</div>
                    <div class="player-elo" id="whiteElo">ELO: ---</div>
                </div>
                <div class="player-stats">
                    <div class="stat-badge blunders">
                        <span class="stat-label">Blunders</span>
                        <span class="stat-value" id="whiteBlunders">0</span>
                    </div>
                    <div class="stat-badge mistakes">
                        <span class="stat-label">Mistakes</span>
                        <span class="stat-value" id="whiteMistakes">0</span>
                    </div>
                    <div class="stat-badge inaccuracies">
                        <span class="stat-label">Inaccuracies</span>
                        <span class="stat-value" id="whiteInaccuracies">0</span>
                    </div>
                    <div class="stat-badge avg-loss">
                        <span class="stat-label">Avg Loss</span>
                        <span class="stat-value" id="whiteAvgLoss">0.00</span>
                    </div>
                </div>
            </div>

            <div class="vs-divider">
                <div class="result-badge" id="gameResult">1-0</div>
                <div class="game-date" id="gameDate">Dec 20, 2025</div>
            </div>

            <div class="player-info-card black">
                <div class="piece-icon">♚</div>
                <div class="player-details">
                    <div class="player-name" id="blackName">Black Player</div>
                    <div class="player-elo" id="blackElo">ELO: ---</div>
                </div>
                <div class="player-stats">
                    <div class="stat-badge blunders">
                        <span class="stat-label">Blunders</span>
                        <span class="stat-value" id="blackBlunders">0</span>
                    </div>
                    <div class="stat-badge mistakes">
                        <span class="stat-label">Mistakes</span>
                        <span class="stat-value" id="blackMistakes">0</span>
                    </div>
                    <div class="stat-badge inaccuracies">
                        <span class="stat-label">Inaccuracies</span>
                        <span class="stat-value" id="blackInaccuracies">0</span>
                    </div>
                    <div class="stat-badge avg-loss">
                        <span class="stat-label">Avg Loss</span>
                        <span class="stat-value" id="blackAvgLoss">0.00</span>
                    </div>
                </div>
            </div>
        </div>

        <div class="review-content">
            <!-- Left Panel: Board & Controls -->
            <div class="board-panel">
                <div class="board-wrapper">
                    <div id="reviewBoard"></div>
                </div>

                <!-- Board Controls -->
                <div class="board-controls">
                    <button class="control-btn" id="startBtn" title="Go to start">
                        ⏮️
                    </button>
                    <button class="control-btn" id="prevBtn" title="Previous move">
                        ◀️
                    </button>
                    <button class="control-btn" id="playBtn" title="Auto-play">
                        ▶️
                    </button>
                    <button class="control-btn" id="nextBtn" title="Next move">
                        ▶️
                    </button>
                    <button class="control-btn" id="endBtn" title="Go to end">
                        ⏭️
                    </button>
                    <button class="control-btn" id="flipBtn" title="Flip board">
                        🔄
                    </button>
                </div>

                <!-- Current Move Info -->
                <div class="current-move-card">
                    <div class="move-header">
                        <h3>Move <span id="currentMoveNumber">1</span>: <span id="currentMove">e4</span></h3>
                        <div class="judgment-badge" id="moveBadge">OK</div>
                    </div>
                    
                    <div class="eval-display">
                        <div class="eval-item">
                            <span class="eval-label">Before</span>
                            <span class="eval-value" id="evalBefore">+0.20</span>
                        </div>
                        <div class="eval-arrow">→</div>
                        <div class="eval-item">
                            <span class="eval-label">After</span>
                            <span class="eval-value" id="evalAfter">+0.25</span>
                        </div>
                    </div>

                    <div class="best-move-container" id="bestMoveContainer" style="display: none;">
                        <div class="best-move-header">
                            <span>💡 Better move available</span>
                        </div>
                        <div class="best-move-content">
                            <span class="label">Best:</span>
                            <span class="move" id="bestMove">Nf3</span>
                            <span class="loss">Loss: <span id="moveLoss">0.5</span> pawns</span>
                        </div>
                    </div>
                </div>

                <!-- Evaluation Graph -->
                <div class="eval-graph-card">
                    <h3>Position Evaluation</h3>
                    <span>green mean white win, red mean black win, yellow mean table turn</span>
                    <canvas id="evalChart"></canvas>
                </div>
            </div>

            <!-- Right Panel: Move List & Analysis -->
            <div class="analysis-panel">
                <!-- Quick Stats Summary -->
                <div class="stats-summary-card">
                    <h3>Game Summary</h3>
                    <div class="summary-grid">
                        <div class="summary-item">
                            <span class="label">Total Moves</span>
                            <span class="value" id="totalMoves">0</span>
                        </div>
                        <div class="summary-item">
                            <span class="label">Accurate Moves</span>
                            <span class="value accurate" id="accurateMoves">0</span>
                        </div>
                        <div class="summary-item">
                            <span class="label">Total Errors</span>
                            <span class="value errors" id="totalErrors">0</span>
                        </div>
                        <div class="summary-item">
                            <span class="label">Critical Moments</span>
                            <span class="value critical" id="criticalMoments">0</span>
                        </div>
                    </div>
                </div>

                <!-- Move List with Analysis -->
                <div class="move-list-card">
                    <div class="move-list-header">
                        <h3>Move Analysis</h3>
                        <div class="filter-buttons">
                            <button class="filter-btn active" data-filter="all">All</button>
                            <button class="filter-btn" data-filter="blunders">Blunders</button>
                            <button class="filter-btn" data-filter="mistakes">Mistakes</button>
                            <button class="filter-btn" data-filter="inaccuracies">Inaccuracies</button>
                        </div>
                    </div>
                    
                    <div class="move-list-container" id="moveList">
                        <!-- Moves will be populated here -->
                        <div class="no-moves">Loading moves...</div>
                    </div>
                </div>

                <!-- Key Moments -->
                <div class="key-moments-card">
                    <h3>🔑 Critical Moments</h3>
                    <div id="keyMoments" class="key-moments-list">
                        <!-- Critical moments will be listed here -->
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Share Modal -->
    <div id="shareModal" class="modal hidden">
        <div class="modal-content">
            <div class="modal-header">
                <h3>Share Analysis</h3>
                <button class="modal-close" onclick="closeShareModal()">×</button>
            </div>
            <div class="modal-body">
                <p>Share this game analysis with others:</p>
                <div class="share-link-container">
                    <input type="text" id="shareLink" readonly>
                    <button class="btn-primary" onclick="copyShareLink()">Copy Link</button>
                </div>
            </div>
        </div>
    </div>

    <!-- Error Modal -->
    <div id="errorModal" class="modal hidden">
        <div class="modal-content error">
            <div class="error-icon">❌</div>
            <h3>Analysis Not Available</h3>
            <p id="errorMessage">Unable to load game analysis.</p>
            <button class="btn-primary" onclick="window.location.href='/home'">
                Back to Lobby
            </button>
        </div>
    </div>

    <!-- Hidden data -->
    <input type="hidden" id="matchId" value="{{ match_id }}">

    <!-- Custom Scripts -->
    <script src="/static/js/review/review.js"></script>
</body>
</html>


================================================
FILE: utils/helper.py
================================================
# utils/helper.py
from flask import request
import jwt
from bson import ObjectId
from Models.user_model import User
import logging
import os
from dotenv import load_dotenv, find_dotenv
# Load environment variables
load_dotenv(find_dotenv())


logger = logging.getLogger(__name__)

#  ============ HELPER FUNCTION ============
def get_user_from_token():
    """Extract user_id from JWT token"""
    SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'linh')
    access_token = request.cookies.get('access_token')
    
    if not access_token:
        return None, {"message": "Not authenticated"}, 401
    
    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=['HS256'])
        user_id = ObjectId(payload.get('user_id'))
        return user_id, None, None
    except jwt.ExpiredSignatureError:
        return None, {"message": "Token expired"}, 401
    except jwt.InvalidTokenError:
        return None, {"message": "Invalid token"}, 401
    except Exception as e:
        logger.error(f"Token decode error: {e}")
        return None, {"message": "Authentication error"}, 401
    

def bot_initial_setup():
    bots = [
        User(
            _id=ObjectId("000000000000000000000000"),
            name="ChessBot Junior",
            mail="bot_junior@system.com",
            passwd="!",
            elo=600,
            status="idle",
            is_bot=True,
        ),
        User(
            _id=ObjectId("000000000000000000000001"),
            name="ChessBot Hard",
            mail="bot_hard@system.com",
            passwd="!",
            elo=1000,
            status="idle",
            is_bot=True,
        ),
        User(
            _id=ObjectId("000000000000000000000002"),
            name="ChessBot Super",
            mail="bot_super@system.com",
            passwd="!",
            elo=1400,
            status="idle",
            is_bot=True,
        ),
        User(
            _id=ObjectId("000000000000000000000003"),
            name="ChessBot Master",
            mail="bot_master@system.com",
            passwd="!",
            elo=1800,
            status="idle",
            is_bot=True,
        ),
        User(
            _id=ObjectId("000000000000000000000004"),
            name="ChessBot Godlike",
            mail="bot_god@system.com",
            passwd="!",
            elo=2200,
            status="idle",
            is_bot=True,
        ),
    ]

    from DB.connect import user_col

    existing_ids = {
        u["_id"] for u in user_col.find(
            {"_id": {"$in": [b._id for b in bots]}},
            {"_id": 1}
        )
    }

    new_bots = [b.to_dict() for b in bots if b._id not in existing_ids]

    if new_bots:
        user_col.insert_many(new_bots)



================================================
FILE: utils/validators.py
================================================
from flask import request, jsonify
from functools import wraps
import re

class ValidationError(Exception):
    def __init__(self, message, status_code=400):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        raise ValidationError("Invalid email format")
    return email.strip().lower()

def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        raise ValidationError("Password must be at least 8 characters")
    if not re.search(r'[A-Za-z]', password):
        raise ValidationError("Password must contain letters")
    if not re.search(r'\d', password):
        raise ValidationError("Password must contain numbers")
    return password

def validate_username(name):
    """Validate username"""
    name = name.strip()
    if len(name) < 2 or len(name) > 50:
        raise ValidationError("Name must be 2-50 characters")
    if not re.match(r'^[a-zA-Z0-9_\s]+$', name):
        raise ValidationError("Name can only contain letters, numbers, and underscores")
    return name

def validate_elo(elo):
    """Validate ELO rating"""
    try:
        elo_int = int(elo)
        if elo_int < 0 or elo_int > 3500:
            raise ValidationError("ELO must be between 0 and 3500")
        return elo_int
    except ValueError:
        raise ValidationError("ELO must be a number")

def require_fields(*fields):
    """Decorator to validate required fields"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            data = request.get_json() or {}
            missing = [field for field in fields if not data.get(field)]
            
            if missing:
                return jsonify({
                    "message": f"Missing required fields: {', '.join(missing)}"
                }), 400
            
            return f(*args, **kwargs)
        return decorated
    return decorator

# ============ ERROR HANDLERS ============
def register_error_handlers(app):
    """Register global error handlers"""
    
    @app.errorhandler(ValidationError)
    def handle_validation_error(e):
        return jsonify({"message": e.message}), e.status_code
    
    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({"message": "Bad request"}), 400
    
    @app.errorhandler(401)
    def unauthorized(e):
        return jsonify({"message": "Unauthorized"}), 401
    
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"message": "Resource not found"}), 404
    
    @app.errorhandler(500)
    def internal_error(e):
        return jsonify({"message": "Internal server error"}), 500


# ============ USAGE EXAMPLE ============
"""
from utils.validators import require_fields, validate_email, validate_password

@auth_bp.route('/register', methods=['POST'])
@require_fields('mail', 'password', 'name')
def register():
    data = request.get_json()
    
    try:
        mail = validate_email(data['mail'])
        passwd = validate_password(data['password'])
        name = validate_username(data['name'])
    except ValidationError as e:
        return jsonify({"message": e.message}), e.status_code
    
    # ... rest of logic
"""


================================================
FILE: web_socket/pve.py
================================================
from flask_socketio import emit, join_room, leave_room
from flask import request
from bson import ObjectId
import chess
import logging
from datetime import datetime
import random

from controllers.bot.bot_controller import (
    ChessBot, create_bot_match, get_bot_match,
    append_move_to_bot_pgn, end_bot_match, is_valid_bot_player
)
from Models.bot_model import BotProfile, BotDifficulty
from controllers.users.users_controller import change_user_status, get_user_by_id
from Models.user_model import UserStatus

logger = logging.getLogger(__name__)

active_bot_matches = {}

def register_bot_socket_events(socketio):
    """Register all bot-related WebSocket events"""
    
    @socketio.on('create_bot_match')
    def handle_create_bot_match(data):
        try:
            user_id = data.get('user_id')
            difficulty = data.get('difficulty')
            
            if not user_id:
                emit('error', {'message': 'Missing user_id'})
                return
            
            try:
                BotDifficulty(difficulty)
            except ValueError:
                emit('error', {'message': 'Invalid difficulty level'})
                return
            
            user_obj_id = ObjectId(user_id)
            player_color = random.choice(['white', 'black'])
            
            bot_match = create_bot_match(user_obj_id, difficulty, player_color)
            change_user_status(user_obj_id, UserStatus.PLAYING)
            
            bot_name = BotProfile.get_bot_name(difficulty)
            bot_elo = BotProfile.get_bot_elo(difficulty)
            user = get_user_by_id(user_obj_id)
            
            logger.info(f"[+] Bot match created: {bot_match._id}")
            
            match_id = str(bot_match._id)
            join_room(match_id)
            
            emit('bot_match_created', {
                'status': 'success',
                'match_id': match_id,
                'your_color': player_color,
                'bot': {
                    'name': bot_name,
                    'elo': bot_elo,
                    'difficulty': difficulty
                },
                'player': {
                    'name': user.name,
                    'elo': user.elo
                },
                'timestamp': datetime.utcnow().isoformat()
            })
            
            if player_color == 'black':
                socketio.start_background_task(
                    make_bot_move, 
                    match_id, 
                    difficulty, 
                    'rnbqkbnr/pppppppp/8/8/8/8/PPPPPPPP/RNBQKBNR w KQkq - 0 1',
                    socketio
                )
            
        except Exception as e:
            logger.error(f"[-] Create bot match error: {e}")
            emit('error', {'message': 'Failed to create bot match'})
    
    @socketio.on('join_bot_match')
    def handle_join_bot_match(data):
        try:
            match_id = data.get('match_id')
            user_id = data.get('user_id')
            
            if not match_id or not user_id:
                emit('error', {'message': 'Missing match_id or user_id'})
                return
            
            match_obj_id = ObjectId(match_id)
            user_obj_id = ObjectId(user_id)
            
            is_valid, error_msg = is_valid_bot_player(match_obj_id, user_obj_id)
            if not is_valid:
                emit('error', {'message': error_msg})
                return
            
            bot_match = get_bot_match(match_obj_id)
            if not bot_match:
                emit('error', {'message': 'Bot match not found'})
                return
            
            join_room(match_id)
            
            bot_name = BotProfile.get_bot_name(bot_match.bot_difficulty)
            bot_elo = BotProfile.get_bot_elo(bot_match.bot_difficulty)
            user = get_user_by_id(user_obj_id)
            
            logger.info(f"[+] Player joined bot match: {match_id}")
            
            emit('bot_match_joined', {
                'status': 'success',
                'match_id': match_id,
                'your_color': bot_match.player_color,
                'pgn': bot_match.pgn,
                'match_status': bot_match.status,
                'bot': {
                    'name': bot_name,
                    'elo': bot_elo,
                    'difficulty': bot_match.bot_difficulty
                },
                'player': {
                    'name': user.name,
                    'elo': user.elo
                },
                'timestamp': datetime.utcnow().isoformat()
            })
            
            change_user_status(user_obj_id, UserStatus.PLAYING)
            
        except Exception as e:
            logger.error(f"[-] Join bot match error: {e}")
            emit('error', {'message': 'Failed to join bot match'})
    
    @socketio.on('bot_player_move')
    def handle_bot_player_move(data):
        try:
            match_id = data.get('match_id')
            move = data.get('move')
            fen = data.get('fen')
            user_id = data.get('user_id')
            
            if not all([match_id, move, user_id, fen]):
                emit('move_error', {'message': 'Missing required data'})
                return
            
            match_obj_id = ObjectId(match_id)
            user_obj_id = ObjectId(user_id)
            
            is_valid, error_msg = is_valid_bot_player(match_obj_id, user_obj_id)
            if not is_valid:
                emit('move_error', {'message': error_msg})
                return
            
            bot_match = get_bot_match(match_obj_id)
            if not bot_match:
                emit('move_error', {'message': 'Bot match not found'})
                return
            
            success = append_move_to_bot_pgn(match_obj_id, move)
            
            if success:
                logger.info(f"[+] Player move in bot match {match_id}: {move}")
                
                emit('move_accepted', {
                    'move': move,
                    'fen': fen,
                    'timestamp': datetime.utcnow().isoformat()
                })
                
                board = chess.Board(fen)
                if board.is_game_over():
                    handle_bot_game_over(match_id, board, bot_match, socketio)
                    return
                
                socketio.start_background_task(
                    make_bot_move,
                    match_id,
                    bot_match.bot_difficulty,
                    fen,
                    socketio
                )
            else:
                emit('move_error', {'message': 'Failed to save move'})
                
        except Exception as e:
            logger.error(f"[-] Bot player move error: {e}")
            emit('move_error', {'message': 'Internal error'})
    
    @socketio.on('bot_resign')
    def handle_bot_resign(data):
        try:
            match_id = data.get('match_id')
            user_id = data.get('user_id')
            
            if not match_id or not user_id:
                emit('error', {'message': 'Missing required data'})
                return
            
            match_obj_id = ObjectId(match_id)
            user_obj_id = ObjectId(user_id)
            
            is_valid, error_msg = is_valid_bot_player(match_obj_id, user_obj_id)
            if not is_valid:
                emit('error', {'message': error_msg})
                return
            
            success = end_bot_match(match_obj_id, 'bot_win')
            
            if success:
                logger.info(f"[+] Player resigned from bot match {match_id}")
                
                from DB.connect import user_col
                user = user_col.find_one({'_id': user_obj_id})
                
                emit('bot_game_ended', {
                    'result': 'bot_win',
                    'reason': 'resignation',
                    'player_elo': user.get('elo'),
                    'timestamp': datetime.utcnow().isoformat()
                }, room=match_id)
                
                active_bot_matches.pop(match_id, None)
            else:
                emit('error', {'message': 'Failed to resign'})
                
        except Exception as e:
            logger.error(f"[-] Bot resign error: {e}")
            emit('error', {'message': 'Internal error'})
    
    @socketio.on('leave_bot_match')
    def handle_leave_bot_match(data):
        try:
            match_id = data.get('match_id')
            user_id = data.get('user_id')
            
            if not match_id or not user_id:
                return
            
            leave_room(match_id)
            logger.info(f"[+] Player left bot match {match_id}")
            
            change_user_status(ObjectId(user_id), UserStatus.IDLE)
            active_bot_matches.pop(match_id, None)
            
        except Exception as e:
            logger.error(f"[-] Leave bot match error: {e}")


def make_bot_move(match_id: str, difficulty: str, current_fen: str, socketio):
    try:
        logger.info(f"🤖 Bot thinking... (difficulty: {difficulty})")
        
        with ChessBot(difficulty) as bot:
            san_move, new_fen = bot.make_move(current_fen)
            
            if not san_move or not new_fen:
                logger.error("Bot failed to make move")
                return
            
            match_obj_id = ObjectId(match_id)
            success = append_move_to_bot_pgn(match_obj_id, san_move)
            
            if success:
                logger.info(f"🤖 Bot move: {san_move}")
                
                socketio.emit('bot_move', {
                    'move': san_move,
                    'fen': new_fen,
                    'timestamp': datetime.utcnow().isoformat()
                }, room=match_id)
                
                board = chess.Board(new_fen)
                if board.is_game_over():
                    bot_match = get_bot_match(match_obj_id)
                    handle_bot_game_over(match_id, board, bot_match, socketio)
            
    except Exception as e:
        logger.error(f"[-] Bot move error: {e}")


def handle_bot_game_over(match_id: str, board: chess.Board, bot_match, socketio):
    try:
        result = None
        reason = None
        
        if board.is_checkmate():
            winner_color = 'black' if board.turn == chess.WHITE else 'white'
            if winner_color == bot_match.player_color:
                result = 'player_win'
            else:
                result = 'bot_win'
            reason = 'checkmate'
            
        elif board.is_stalemate():
            result = 'draw'
            reason = 'stalemate'
            
        elif board.is_insufficient_material():
            result = 'draw'
            reason = 'insufficient material'
            
        elif board.is_seventyfive_moves():
            result = 'draw'
            reason = '75-move rule'
            
        elif board.is_fivefold_repetition():
            result = 'draw'
            reason = 'fivefold repetition'
            
        else:
            result = 'draw'
            reason = 'unknown'
        
        match_obj_id = ObjectId(match_id)
        success = end_bot_match(match_obj_id, result)
        
        if success:
            logger.info(f"[+] Bot game ended: {result} by {reason}")
            
            from DB.connect import user_col
            user = user_col.find_one({'_id': bot_match.player_id})
            
            socketio.emit('bot_game_ended', {
                'result': result,
                'reason': reason,
                'player_elo': user.get('elo'),
                'timestamp': datetime.utcnow().isoformat()
            }, room=match_id)
            
            active_bot_matches.pop(match_id, None)
            
    except Exception as e:
        logger.error(f"[-] Bot game over error: {e}")


logger.info("[+] Bot WebSocket events registered")


================================================
FILE: web_socket/pvp.py
================================================
# api/routes/pvp.py
from flask_socketio import emit, join_room, leave_room, disconnect
from flask import request
from bson import ObjectId
from DB.connect import match_col, user_col
from controllers.matchs.match_controller import (
    get_match, 
    append_move_to_pgn,
    end_match,
    resign_match,
    is_valid_player
)
from controllers.users.users_controller import change_user_status
from Models.user_model import UserStatus
from dotenv import load_dotenv, find_dotenv
import logging
import jwt
import os
from datetime import datetime

load_dotenv(find_dotenv())
logger = logging.getLogger(__name__)
SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'linh')

# Store active connections: {user_id: session_id}
active_connections = {}
# Store match rooms: {match_id: {white: user_id, black: user_id}}
match_rooms = {}

def register_socket_events(socketio):
    """Register all WebSocket event handlers"""
    
    # ============ CONNECTION EVENTS ============
    @socketio.on('connect')
    def handle_connect():
        """Handle new WebSocket connection"""
        try:
            # Get user from cookie
            token = request.cookies.get('access_token')
            if not token:
                logger.warning(f"Connection rejected: No token")
                disconnect()
                return False
            
            # Verify JWT
            try:
                payload = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
                user_id = payload.get('user_id')
            except jwt.InvalidTokenError:
                logger.warning(f"Connection rejected: Invalid token")
                disconnect()
                return False
            
            # Store connection
            active_connections[user_id] = request.sid
            
            logger.info(f"Client connected: {request.sid} (User: {user_id})")
            
            emit('connected', {
                'status': 'success',
                'message': 'Connected to game server',
                'session_id': request.sid,
                'timestamp': datetime.utcnow().isoformat()
            })
            
        except Exception as e:
            logger.error(f"Connection error: {e}")
            disconnect()
            return False
    
    @socketio.on('disconnect')
    def handle_disconnect():
        """Handle WebSocket disconnection"""
        try:
            # Find user_id from session
            user_id = None
            for uid, sid in active_connections.items():
                if sid == request.sid:
                    user_id = uid
                    break
            
            if user_id:
                # Remove from active connections
                del active_connections[user_id]
                
                # Notify opponent in any active match
                for match_id, players in match_rooms.items():
                    if user_id in [players.get('white'), players.get('black')]:
                        emit('opponent_disconnected', {
                            'message': 'Your opponent disconnected',
                            'timestamp': datetime.utcnow().isoformat()
                        }, room=match_id, skip_sid=request.sid)
                        
                        # Clean up match room if both disconnected
                        opponent_id = players.get('black') if players.get('white') == user_id else players.get('white')
                        if opponent_id not in active_connections:
                            match_rooms.pop(match_id, None)
                            logger.info(f"🧹 Cleaned up match room: {match_id}")
                
                logger.info(f"🔌 Client disconnected: {request.sid} (User: {user_id})")
            else:
                logger.info(f"🔌 Unknown client disconnected: {request.sid}")
                
        except Exception as e:
            logger.error(f"Disconnect error: {e}")
    
    # ============ MATCH EVENTS ============
    @socketio.on('join_match')
    def handle_join_match(data):
        """Join a match room"""
        try:
            match_id = data.get('match_id')
            user_id = data.get('user_id')
            
            if not match_id or not user_id:
                emit('error', {'message': 'Missing match_id or user_id'})
                return
            
            # Validate match and player
            match_obj_id = ObjectId(match_id)
            user_obj_id = ObjectId(user_id)
            
            is_valid, error_msg = is_valid_player(match_obj_id, user_obj_id)
            if not is_valid:
                emit('error', {'message': error_msg})
                return
            
            # Get match details
            match = get_match(match_obj_id)
            if not match:
                emit('error', {'message': 'Match not found'})
                return
            
            # Join room
            join_room(match_id)
            
            # Store in match_rooms
            if match_id not in match_rooms:
                match_rooms[match_id] = {
                    'white': str(match.white),
                    'black': str(match.black)
                }
            
            # Get player color
            player_color = 'white' if str(match.white) == user_id else 'black'
            
            # Get opponent info
            opponent_id = match.black if str(match.white) == user_id else match.white
            opponent = user_col.find_one({'_id': opponent_id})
            
            opponent_connected = str(opponent_id) in active_connections
            
            logger.info(f"Player {user_id} joined match {match_id} as {player_color}")
            
            # Send match state to joining player
            emit('match_joined', {
                'status': 'success',
                'match_id': match_id,
                'your_color': player_color,
                'pgn': match.pgn,
                'match_status': match.status,
                'opponent': {
                    'id': str(opponent_id),
                    'name': opponent.get('name', 'Unknown') if opponent else 'Unknown',
                    'elo': opponent.get('elo', 1200) if opponent else 1200,
                    'connected': opponent_connected
                },
                'timestamp': datetime.utcnow().isoformat()
            })
            
            # Notify opponent
            emit('opponent_connected', {
                'message': 'Your opponent has joined',
                'opponent_color': player_color,
                'timestamp': datetime.utcnow().isoformat()
            }, room=match_id, skip_sid=request.sid)
            
            # Update user status
            change_user_status(user_obj_id, UserStatus.PLAYING)
            
        except Exception as e:
            logger.error(f"Join match error: {e}")
            emit('error', {'message': 'Failed to join match'})
    
    @socketio.on('leave_match')
    def handle_leave_match(data):
        """Leave a match room"""
        try:
            match_id = data.get('match_id')
            user_id = data.get('user_id')
            
            if not match_id or not user_id:
                return
            
            leave_room(match_id)
            logger.info(f"[+] Player {user_id} left match {match_id}")
            
            # Update user status
            change_user_status(ObjectId(user_id), UserStatus.IDLE)
            
        except Exception as e:
            logger.error(f"Leave match error: {e}")
    
    # ============ GAME EVENTS ============
    @socketio.on('make_move')
    def handle_make_move(data):
        """Handle chess move"""
        try:
            match_id = data.get('match_id')
            move = data.get('move')
            fen = data.get('fen')  # Current board state
            user_id = data.get('user_id')
            
            if not all([match_id, move, user_id]):
                emit('move_error', {'message': 'Missing required data'})
                return
            
            # Validate player
            match_obj_id = ObjectId(match_id)
            user_obj_id = ObjectId(user_id)
            
            is_valid, error_msg = is_valid_player(match_obj_id, user_obj_id)
            if not is_valid:
                emit('move_error', {'message': error_msg})
                return
            
            # Save move to database
            success = append_move_to_pgn(match_obj_id, move)
            
            if success:
                logger.info(f"[+] Move in match {match_id}: {move}")
                
                # Confirm to sender
                emit('move_accepted', {
                    'move': move,
                    'fen': fen,
                    'timestamp': datetime.utcnow().isoformat()
                })
                
                # Broadcast to opponent
                emit('opponent_move', {
                    'move': move,
                    'fen': fen,
                    'timestamp': datetime.utcnow().isoformat()
                }, room=match_id, skip_sid=request.sid)
            else:
                emit('move_error', {'message': 'Failed to save move'})
                
        except Exception as e:
            logger.error(f"Make move error: {e}")
            emit('move_error', {'message': 'Internal error'})
    
    @socketio.on('game_end')
    def handle_game_end(data):
        """Handle game end (checkmate, stalemate, etc)"""
        try:
            match_id = data.get('match_id')
            result = data.get('result')  # 'white_win', 'black_win', 'draw'
            reason = data.get('reason')  # 'checkmate', 'stalemate', 'timeout', etc
            user_id = data.get('user_id')
            
            if not all([match_id, result, user_id]):
                emit('error', {'message': 'Missing required data'})
                return
            
            # Validate
            match_obj_id = ObjectId(match_id)
            is_valid, error_msg = is_valid_player(match_obj_id, ObjectId(user_id))
            if not is_valid:
                emit('error', {'message': error_msg})
                return
            
            # End match in database
            success = end_match(match_obj_id, result)
            
            if success:
                # Get updated match info with ELO changes
                match_data = match_col.find_one({'_id': match_obj_id})
                white_user = user_col.find_one({'_id': match_data['white']})
                black_user = user_col.find_one({'_id': match_data['black']})
                
                logger.info(f"[+] Game ended: {match_id} - Result: {result} - Reason: {reason}")
                
                # Broadcast to both players
                emit('game_ended', {
                    'result': result,
                    'reason': reason,
                    'white': {
                        'name': white_user.get('name'),
                        'elo': white_user.get('elo')
                    },
                    'black': {
                        'name': black_user.get('name'),
                        'elo': black_user.get('elo')
                    },
                    'timestamp': datetime.utcnow().isoformat()
                }, room=match_id)
                
                # Clean up
                match_rooms.pop(match_id, None)
            else:
                emit('error', {'message': 'Failed to end game'})
                
        except Exception as e:
            logger.error(f"Game end error: {e}")
            emit('error', {'message': 'Internal error'})
    
    @socketio.on('resign')
    def handle_resign(data):
        """Handle player resignation"""
        try:
            match_id = data.get('match_id')
            user_id = data.get('user_id')
            
            if not match_id or not user_id:
                emit('error', {'message': 'Missing required data'})
                return
            
            # Validate
            match_obj_id = ObjectId(match_id)
            user_obj_id = ObjectId(user_id)
            
            is_valid, error_msg = is_valid_player(match_obj_id, user_obj_id)
            if not is_valid:
                emit('error', {'message': error_msg})
                return
            
            # Process resignation
            success = resign_match(match_obj_id, user_obj_id)
            
            if success:
                # Get match to determine winner
                match_data = match_col.find_one({'_id': match_obj_id})
                result = match_data.get('status')
                
                logger.info(f"[+] Player {user_id} resigned from match {match_id}")
                
                # Notify both players
                emit('player_resigned', {
                    'resigning_player': user_id,
                    'result': result,
                    'message': 'Player resigned',
                    'timestamp': datetime.utcnow().isoformat()
                }, room=match_id)
                
                # Clean up
                match_rooms.pop(match_id, None)
            else:
                emit('error', {'message': 'Failed to resign'})
                
        except Exception as e:
            logger.error(f"Resign error: {e}")
            emit('error', {'message': 'Internal error'})
    
    # ============ CHAT EVENTS ============
    @socketio.on('chat_message')
    def handle_chat_message(data):
        """Handle in-game chat"""
        try:
            match_id = data.get('match_id')
            user_id = data.get('user_id')
            message = data.get('message', '').strip()
            
            if not all([match_id, user_id, message]):
                return
            
            # Get sender name
            user = user_col.find_one({'_id': ObjectId(user_id)})
            sender_name = user.get('name', 'Unknown') if user else 'Unknown'
            
            logger.info(f"Chat in match {match_id}: {sender_name}: {message}")
            
            # Broadcast to room
            emit('chat_message', {
                'sender_id': user_id,
                'sender_name': sender_name,
                'message': message,
                'timestamp': datetime.utcnow().isoformat()
            }, room=match_id)
            
        except Exception as e:
            logger.error(f"Chat error: {e}")
    
    # ============ DRAW OFFER EVENTS ============
    @socketio.on('offer_draw')
    def handle_offer_draw(data):
        """Handle draw offer"""
        try:
            match_id = data.get('match_id')
            user_id = data.get('user_id')
            
            if not match_id or not user_id:
                return
            
            logger.info(f"Draw offered in match {match_id} by {user_id}")
            
            # Notify opponent
            emit('draw_offered', {
                'offering_player': user_id,
                'message': 'Your opponent offers a draw',
                'timestamp': datetime.utcnow().isoformat()
            }, room=match_id, skip_sid=request.sid)
            
        except Exception as e:
            logger.error(f"Offer draw error: {e}")
    
    @socketio.on('respond_draw')
    def handle_respond_draw(data):
        """Handle draw response"""
        try:
            match_id = data.get('match_id')
            user_id = data.get('user_id')
            accepted = data.get('accepted', False)
            
            if not match_id or not user_id:
                return
            
            if accepted:
                # End game as draw
                match_obj_id = ObjectId(match_id)
                success = end_match(match_obj_id, 'draw')
                
                if success:
                    logger.info(f"Draw accepted in match {match_id}")
                    
                    emit('draw_accepted', {
                        'message': 'Draw accepted',
                        'result': 'draw',
                        'timestamp': datetime.utcnow().isoformat()
                    }, room=match_id)
                    
                    # Clean up
                    match_rooms.pop(match_id, None)
            else:
                logger.info(f"Draw declined in match {match_id}")
                
                emit('draw_declined', {
                    'message': 'Draw offer declined',
                    'timestamp': datetime.utcnow().isoformat()
                }, room=match_id, skip_sid=request.sid)
                
        except Exception as e:
            logger.error(f"Respond draw error: {e}")
    
    # ============ HEARTBEAT ============
    @socketio.on('ping')
    def handle_ping():
        """Handle ping for connection keepalive"""
        emit('pong', {
            'timestamp': datetime.utcnow().isoformat()
        })
    
    logger.info("WebSocket events registered")

