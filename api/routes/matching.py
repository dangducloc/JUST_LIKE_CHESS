# api/routes/matching.py
from flask import Blueprint, request, jsonify, Response
from Models.user_model import User, UserStatus
from Models.match_model import Match
from controllers.users.users_controller import change_user_status
from controllers.matchs.match_controller import create_match
from bson import ObjectId
from DB.connect import user_col, waiting_col, match_col
from datetime import datetime, timedelta
import logging
import jwt
import os

matching_bp = Blueprint('matching', __name__)
logger = logging.getLogger(__name__)

# JWT Secret from environment
SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'linh')

# ============ HELPER FUNCTION ============
def get_user_from_token():
    """Extract user_id from JWT token"""
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
            
            return jsonify({
                "status": "matched",
                "match_id": str(match['_id']),
                "opponent": {
                    "id": str(opponent_id),
                    "name": opponent.get("name", "Unknown"),
                    "elo": opponent.get("elo", 1200)
                },
                "your_color": "white" if match['white'] == user_id else "black"
            }), 200
        
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