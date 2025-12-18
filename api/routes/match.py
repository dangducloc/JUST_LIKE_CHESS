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
import jwt
import os
import logging

match_bp = Blueprint('match', __name__)
logger = logging.getLogger(__name__)
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