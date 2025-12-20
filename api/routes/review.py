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