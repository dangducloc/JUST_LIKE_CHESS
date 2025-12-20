# api/route/review.py

from flask import Blueprint, jsonify, request
from bson import ObjectId
from controllers.review.review_controller import review_game
import logging
logger = logging.getLogger(__name__)

review_bp = Blueprint('review', __name__, url_prefix='/api/review')
@review_bp.route('/<match_id>', methods=['GET'])
def review_match(match_id):
    try:
        id = ObjectId(match_id)
    except Exception as e:
        logger.error(f"[-] Invalid match ID: {match_id}, error: {e}")
        return jsonify({"error": "Invalid match ID"}), 400

    analysis = review_game(id)
    if analysis is None:
        return jsonify({"error": "Match not found or analysis failed"}), 404

    return analysis, 200