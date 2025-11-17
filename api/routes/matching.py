import secrets
from flask import Blueprint, request, jsonify, make_response, Response
from Models.user_model import User, UserStatus
from controllers.users.users_controller import change_user_status,find_opponent
from bson import ObjectId
from DB.connect import user_col,waiting_col

matching_bp: Blueprint = Blueprint('matching', __name__)
user_status: UserStatus = UserStatus
# ========== FIND MATCH ==========
@matching_bp.route('/find_match', methods=['POST'])
def matching() -> Response:
    id_user: str | None = request.cookies.get('user_id')
    user_elo = user_col.find_one({"_id": ObjectId(id_user)}).get("elo") if id_user else None
    waiting_col.insert_one({"user_id": ObjectId(id_user), "elo": user_elo})
    

    opponent_id:ObjectId = find_opponent(user_elo)
    if opponent_id:
        # change_user_status(user_id=ObjectId(id_user), status=user_status.PLAYING)
        return jsonify({"Opponent Found":str(opponent_id)}),200
    if not id_user:
        return jsonify({"message": "User not logged in"}), 401
    # how to matchin 2 user together is out of scope now
    

