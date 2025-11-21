from flask import Blueprint, request, jsonify, make_response, Response
from flask_socketio import emit, join_room, leave_room
from Models.user_model import User, UserStatus
from controllers.users.users_controller import change_user_status, find_opponent
from bson import ObjectId
from DB.connect import user_col, waiting_col
import secrets

matching_bp: Blueprint = Blueprint('matching', __name__)
user_status: UserStatus = UserStatus

# ========== FIND MATCH ==========
@matching_bp.route('/find_match', methods=['POST'])
def matching() -> Response:
    id_user = request.cookies.get('user_id')
    if not id_user:
        return jsonify({"message": "User not logged in"}), 401

    uid = ObjectId(id_user)
    user_doc = user_col.find_one({"_id": uid})
    if not user_doc:
        return jsonify({"message": "User not found"}), 404

    # must be idle to enter queue
    if user_doc["status"] != UserStatus.IDLE.value:
        return jsonify({"message": "User not idle"}), 409

    user_elo = user_doc.get("elo", 0)

    # Check if user is already in waiting queue
    existing_wait = waiting_col.find_one({"user_id": uid})
    if existing_wait:
        # User is already waiting, check if we can find an opponent now
        opponent_id = find_opponent(uid, user_elo)
        if opponent_id:
            # update status
            change_user_status(uid, UserStatus.PLAYING.value)
            change_user_status(opponent_id, UserStatus.PLAYING.value)

            # remove both from queue
            waiting_col.delete_many({
                "user_id": {"$in": [uid, opponent_id]}
            })

            return jsonify({
                "message": "Match found",
                "opponent_id": str(opponent_id)
            }), 200
        else:
            return jsonify({"message": "Still waiting"}), 202

    # insert queue
    waiting_col.insert_one({"user_id": uid, "elo": user_elo})

    # Try to find opponent immediately
    opponent_id = find_opponent(uid, user_elo)
    if opponent_id:
        # update status
        change_user_status(uid, UserStatus.PLAYING.value)
        change_user_status(opponent_id, UserStatus.PLAYING.value)

        # remove both from queue
        waiting_col.delete_many({
            "user_id": {"$in": [uid, opponent_id]}
        })

        return jsonify({
            "message": "Match found",
            "opponent_id": str(opponent_id)
        }), 200

    return jsonify({"message": "No opponent found, please wait"}), 202

# WebSocket events for matching
def init_socket_events(socketio):
    @socketio.on('join_queue')
    def handle_join_queue(data):
        user_id = data.get('user_id')
        if not user_id:
            emit('error', {'message': 'User not logged in'})
            return

        uid = ObjectId(user_id)
        user_doc = user_col.find_one({"_id": uid})
        if not user_doc:
            emit('error', {'message': 'User not found'})
            return

        if user_doc["status"] != UserStatus.IDLE.value:
            emit('error', {'message': 'User not idle'})
            return

        user_elo = user_doc.get("elo", 0)

        # Check if already in queue
        existing_wait = waiting_col.find_one({"user_id": uid})
        if existing_wait:
            emit('waiting', {'message': 'Already in queue'})
            return

        # Join queue
        waiting_col.insert_one({"user_id": uid, "elo": user_elo})
        join_room(str(uid))  # Join user's room for private messages

        # Try to find opponent
        opponent_id = find_opponent(uid, user_elo)
        if opponent_id:
            # Update status
            change_user_status(uid, UserStatus.PLAYING.value)
            change_user_status(opponent_id, UserStatus.PLAYING.value)

            # Remove from queue
            waiting_col.delete_many({"user_id": {"$in": [uid, opponent_id]}})

            # Notify both users
            emit('match_found', {'opponent_id': str(opponent_id)}, room=str(uid))
            emit('match_found', {'opponent_id': str(uid)}, room=str(opponent_id))
        else:
            emit('waiting', {'message': 'Waiting for opponent'})

    @socketio.on('leave_queue')
    def handle_leave_queue(data):
        user_id = data.get('user_id')
        if not user_id:
            return

        uid = ObjectId(user_id)
        waiting_col.delete_one({"user_id": uid})
        leave_room(str(uid))
        emit('left_queue', {'message': 'Left the queue'})
