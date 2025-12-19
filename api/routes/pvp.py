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
import logging
import jwt
import os
from datetime import datetime

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
                
                logger.info(f"🏁 Game ended: {match_id} - Result: {result} - Reason: {reason}")
                
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
                
                logger.info(f"🏳️ Player {user_id} resigned from match {match_id}")
                
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