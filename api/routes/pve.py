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