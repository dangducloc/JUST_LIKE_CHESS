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