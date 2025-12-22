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
    