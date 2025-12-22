from enum import Enum
from bson import ObjectId
from datetime import datetime

class BotDifficulty(str, Enum):
    """Bot difficulty levels"""
    BEGINNER = "beginner"      # ELO: 400-800, Depth: 1-3
    EASY = "easy"              # ELO: 800-1200, Depth: 4-6
    MEDIUM = "medium"          # ELO: 1200-1600, Depth: 7-10
    HARD = "hard"              # ELO: 1600-2000, Depth: 11-15
    EXPERT = "expert"          # ELO: 2000+, Depth: 16-20

class BotMatch:
    """Model for bot matches"""

    def __init__(
        self,
        player_id: ObjectId,
        bot_difficulty: str,
        player_color: str,
        pgn: str = "",
        start: datetime = None,
        end: datetime = None,
        status: str = "ongoing",
        _id: ObjectId = None
    ):
        self._id = _id or ObjectId()
        self.player_id = player_id
        self.bot_difficulty = bot_difficulty
        self.player_color = player_color
        self.pgn = pgn
        self.start = start or datetime.utcnow()
        self.end = end
        self.status = status

        bot_id = self.define_bot_id()

        if player_color == "white":
            self.white = player_id
            self.black = bot_id
        else:
            self.black = player_id
            self.white = bot_id

    def define_bot_id(self) -> ObjectId:
        difficulty = BotDifficulty(self.bot_difficulty)

        bot_map = {
            BotDifficulty.BEGINNER: ObjectId("000000000000000000000000"),
            BotDifficulty.EASY: ObjectId("000000000000000000000001"),
            BotDifficulty.MEDIUM: ObjectId("000000000000000000000002"),
            BotDifficulty.HARD: ObjectId("000000000000000000000003"),
            BotDifficulty.EXPERT: ObjectId("000000000000000000000004"),
        }

        return bot_map[difficulty]

    def to_dict(self):
        return {
            "_id": self._id,
            "player_id": self.player_id,
            "bot_difficulty": self.bot_difficulty,
            "player_color": self.player_color,
            "pgn": self.pgn,
            "start": self.start,
            "end": self.end,
            "status": self.status,
            "white": self.white,
            "black": self.black,
        }


    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            player_id=data["player_id"],
            bot_difficulty=data["bot_difficulty"],
            player_color=data["player_color"],
            pgn=data.get("pgn", ""),
            start=data.get("start"),
            end=data.get("end"),
            # white=data.get("white"),
            # black=data.get("black"),
            status=data.get("status", "ongoing"),
            _id=data.get("_id")
        )

    def __repr__(self):
        return f"BotMatch(player={self.player_id}, difficulty={self.bot_difficulty}, status={self.status})"


class BotProfile:
    """Bot profile with settings"""
    
    DIFFICULTY_SETTINGS = {
        BotDifficulty.BEGINNER: {
            "depth": 2,
            "elo_range": (400, 800),
            "thinking_time": 0.5,
            "error_rate": 0.3
        },
        BotDifficulty.EASY: {
            "depth": 5,
            "elo_range": (800, 1200),
            "thinking_time": 1.0,
            "error_rate": 0.15
        },
        BotDifficulty.MEDIUM: {
            "depth": 8,
            "elo_range": (1200, 1600),
            "thinking_time": 1.5,
            "error_rate": 0.05
        },
        BotDifficulty.HARD: {
            "depth": 12,
            "elo_range": (1600, 2000),
            "thinking_time": 2.0,
            "error_rate": 0.02
        },
        BotDifficulty.EXPERT: {
            "depth": 16,
            "elo_range": (2000, 2400),
            "thinking_time": 3.0,
            "error_rate": 0.0
        }
    }
    
    @classmethod
    def get_settings(cls, difficulty: str) -> dict:
        """Get bot settings for difficulty level"""
        return cls.DIFFICULTY_SETTINGS.get(
            BotDifficulty(difficulty),
            cls.DIFFICULTY_SETTINGS[BotDifficulty.MEDIUM]
        )
    
    @classmethod
    def get_bot_name(cls, difficulty: str) -> str:
        """Get bot display name"""
        names = {
            BotDifficulty.BEGINNER: "ChessBot Junior",
            BotDifficulty.EASY: "ChessBot Novice",
            BotDifficulty.MEDIUM: "ChessBot Standard",
            BotDifficulty.HARD: "ChessBot Pro",
            BotDifficulty.EXPERT: "ChessBot Master"
        }
        return names.get(BotDifficulty(difficulty), "ChessBot")
    
    @classmethod
    def get_bot_elo(cls, difficulty: str) -> int:
        """Get average bot ELO for difficulty"""
        settings = cls.get_settings(difficulty)
        elo_range = settings["elo_range"]
        return (elo_range[0] + elo_range[1]) // 2