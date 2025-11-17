from datetime import datetime
from bson import ObjectId

# =============== Match ===============
class Match:
    def __init__(self, black: ObjectId, white: ObjectId, pgn: str = "",
                 start: datetime = None, end: datetime = None,
                 status: str = "ongoing", _id: ObjectId = None):
        self._id = _id or ObjectId()
        self.black = black
        self.white = white
        self.pgn = pgn
        self.start = start or datetime.utcnow()
        self.end = end
        self.status = status

    def to_dict(self):
        return {
            "_id": self._id,
            "black": self.black,
            "white": self.white,
            "pgn": self.pgn,
            "start": self.start,
            "end": self.end,
            "status": self.status
        }

    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            black=data["black"],
            white=data["white"],
            pgn=data.get("pgn", ""),
            start=data.get("start"),
            end=data.get("end"),
            status=data.get("status", "ongoing"),
            _id=data.get("_id")
        )

    def __repr__(self):
        return f"Match(black={self.black}, white={self.white}, status={self.status})"
