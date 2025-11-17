from bson import ObjectId
from hashlib import sha256
from enum import Enum
import re


# =============== User ===============
class UserStatus(str, Enum):
    IDLE :str = "idle"
    PLAYING:str = "playing"
    OFFLINE:str = "offline"
    MATCHING:str = "matching"


class User:
    def __init__(self, name: str, passwd: str, mail: str,
                 elo: int = 400, status: UserStatus = UserStatus.OFFLINE,
                 _id: ObjectId = None, hashed: bool = False):

        self._id = _id or ObjectId()
        self.name = name
        self.passwd = passwd if hashed else sha256(passwd.encode()).hexdigest()
        self.mail = mail
        self.elo = elo
        self.status = status

        if not self.mail_valid():
            raise ValueError(f"Invalid email: {mail}")

    def mail_valid(self) -> bool:
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return re.match(pattern, self.mail) is not None

    def check_password(self, raw_passwd: str) -> bool:
        return self.passwd == sha256(raw_passwd.encode()).hexdigest()

    def update_elo(self, opponent_elo: int, result: float, k: int = 32):
        expected = 1 / (1 + 10 ** ((opponent_elo - self.elo) / 400))
        self.elo += int(k * (result - expected))

    def to_dict(self):
        return {
            "_id": self._id,
            "name": self.name,
            "pass": self.passwd,
            "mail": self.mail,
            "elo": self.elo,
            "status": self.status.value
        }

    @classmethod
    def from_dict(cls, data: dict):
        return cls(
            name=data["name"],
            passwd=data["pass"],
            mail=data["mail"],
            elo=data.get("elo", 1200),
            status=UserStatus(data.get("status", "idle")),
            _id=data.get("_id"),
            hashed=True
        )

    def __repr__(self):
        return f"User(name={self.name!r}, elo={self.elo}, status={self.status.value!r})"


