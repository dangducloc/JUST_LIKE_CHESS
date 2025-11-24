# DB/connect.py
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import PyMongoError
from pymongo.results import InsertOneResult,InsertManyResult
from typing import Optional
import os
from dotenv import load_dotenv, find_dotenv
import logging

# ==================== LOAD ENV ====================
_ = load_dotenv(find_dotenv())

# ==================== LOGGING ====================
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("MongoDB")

# ==================== CONFIG ====================
USER = os.getenv("USER")
PASS = os.getenv("PASS")
HOST = os.getenv("HOST", "localhost")
PORT = os.getenv("PORT", "27017")
DB   = os.getenv("DB", "chess")
AUTH_SOURCE = os.getenv("AUTH_SOURCE", "admin")

# ==================== BUILD URI ====================
if USER and PASS:
    uri = f"mongodb://{USER}:{PASS}@{HOST}:{PORT}/{DB}?authSource={AUTH_SOURCE}"
else:
    uri = f"mongodb://{HOST}:{PORT}"

# ==================== GLOBAL VARIABLES====================
client: Optional[MongoClient] = None
db: Optional[Database] = None

user_col: Optional[Collection]    = None
match_col: Optional[Collection]   = None
pending_col: Optional[Collection] = None
waiting_col: Optional[Collection] = None

# ==================== CONNECT & INITIALIZE ====================
try:
    client = MongoClient(
        uri,
        serverSelectionTimeoutMS=5000,
        connectTimeoutMS=10000,
        socketTimeoutMS=10000,
        maxPoolSize=50,
        retryWrites=True,
        w="majority",
        tz_aware=True,
        uuidRepresentation="standard"
    )
    client.admin.command("ping")
    logger.info("Connected to MongoDB successfully!")

    # variables assignment
    db = client[DB]
    user_col    = db["user"]
    match_col   = db["match"]
    pending_col = db["pending"]
    waiting_col = db["waiting"]

except PyMongoError as e:
    logger.error(f"MongoDB connection failed: {e}")
    client = db = user_col = match_col = pending_col = waiting_col = None

# ==================== ENSURE INDEXES (chỉ chạy nếu db tồn tại) ====================
if db is not None:  # oke
    try:
        # 1. User email unique
        user_col.create_index("mail", unique=True, name="mail_unique")

        # 2. Pending – TTL + unique token
        # drop old TTL indexes if any
        for idx in list(pending_col.list_indexes()):
            if idx.get("key", {}).get("expireAt") == 1 and idx["name"] != "pending_ttl_index":
                pending_col.drop_index(idx["name"])
                logger.info(f"Dropped old TTL index: {idx['name']}")

        pending_col.create_index("expireAt", expireAfterSeconds=0, name="pending_ttl_index")
        pending_col.create_index("token", unique=True, name="token_unique")

        # 3. Waiting queue 
        waiting_col.create_index([("status", 1), ("elo", 1)], name="status_elo_compound")

        logger.info("All indexes created/ensured successfully!")

    except Exception as e:
        logger.warning(f"Some indexes may already exist or failed (safe to ignore): {e}")
else:
    logger.error("Database connection failed → indexes were NOT created")

# ==================== EXPORT ====================
__all__ = [
    "client", "db",
    "user_col", "match_col", "pending_col", "waiting_col"
]