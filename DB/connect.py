# DB/connect.py 
from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import PyMongoError, ConnectionFailure
from pymongo.results import InsertOneResult, InsertManyResult
import os
from dotenv import load_dotenv, find_dotenv
import logging

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv(find_dotenv())

# Configuration
class DBConfig:
    USER = os.getenv("USER")
    PASS = os.getenv("PASS")
    HOST = os.getenv("HOST", "localhost")
    PORT = os.getenv("PORT", "27017")
    DB_NAME = os.getenv("DB", "chess_db")
    
    @classmethod
    def get_uri(cls):
        if cls.USER and cls.PASS:
            return f"mongodb://{cls.USER}:{cls.PASS}@{cls.HOST}:{cls.PORT}/{cls.DB_NAME}?authSource=admin"
        return f"mongodb://{cls.HOST}:{cls.PORT}/{cls.DB_NAME}"

# ============ DATABASE CONNECTION ============
class Database:
    _instance = None
    _client = None
    _db = None
    
    def __new__(cls):
        """Singleton pattern for database connection"""
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance
    
    def __init__(self):
        if self._client is None:
            self.connect()
    
    def connect(self):
        """Establish database connection"""
        try:
            uri = DBConfig.get_uri()
            self._client = MongoClient(
                uri,
                serverSelectionTimeoutMS=5000,
                connectTimeoutMS=10000,
                socketTimeoutMS=10000,
                maxPoolSize=50,
                minPoolSize=10
            )
            
            # Verify connection
            self._client.admin.command("ping")
            logger.info("✅ Connected to MongoDB")
            
            # Get database
            self._db = self._client[DBConfig.DB_NAME]
            
            # Setup collections
            self._setup_collections()
            
        except ConnectionFailure as e:
            logger.error(f"❌ MongoDB connection failed: {e}")
            raise
        except PyMongoError as e:
            logger.error(f"❌ MongoDB error: {e}")
            raise
    
    def _setup_collections(self):
        """Setup collections with indexes"""
        try:
            # User collection
            self.user_col.create_index("mail", unique=True)
            self.user_col.create_index("status")
            self.user_col.create_index("elo")
            
            # Match collection
            self.match_col.create_index([("white", 1), ("black", 1)])
            self.match_col.create_index("status")
            self.match_col.create_index("start")
            
            # Pending users (TTL index)
            self.pending_col.create_index(
                "expireAt",
                expireAfterSeconds=0
            )
            
            # Waiting queue
            self.waiting_col.create_index("elo")
            self.waiting_col.create_index("created_at")
            
            logger.info("✅ Database indexes created")
            
        except PyMongoError as e:
            logger.warning(f"⚠️ Index creation warning: {e}")
    
    @property
    def client(self) -> MongoClient:
        return self._client
    
    @property
    def db(self) -> Database:
        return self._db
    
    @property
    def user_col(self) -> Collection:
        return self._db["user"]
    
    @property
    def match_col(self) -> Collection:
        return self._db["match"]
    
    @property
    def pending_col(self) -> Collection:
        return self._db["pending"]
    
    @property
    def waiting_col(self) -> Collection:
        return self._db["waiting"]
    
    def close(self):
        """Close database connection"""
        if self._client:
            self._client.close()
            logger.info("🔌 MongoDB connection closed")

# ============ SINGLETON INSTANCE ============
db_instance = Database()

# Export collections for backward compatibility
user_col = db_instance.user_col
match_col = db_instance.match_col
pending_col = db_instance.pending_col
waiting_col = db_instance.waiting_col

# Export for new usage
__all__ = [
    'Database',
    'db_instance',
    'user_col',
    'match_col',
    'pending_col',
    'waiting_col',
    'PyMongoError',
    'InsertOneResult',
    'InsertManyResult'
]