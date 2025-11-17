from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import PyMongoError
from pymongo.results import InsertOneResult,InsertManyResult
import os
from dotenv import load_dotenv, find_dotenv

# Load .env file
load_dotenv(find_dotenv())

# Get config
USER = os.getenv("USER")
PASS = os.getenv("PASS")
HOST = os.getenv("HOST")
PORT = os.getenv("PORT")
DB   = os.getenv("DB")

print(USER, PASS, HOST, PORT, DB)

if USER and PASS:
    uri = f"mongodb://{USER}:{PASS}@{HOST}:{PORT}/{DB}?authSource=admin"
else:
    uri = f"mongodb://{HOST}:{PORT}/{DB}"

try:
    client: MongoClient = MongoClient(uri, serverSelectionTimeoutMS=5000)
    client.admin.command("ping")
    print("✅ Connected to MongoDB")

    db: Database = client[DB]
    user_col: Collection = db["user"]
    match_col: Collection = db["match"]
    pending_col: Collection = db["pending"] #for register confirmation
    waiting_col: Collection = db["waiting"] #for matching queue
    
    user_col.create_index("mail", unique=True)

except PyMongoError as e:
    print(f"❌ MongoDB connection failed: {e}")
    client = None
    db = None
    user_col = None
    match_col = None
