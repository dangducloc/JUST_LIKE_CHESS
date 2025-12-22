# utils/helper.py
from flask import request
import jwt
from bson import ObjectId
from Models.user_model import User
import logging
import os
from dotenv import load_dotenv, find_dotenv
# Load environment variables
load_dotenv(find_dotenv())


logger = logging.getLogger(__name__)

#  ============ HELPER FUNCTION ============
def get_user_from_token():
    """Extract user_id from JWT token"""
    SECRET_KEY = os.getenv('JWT_SECRET_KEY', 'linh')
    access_token = request.cookies.get('access_token')
    
    if not access_token:
        return None, {"message": "Not authenticated"}, 401
    
    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=['HS256'])
        user_id = ObjectId(payload.get('user_id'))
        return user_id, None, None
    except jwt.ExpiredSignatureError:
        return None, {"message": "Token expired"}, 401
    except jwt.InvalidTokenError:
        return None, {"message": "Invalid token"}, 401
    except Exception as e:
        logger.error(f"Token decode error: {e}")
        return None, {"message": "Authentication error"}, 401
    

def bot_initial_setup():
    bots = [
        User(
            _id=ObjectId("000000000000000000000000"),
            name="ChessBot Junior",
            mail="bot_junior@system.com",
            passwd="!",
            elo=600,
            status="idle",
            is_bot=True,
        ),
        User(
            _id=ObjectId("000000000000000000000001"),
            name="ChessBot Hard",
            mail="bot_hard@system.com",
            passwd="!",
            elo=1000,
            status="idle",
            is_bot=True,
        ),
        User(
            _id=ObjectId("000000000000000000000002"),
            name="ChessBot Super",
            mail="bot_super@system.com",
            passwd="!",
            elo=1400,
            status="idle",
            is_bot=True,
        ),
        User(
            _id=ObjectId("000000000000000000000003"),
            name="ChessBot Master",
            mail="bot_master@system.com",
            passwd="!",
            elo=1800,
            status="idle",
            is_bot=True,
        ),
        User(
            _id=ObjectId("000000000000000000000004"),
            name="ChessBot Godlike",
            mail="bot_god@system.com",
            passwd="!",
            elo=2200,
            status="idle",
            is_bot=True,
        ),
    ]

    from DB.connect import user_col

    existing_ids = {
        u["_id"] for u in user_col.find(
            {"_id": {"$in": [b._id for b in bots]}},
            {"_id": 1}
        )
    }

    new_bots = [b.to_dict() for b in bots if b._id not in existing_ids]

    if new_bots:
        user_col.insert_many(new_bots)
