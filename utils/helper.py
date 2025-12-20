# utils/helper.py
from flask import request
import jwt
from bson import ObjectId
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
