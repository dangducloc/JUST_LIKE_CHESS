from Models.user_model import User, UserStatus
from DB.connect import user_col,waiting_col, PyMongoError, InsertOneResult
from hashlib import sha256
from bson import ObjectId
from pymongo.errors import DuplicateKeyError
# from threading import Thread


# ================= Add User =================
def add_user(user: User) -> bool:
    try:
        result: InsertOneResult = user_col.insert_one(user.to_dict())
        print(f"✅ User inserted with id: {result.inserted_id}")
        return True
    except DuplicateKeyError:
        print(f"❌ Email {user.mail} is used")
        return False
    except PyMongoError as e:
        print(f"❌ Error inserting user: {e}")
        return False


# ================= Find User =================
def find_user(user_mail: str, user_passwd: str) -> ObjectId | None:
    try:
        hash_pass = sha256(user_passwd.encode()).hexdigest()
        result = user_col.find_one(
            {"mail": user_mail, "pass": hash_pass},
            {"_id": 1}
        )

        if result:
            print(f"[+] Found user: {result}")
            return result["_id"]

        print("[-] User not found.")
        return None

    except PyMongoError as e:
        print(f"❌ Error finding user: {e}")
        return None


# ================= Change User Status =================
def change_user_status(user_id: ObjectId, status: str) -> bool:
    """
    change to one of this (idle, playing, offline).
    """
    if status not in [s.value for s in UserStatus]:
        print(f"❌ Invalid status: {status}")
        return False

    try:
        result = user_col.update_one(
            {"_id": user_id},
            {"$set": {"status": status}}
        )
        if result.matched_count == 0:
            print(f"⚠️ No user found with id {user_id}")
            return False
        print(f"✅ User {user_id} status changed to {status}")
        return True
    except PyMongoError as e:
        print(f"❌ Error updating user status: {e}")
        return False

# ================= Find Opponent =================
def find_opponent(user_id: ObjectId, user_elo: int) -> ObjectId | None:
    try:
        pipeline = [
            {
                "$match": {
                    "user_id": {"$ne": user_id},
                    "elo": {"$gte": user_elo - 50, "$lte": user_elo + 50}
                }
            },
            {
                "$addFields": {
                    "elo_diff": {"$abs": {"$subtract": ["$elo", user_elo]}}
                }
            },
            {
                "$sort": {"elo_diff": 1}
            },
            {"$limit": 1}
        ]

        result = list(waiting_col.aggregate(pipeline))

        if result:
            print(f"[+] Opponent found: {result[0]['user_id']}")
            return result[0]["user_id"]

        print("[-] No idle opponent found.")
        return None

    except PyMongoError as e:
        print(f"❌ Error in find_opponent: {e}")
        return None
