// ================= USER =================
db.createCollection("user", {
  validator: {
    $jsonSchema: {
      bsonType: "object",
      title: "user",
      required: ["_id", "name", "pass", "mail", "elo", "status"],
      properties: {
        _id: { bsonType: "objectId" },
        name: { bsonType: "string" },
        pass: { bsonType: "string" },   // hashed password
        mail: {
          bsonType: "string",
          description: "Must be a valid email"
        },
        elo: {
          bsonType: "int",
          minimum: 0,
          description: "ELO rating (default 400)"
        },
        status: {
          enum: ["idle", "playing", "offline"],
          description: "User status"
        }
      }
    }
  },
  validationLevel: "strict",
  validationAction: "error"
});

// Unique index cho email
db.user.createIndex({ mail: 1 }, { unique: true });


// ================= MATCH =================
db.createCollection("match", {
  validator: {
    $jsonSchema: {
      bsonType: "object",
      title: "match",
      required: ["_id", "black", "white", "status", "start"],
      properties: {
        _id: { bsonType: "objectId" },
        black: { bsonType: "objectId" },
        white: { bsonType: "objectId" },
        pgn: { bsonType: "string" },
        start: { bsonType: "date" },
        end: { bsonType: ["date", "null"] },
        status: {
          enum: ["ongoing", "white_win", "black_win", "draw"],
          description: "Current status of the match"
        }
      }
    }
  },
  validationLevel: "strict",
  validationAction: "error"
});


db.createCollection("pending_user", {
  validator: {
    $jsonSchema: {
      bsonType: "object",
      title: "pending_user",
      required: ["_id", "name", "mail", "pass", "token", "expireAt"],
      properties: {
        _id: { bsonType: "objectId" },
        name: { bsonType: "string" },
        mail: { bsonType: "string" },
        pass: { bsonType: "string" }, // hashed password
        token: { bsonType: "string" }, // random confirm token
        expireAt: { bsonType: "date" } // TTL index để tự xoá khi quá hạn
      }
    }
  }
});

db.pending_user.createIndex({ expireAt: 1 }, { expireAfterSeconds: 0 })
