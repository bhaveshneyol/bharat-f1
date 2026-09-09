from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import sqlite3, bcrypt, jwt, datetime, os, functools

from database import init_db, get_db

app = Flask(__name__, static_folder="static", static_url_path="")
CORS(app)

SECRET_KEY = "bharatf1_secret_key_2024_dhruv_ahlawat"

# --- JWT HELPERS --------------------------------------------------------------

def make_token(user_id, username, role):
    payload = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=7)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def decode_token(token):
    return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])

def require_auth(roles=None):
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            auth_header = request.headers.get("Authorization", "")
            if not auth_header.startswith("Bearer "):
                return jsonify({"error": "Unauthorized"}), 401
            token = auth_header.split(" ")[1]
            try:
                payload = decode_token(token)
            except jwt.ExpiredSignatureError:
                return jsonify({"error": "Token expired"}), 401
            except jwt.InvalidTokenError:
                return jsonify({"error": "Invalid token"}), 401
            if roles and payload["role"] not in roles:
                return jsonify({"error": "Forbidden: Admin privileges required"}), 403
            request.user = payload
            return f(*args, **kwargs)
        return wrapper
    return decorator

# --- AUTH ROUTES --------------------------------------------------------------

@app.route("/api/auth/signup", methods=["POST"])
def signup():
    data = request.json or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    if len(password) < 4:
        return jsonify({"error": "Password must be at least 4 characters"}), 400
    if username.lower() in ["dhruv", "ahlawatdhruv", "admin", "administrator", "guest"]:
        return jsonify({"error": "This username is reserved"}), 400

    pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'member')",
            (username, pw_hash)
        )
        db.commit()
        user = db.execute("SELECT * FROM users WHERE LOWER(username) = LOWER(?)", (username,)).fetchone()
        token = make_token(user["id"], user["username"], user["role"])
        return jsonify({"token": token, "username": user["username"], "role": user["role"]})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already taken"}), 409
    finally:
        db.close()

@app.route("/api/auth/login", methods=["POST"])
def login():
    data = request.json or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    db = get_db()
    # Support admin alias matching (Dhruv / AhlawatDhruv / admin / administrator)
    if username.lower() in ["dhruv", "ahlawatdhruv", "admin", "administrator"]:
        user = db.execute("SELECT * FROM users WHERE LOWER(username) IN ('dhruv', 'ahlawatdhruv')").fetchone()
    else:
        user = db.execute("SELECT * FROM users WHERE LOWER(username) = LOWER(?)", (username,)).fetchone()
    db.close()

    if not user or not bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
        return jsonify({"error": "Invalid username or password"}), 401

    token = make_token(user["id"], user["username"], user["role"])
    return jsonify({"token": token, "username": user["username"], "role": user["role"]})

@app.route("/api/auth/admin-login", methods=["POST"])
def admin_login():
    data = request.json or {}
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    if not username or not password:
        return jsonify({"error": "Administrator username and password required"}), 400

    db = get_db()
    # If using admin aliases, check Dhruv / AhlawatDhruv
    if username.lower() in ["dhruv", "ahlawatdhruv", "admin", "administrator"]:
        user = db.execute("SELECT * FROM users WHERE LOWER(username) IN ('dhruv', 'ahlawatdhruv')").fetchone()
    else:
        user = db.execute("SELECT * FROM users WHERE LOWER(username) = LOWER(?)", (username,)).fetchone()
    db.close()

    if not user or not bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
        return jsonify({"error": "Invalid administrator credentials"}), 401

    if user["role"] != "admin":
        return jsonify({"error": "This account does not have administrator privileges"}), 403

    token = make_token(user["id"], user["username"], user["role"])
    return jsonify({"token": token, "username": user["username"], "role": "admin"})

@app.route("/api/auth/guest", methods=["POST"])
def guest():
    payload = {
        "user_id": None,
        "username": "Guest",
        "role": "guest",
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=6)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return jsonify({"token": token, "username": "Guest", "role": "guest"})

# --- POLL ROUTES --------------------------------------------------------------

@app.route("/api/polls", methods=["GET"])
@require_auth()
def get_polls():
    db = get_db()
    polls = db.execute("SELECT * FROM polls ORDER BY created_at DESC").fetchall()
    result = []
    for poll in polls:
        options = db.execute(
            "SELECT po.id, po.option_text, COUNT(v.id) as votes "
            "FROM poll_options po LEFT JOIN votes v ON v.option_id = po.id "
            "WHERE po.poll_id = ? GROUP BY po.id", (poll["id"],)
        ).fetchall()
        user_vote = None
        if request.user.get("user_id"):
            vote = db.execute(
                "SELECT option_id FROM votes WHERE user_id = ? AND poll_id = ?",
                (request.user["user_id"], poll["id"])
            ).fetchone()
            if vote:
                user_vote = vote["option_id"]
        result.append({
            "id": poll["id"],
            "question": poll["question"],
            "created_at": poll["created_at"],
            "options": [{"id": o["id"], "text": o["option_text"], "votes": o["votes"]} for o in options],
            "user_vote": user_vote
        })
    db.close()
    return jsonify(result)

@app.route("/api/polls", methods=["POST"])
@require_auth(roles=["admin"])
def create_poll():
    data = request.json or {}
    question = (data.get("question") or "").strip()
    options = [o.strip() for o in (data.get("options") or []) if o.strip()]
    if not question:
        return jsonify({"error": "Question required"}), 400
    if len(options) < 2:
        return jsonify({"error": "At least 2 options required"}), 400
    db = get_db()
    cur = db.execute(
        "INSERT INTO polls (question, created_by) VALUES (?, ?)",
        (question, request.user["user_id"])
    )
    poll_id = cur.lastrowid
    for opt in options:
        db.execute("INSERT INTO poll_options (poll_id, option_text) VALUES (?, ?)", (poll_id, opt))
    db.commit()
    db.close()
    return jsonify({"message": "Poll created", "poll_id": poll_id}), 201

@app.route("/api/polls/<int:poll_id>", methods=["DELETE"])
@require_auth(roles=["admin"])
def delete_poll(poll_id):
    db = get_db()
    db.execute("DELETE FROM polls WHERE id = ?", (poll_id,))
    db.commit()
    db.close()
    return jsonify({"message": "Poll deleted"})

@app.route("/api/polls/<int:poll_id>/vote", methods=["POST"])
@require_auth(roles=["member", "admin"])
def vote(poll_id):
    data = request.json or {}
    option_id = data.get("option_id")
    if not option_id:
        return jsonify({"error": "Option required"}), 400
    db = get_db()
    existing = db.execute(
        "SELECT id FROM votes WHERE user_id = ? AND poll_id = ?",
        (request.user["user_id"], poll_id)
    ).fetchone()
    if existing:
        db.close()
        return jsonify({"error": "Already voted in this poll"}), 409
    valid_option = db.execute(
        "SELECT id FROM poll_options WHERE id = ? AND poll_id = ?",
        (option_id, poll_id)
    ).fetchone()
    if not valid_option:
        db.close()
        return jsonify({"error": "Invalid option"}), 400
    db.execute(
        "INSERT INTO votes (user_id, poll_id, option_id) VALUES (?, ?, ?)",
        (request.user["user_id"], poll_id, option_id)
    )
    db.commit()
    db.close()
    return jsonify({"message": "Vote recorded"})

# --- ADMIN ROUTES -------------------------------------------------------------

@app.route("/api/admin/users", methods=["GET"])
@require_auth(roles=["admin"])
def list_users():
    db = get_db()
    users = db.execute(
        "SELECT id, username, role, created_at FROM users ORDER BY created_at ASC"
    ).fetchall()
    db.close()
    return jsonify([dict(u) for u in users])

@app.route("/api/admin/users/<int:user_id>/promote", methods=["POST"])
@require_auth(roles=["admin"])
def promote_user(user_id):
    db = get_db()
    user = db.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        db.close()
        return jsonify({"error": "User not found"}), 404
    db.execute("UPDATE users SET role = 'admin' WHERE id = ?", (user_id,))
    db.commit()
    db.close()
    return jsonify({"message": f"{user['username']} promoted to Administrator"})

@app.route("/api/admin/users/<int:user_id>/demote", methods=["POST"])
@require_auth(roles=["admin"])
def demote_user(user_id):
    db = get_db()
    user = db.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        db.close()
        return jsonify({"error": "User not found"}), 404
    if user["username"].lower() in ["dhruv", "ahlawatdhruv"]:
        db.close()
        return jsonify({"error": "Cannot demote root administrator Dhruv / AhlawatDhruv"}), 403
    db.execute("UPDATE users SET role = 'member' WHERE id = ?", (user_id,))
    db.commit()
    db.close()
    return jsonify({"message": f"{user['username']} demoted to Member"})

# --- SERVE FRONTEND -----------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory("static", "index.html")

# --- MAIN ---------------------------------------------------------------------

if __name__ == "__main__":
    init_db()
    print("[SERVER] Bharat F1 running:")
    print("  👉 http://127.0.0.1:5000 (Direct IPv4 - Recommended)")
    print("  👉 http://localhost:5000")
    app.run(debug=True, host="0.0.0.0", port=5000)
