import sqlite3
import bcrypt
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "bharatf1.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def init_db():
    conn = get_db()
    c = conn.cursor()

    c.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE COLLATE NOCASE NOT NULL,
            password_hash TEXT,
            role TEXT NOT NULL DEFAULT 'member',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS polls (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            question TEXT NOT NULL,
            created_by INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS poll_options (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            poll_id INTEGER NOT NULL,
            option_text TEXT NOT NULL,
            FOREIGN KEY (poll_id) REFERENCES polls(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS votes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            poll_id INTEGER NOT NULL,
            option_id INTEGER NOT NULL,
            voted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, poll_id),
            FOREIGN KEY (user_id) REFERENCES users(id),
            FOREIGN KEY (poll_id) REFERENCES polls(id) ON DELETE CASCADE,
            FOREIGN KEY (option_id) REFERENCES poll_options(id) ON DELETE CASCADE
        );
    """)

    # Ensure AhlawatDhruv / Dhruv / @01 is always admin with fresh hash
    pw_hash = bcrypt.hashpw(b"@01", bcrypt.gensalt()).decode()
    admin_users = ["Dhruv", "AhlawatDhruv"]
    for admin_name in admin_users:
        existing = c.execute("SELECT id FROM users WHERE LOWER(username) = LOWER(?)", (admin_name,)).fetchone()
        if not existing:
            c.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (admin_name, pw_hash, "admin")
            )
        else:
            c.execute("UPDATE users SET role = 'admin', password_hash = ? WHERE id = ?", (pw_hash, existing["id"]))

    conn.commit()
    conn.close()
    print("[DB] Initialized. Admin users 'Dhruv' & 'AhlawatDhruv' verified and ready.")

if __name__ == "__main__":
    init_db()
