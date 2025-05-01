import sqlite3
import bcrypt

def init_db():
    conn = sqlite3.connect("bank.db")
    cursor = conn.cursor()
    
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                      id INTEGER PRIMARY KEY AUTOINCREMENT,
                      username TEXT UNIQUE NOT NULL,
                      password_hash TEXT NOT NULL,
                      email TEXT UNIQUE NOT NULL,
                      otp_secret TEXT NOT NULL,
                      balance REAL DEFAULT 0.0)''')

    conn.commit()
    conn.close()
    print("Database initialized successfully.")

if __name__ == "__main__":
    init_db()
