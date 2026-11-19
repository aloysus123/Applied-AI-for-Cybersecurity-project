import sqlite3

def get_user_records(username):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # SQL Injection via unparameterized string formatting
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()
