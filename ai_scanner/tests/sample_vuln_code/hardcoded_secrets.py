# Insecure hardcoded API token and admin password
DB_PASSWORD = "SuperSecretPassword2026!"
AWS_SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"

def connect_db():
    print(f"Connecting with password: {DB_PASSWORD}")
