import secrets
from app import create_app

app = create_app()
app.secret_key = secrets.token_hex(16)

if __name__ == "__main__":
    app.run(debug=False,port=5003)