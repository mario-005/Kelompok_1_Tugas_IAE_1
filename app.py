from flask import Flask, jsonify, request
import jwt, datetime, os
from functools import wraps
from dotenv import load_dotenv

load_dotenv()
app = Flask(__name__)
SECRET = os.getenv("JWT_SECRET", "secret123")

USERS = {"mario@example.com": {"password": "pass123", "name": "Mario Ke 1"}}

def create_token(email):
    return jwt.encode({
        "sub": email, "email": email,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=15)
    }, SECRET, algorithm="HS256")

def token_required(f):
    @wraps(f)
    def wrapper(*a, **kw):
        header = request.headers.get("Authorization")
        if not header or not header.startswith("Bearer "):
            return jsonify({"error": "Missing or invalid Authorization header"}), 401
        try:
            data = jwt.decode(header.split()[1], SECRET, algorithms=["HS256"])
            request.user_email = data["email"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Invalid token"}), 401
        return f(*a, **kw)
    return wrapper

@app.route("/auth/login", methods=["POST"])
def login():
    d = request.get_json()
    u = USERS.get(d.get("email"))
    if not u or u["password"] != d.get("password"):
        return jsonify({"error": "Invalid credentials"}), 401
    return jsonify({"access_token": create_token(d["email"])})

@app.route("/items")
def items():
    return jsonify({"items": [
        {"id": 1, "name": "Laptop", "price": 12000000},
        {"id": 2, "name": "Headphone", "price": 350000},
        {"id": 3, "name": "Keyboard", "price": 250000},
        {"id": 5, "name": "Speaker", "price": 50000},
        {"id": 6, "name": "Mouse", "price": 25000}
    ]})

@app.route("/profile", methods=["PUT"])
@token_required
def profile():
    email = request.user_email
    d = request.get_json()
    u = USERS.get(email)
    if not u:
        return jsonify({"error": "User not found"}), 404
    if d.get("name"):
        u["name"] = d["name"]
    if d.get("email"):
        USERS[d["email"]] = USERS.pop(email)
        email = d["email"]
    return jsonify({
        "message": "Profile updated",
        "profile": {"name": u["name"], "email": email}
    })

if __name__ == "__main__":
    app.run(debug=True, port=int(os.getenv("PORT", 5000)))
