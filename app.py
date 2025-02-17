from flask import Flask, request, jsonify
import jwt
import datetime
import subprocess
import os
from functools import wraps  # ✅ Add this import

app = Flask(__name__)
SECRET_KEY = os.environ.get("SECRET_KEY", "default-secret-key")

# Generate JWT Token
@app.route('/get_token', methods=['POST'])
def get_token():
    auth_data = request.json
    if auth_data and auth_data.get("username") == os.environ.get("API_USERNAME", "admin") and auth_data.get("password") == os.environ.get("API_PASSWORD", "password"):
        token = jwt.encode(
            {"exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)},
            SECRET_KEY,
            algorithm="HS256"
        )
        return jsonify({"token": token})
    return jsonify({"message": "Invalid credentials"}), 401

# Middleware to verify JWT token

def token_required(func):
    @wraps(func)  # ✅ Use wraps to prevent Flask from overwriting functions
    def wrapper(*args, **kwargs):
        token = request.headers.get("Authorization")
        if not token:
            return jsonify({"message": "Token is missing"}), 403
        try:
            jwt.decode(token.split(" ")[1], SECRET_KEY, algorithms=["HS256"])
        except:
            return jsonify({"message": "Invalid or expired token"}), 403
        return func(*args, **kwargs)
    return wrapper

# Get Current Proxy IP
@app.route('/get_ip', methods=['GET'])
@token_required
def get_ip():
    result = subprocess.run(['curl', '--proxy', 'socks5h://127.0.0.1:1080', 'ifconfig.me'], capture_output=True, text=True)
    return jsonify({"ip": result.stdout.strip()})

# Rotate IP
@app.route('/rotate_ip', methods=['POST'])
@token_required
def rotate_ip():
    subprocess.run(["warp-cli", "disconnect"], capture_output=True, text=True)
    subprocess.run(["warp-cli", "connect"], capture_output=True, text=True)
    return jsonify({"status": "IP rotated"})

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
