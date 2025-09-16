server/app.py:
from flask import Flask, request, jsonify, g, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from flask_pymongo import PyMongo
from bson import ObjectId
from flask_cors import CORS
import os
import jwt
from datetime import datetime, timedelta
import requests
from functools import wraps
import uuid
import pymongo

app = Flask(__name__)
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "supersecretkey")
ACCESS_EXPIRES_MIN = int(os.getenv("ACCESS_EXPIRES_MIN", "15"))
REFRESH_EXPIRES_DAYS = int(os.getenv("REFRESH_EXPIRES_DAYS", "7"))
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "False").lower() in ("1", "true", "yes")

MONGO_URI = os.getenv("MONGO_URI")
if not MONGO_URI:
    raise RuntimeError("MONGO_URI environment variable is not set.")

app.config["MONGO_URI"] = MONGO_URI
mongo = None
db = None
users_collection = None

try:
    mongo = PyMongo(app)
    db = mongo.db
except Exception as e:
    print("flask_pymongo initialization failed:", str(e))
    mongo = None
    db = None

if db is None:
    try:
        client = pymongo.MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        client.admin.command("ping")
        try:
            db = client.get_default_database()
        except Exception:
            fallback_dbname = os.getenv("MONGO_DBNAME", "mydb")
            db = client[fallback_dbname]
        print("Connected to MongoDB via pymongo; using database:", db.name)
    except Exception as e:
        print("Failed to connect to MongoDB with pymongo:", str(e))
        db = None

if db is None:
    raise RuntimeError("Could not initialize MongoDB connection.")

users_collection = db.get_collection("users")

CORS(app, resources={r"/*": {"origins": ["http://localhost:3000", "https://*.replit.dev"], "methods": ["GET", "POST", "OPTIONS", "DELETE", "PUT"], "allow_headers": ["Content-Type"], "supports_credentials": True}})

def _encode_token(payload):
    return jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")

def _decode_token(token):
    return jwt.decode(token, app.config["SECRET_KEY"], algorithms=["HS256"])

def _create_access_token(user_id):
    exp = datetime.utcnow() + timedelta(minutes=ACCESS_EXPIRES_MIN)
    payload = {"user_id": str(user_id), "type": "access", "exp": exp}
    token = _encode_token(payload)
    return token, exp

def _create_refresh_token(user_id, jti=None):
    if not jti:
        jti = str(uuid.uuid4())
    exp = datetime.utcnow() + timedelta(days=REFRESH_EXPIRES_DAYS)
    payload = {"user_id": str(user_id), "type": "refresh", "jti": jti, "exp": exp}
    token = _encode_token(payload)
    return token, jti, exp

def _set_cookie(response, name, value, expires):
    response.set_cookie(name, value, httponly=True, secure=COOKIE_SECURE, samesite="Lax", path="/", expires=expires)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("access_token")
        if not token:
            return jsonify({"error": "Authentication required"}), 401
        try:
            data = _decode_token(token)
            if data.get("type") != "access":
                return jsonify({"error": "Invalid token type"}), 401
            user = users_collection.find_one({"_id": ObjectId(data["user_id"])})
            if not user:
                return jsonify({"error": "User not found"}), 401
            g.current_user = user
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Access token expired"}), 401
        except Exception:
            return jsonify({"error": "Invalid access token"}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/signup', methods=['POST', 'OPTIONS'])
def signup():
    if request.method == 'OPTIONS':
        return '', 200
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        user_data = data.get('user_data', {})
        if not username or not password or not email:
            return jsonify({"error": "Missing username, email or password"}), 400
        if users_collection.find_one({"email": email}):
            return jsonify({"error": "Email already exists"}), 409
        if users_collection.find_one({"username": username}):
            return jsonify({"error": "Username already exists"}), 409
        hashed_password = generate_password_hash(password)
        new_user = {"username": username, "email": email, "password": hashed_password, "user_data": user_data}
        result = users_collection.insert_one(new_user)
        return jsonify({"message": "User registered successfully", "id": str(result.inserted_id)}), 201
    except Exception as e:
        print(f"Registration error: {str(e)}")
        return jsonify({"error": "Registration failed"}), 500

@app.route('/login', methods=['POST', 'OPTIONS'])
def login():
    if request.method == 'OPTIONS':
        return '', 200
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        email = data.get('email')
        password = data.get('password')
        if not email or not password:
            return jsonify({"error": "Missing email or password"}), 400
        user = users_collection.find_one({"email": email})
        if not user or not check_password_hash(user.get("password", ""), password):
            return jsonify({"error": "Invalid credentials"}), 401
        user_id = user["_id"]
        access_token, access_exp = _create_access_token(user_id)
        refresh_token, jti, refresh_exp = _create_refresh_token(user_id)
        users_collection.update_one({"_id": user_id}, {"$set": {"refresh_jti": jti}})
        resp = make_response(jsonify({"message": "Logged in"}), 200)
        _set_cookie(resp, "access_token", access_token, access_exp)
        _set_cookie(resp, "refresh_token", refresh_token, refresh_exp)
        return resp
    except Exception as e:
        print(f"Login error: {str(e)}")
        return jsonify({"error": "Login failed"}), 500

@app.route('/refresh', methods=['POST', 'OPTIONS'])
def refresh():
    if request.method == 'OPTIONS':
        return '', 200
    try:
        token = request.cookies.get("refresh_token")
        if not token:
            return jsonify({"error": "Missing refresh token"}), 401
        try:
            data = _decode_token(token)
            if data.get("type") != "refresh":
                return jsonify({"error": "Invalid token type"}), 401
            user_id = data.get("user_id")
            jti = data.get("jti")
            user = users_collection.find_one({"_id": ObjectId(user_id)})
            if not user or user.get("refresh_jti") != jti:
                return jsonify({"error": "Invalid refresh token"}), 401
            access_token, access_exp = _create_access_token(user_id)
            new_refresh_token, new_jti, new_refresh_exp = _create_refresh_token(user_id)
            users_collection.update_one({"_id": ObjectId(user_id)}, {"$set": {"refresh_jti": new_jti}})
            resp = make_response(jsonify({"message": "Token refreshed"}), 200)
            _set_cookie(resp, "access_token", access_token, access_exp)
            _set_cookie(resp, "refresh_token", new_refresh_token, new_refresh_exp)
            return resp
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Refresh token expired"}), 401
        except Exception:
            return jsonify({"error": "Invalid refresh token"}), 401
    except Exception as e:
        print(f"Refresh error: {str(e)}")
        return jsonify({"error": "Refresh failed"}), 500

@app.route('/logout', methods=['POST', 'OPTIONS'])
@token_required
def logout():
    if request.method == 'OPTIONS':
        return '', 200
    try:
        user = g.current_user
        users_collection.update_one({"_id": user["_id"]}, {"$unset": {"refresh_jti": ""}})
        resp = make_response(jsonify({"message": "Logged out"}), 200)
        resp.set_cookie("access_token", "", expires=0, path="/")
        resp.set_cookie("refresh_token", "", expires=0, path="/")
        return resp
    except Exception as e:
        print(f"Logout error: {str(e)}")
        return jsonify({"error": "Logout failed"}), 500

@app.route('/me', methods=['GET'])
@token_required
def me():
    user = g.current_user
    user_info = {"id": str(user["_id"]), "username": user.get("username"), "email": user.get("email"), "user_data": user.get("user_data", {})}
    return jsonify(user_info), 200

@app.route('/profile', methods=['GET', 'PUT', 'OPTIONS'])
@token_required
def profile():
    if request.method == 'OPTIONS':
        return '', 200
    user = g.current_user
    if request.method == 'GET':
        user_info = {"id": str(user["_id"]), "username": user.get("username"), "email": user.get("email"), "user_data": user.get("user_data", {})}
        return jsonify(user_info), 200
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        updates = {}
        new_username = data.get("username")
        new_email = data.get("email")
        new_user_data = data.get("user_data")
        if new_username and new_username != user.get("username"):
            if users_collection.find_one({"username": new_username}):
                return jsonify({"error": "Username already exists"}), 409
            updates["username"] = new_username
        if new_email and new_email != user.get("email"):
            if users_collection.find_one({"email": new_email}):
                return jsonify({"error": "Email already exists"}), 409
            updates["email"] = new_email
        if new_user_data is not None:
            updates["user_data"] = new_user_data
        if updates:
            users_collection.update_one({"_id": user["_id"]}, {"$set": updates})
        updated = users_collection.find_one({"_id": user["_id"]})
        user_info = {"id": str(updated["_id"]), "username": updated.get("username"), "email": updated.get("email"), "user_data": updated.get("user_data", {})}
        return jsonify(user_info), 200
    except Exception as e:
        print(f"Profile update error: {str(e)}")
        return jsonify({"error": "Profile update failed"}), 500


GEMINI_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
GEMINI_URL = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent"
HEADERS = {"Content-Type": "application/json", "x-goog-api-key": GEMINI_KEY}

def call_gemini(prompt, max_output_chars=2000):
    body = {
        "contents": [
            {"role": "user", "parts": [{"text": prompt}]}
        ],
        "response": {"max_output_tokens": max_output_chars}
    }
    r = requests.post(GEMINI_URL, headers=HEADERS, json=body, timeout=30)
    r.raise_for_status()
    j = r.json()
    parts = []
    for c in j.get("candidates", []) :
        for p in c.get("content", {}).get("parts", []):
            parts.append(p.get("text", ""))
    if not parts:
        for item in j.get("results", []):
            for cont in item.get("content", {}).get("parts", []):
                parts.append(cont)
    return "\n".join(parts) if parts else j

@app.route("/threats/priority", methods=["POST"])
def threat_prioritization():
    data = request.get_json() or {}
    targets = data.get("targets", "organization assets")
    context = data.get("context", "")
    prompt = (
        "You are a senior threat analyst. Given the following context and list of threats, "
        "analyze and prioritize threats focusing on relevance and severity. Return a JSON array "
        "of objects with fields: id, title, severity_score(0-100), rationale, recommended_action. "
        f"Context: {context}\nTargets: {targets}\nIf no threats are provided, return an empty array."
    )
    out = call_gemini(prompt)
    return jsonify({"result": out}), 200

@app.route("/threats/daily_snapshot", methods=["POST"])
def daily_snapshot():
    data = request.get_json() or {}
    scope = data.get("scope", "global")
    filters = data.get("filters", {})
    prompt = (
        "Produce a compact daily snapshot of critical threats for the given scope. Include: "
        "top CVEs with metadata (id, cvss, affected_products, summary), active malware campaigns "
        "with indicators, notable geopolitical influence operations, and a one-line urgency tag. "
        f"Scope: {scope}\nFilters: {filters}\nReturn JSON with keys: cves, malware, influence_ops, generated_at."
    )
    out = call_gemini(prompt)
    return jsonify({"snapshot": out}), 200

@app.route("/sources/aggregate", methods=["POST"])
def aggregate_sources():
    data = request.get_json() or {}
    query = data.get("query", "latest critical vulnerabilities")
    prompt = (
        "You are a data aggregator. Describe an unbiased sourcing summary and short aggregated "
        "findings for the query, indicating likely source types (open web, dark web, vendor advisories), "
        "confidence, and a short rationale. Return JSON: sources_summary, top_findings."
        f"\nQuery: {query}"
    )
    out = call_gemini(prompt)
    return jsonify({"aggregate": out}), 200

@app.route("/pattern_match", methods=["POST"])
def pattern_match():
    data = request.get_json() or {}
    indicators = data.get("indicators", [])
    prompt = (
        "Given indicators and historical behavior, detect likely patterns, link them to known "
        "threat actors or campaigns if possible, and produce matching confidence scores. Return JSON array "
        "with: indicator, matched_entity, confidence, evidence_snippet."
        f"\nIndicators: {indicators}"
    )
    out = call_gemini(prompt)
    return jsonify({"matches": out}), 200

@app.route("/custom_insights", methods=["POST"])
def custom_insights():
    data = request.get_json() or {}
    role = data.get("role", "security_lead")
    objective = data.get("objective", "brand protection")
    prompt = (
        "Tailor a short intelligence briefing to the given role and objective. Provide actionable bullets, "
        "top 3 risks, and suggested next steps for the team. Output JSON: role, objective, bullets, risks, next_steps."
        f"\nRole: {role}\nObjective: {objective}"
    )
    out = call_gemini(prompt)
    return jsonify({"insight": out}), 200

@app.route("/assessments/run", methods=["POST"])
def assessments_run():
    data = request.get_json() or {}
    task = data.get("task", "analyze CVE-2024-3400 for exploitability and mitigation")
    prompt = (
        "Act as an interactive lab instructor. For the requested hands-on task, provide: "
        "1) short analysis, 2) step-by-step practical assessment tasks the user can run in a safe test environment, "
        "3) expected outcomes, and 4) AI-driven feedback checklist. Return JSON keys: analysis, steps, expected, checklist."
        f"\nTask: {task}"
    )
    out = call_gemini(prompt)
    return jsonify({"assessment": out}), 200

@app.route("/")
def home():
    return "MongoDB connected!" if db else "MongoDB connection failed."
    #return "Hello from Flask on Replit!"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
