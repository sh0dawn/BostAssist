from flask import Flask, request, jsonify, render_template, render_template_string, make_response
from datetime import datetime, timedelta
import os
import jwt
from functools import wraps

app = Flask(__name__, 
            static_folder='static',  # Specify static folder
            static_url_path='/static')  # Set static URL path

app.secret_key = os.urandom(24)
JWT_SECRET = os.urandom(24).hex()

# Load API key from config file
CONFIG_FILE = "config.py"
API_KEY = ""
try:
    with open(CONFIG_FILE, "r") as f:
        exec(f.read())  # Load API_KEY from config file
except Exception as e:
    print(f"Warning: Could not load config file - {e}")

BOT_TEMPLATES = {
    "default": "AI Bot says: {{ user_message }}",
    "admin": "AI Admin Panel: {{ user_message }}"
}

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('jwt_token')
        if not token:
            return jsonify({'success': False, 'error': 'Missing token'}), 401
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            return jsonify({'success': False, 'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'success': False, 'error': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated

@app.route("/login", methods=["POST"])
def login():
    api_key = request.headers.get("X-API-Key")
    if api_key != API_KEY:
        return jsonify({"success": False, "error": "Invalid API Key"}), 403
    
    token = jwt.encode({
        'exp': datetime.utcnow() + timedelta(hours=1),
        'role': 'admin'
    }, JWT_SECRET, algorithm="HS256")
    
    resp = make_response(jsonify({"success": True, "message": "Logged in successfully"}))
    resp.set_cookie('jwt_token', token, httponly=True)
    return resp

@app.route("/")
def index():
    return render_template('index.html')

@app.route("/download")
def download():
    file = request.args.get("file")
    if not file:
        return "Missing file parameter", 400
    
    try:
        with open(file, "r") as f:
            file_content = f.read()
            return jsonify({"success": True, "bot_response": file_content})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})

# Chatbot functionality
@app.route("/chat", methods=["POST"])
@token_required
def chat():
    user_message = request.form.get("message")
    token = request.cookies.get('jwt_token')
    decoded_token = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
    
    if decoded_token.get('role') == 'admin':
        response_template = BOT_TEMPLATES.get("admin", "AI Admin Panel: {{ user_message }}")
        bot_response = render_template_string(response_template, user_message=user_message)
    else:
        bot_response = BOT_TEMPLATES.get("default", "AI Bot says: {{ user_message }}").replace("{{ user_message }}", user_message)
    
    return jsonify({"success": True, "bot_response": bot_response})

if __name__ == "__main__":
    from waitress import serve
    serve(app, host="0.0.0.0", port=5000)
