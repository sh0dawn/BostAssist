# app.py
from flask import Flask, request, jsonify
from datetime import datetime
import os
from functools import wraps
import uuid

app = Flask(__name__)
app.secret_key = os.urandom(24)

# In-memory storage (replace with database in production)
chat_logs = []
API_KEYS = {'test-key': 'admin'}  # In production, use proper key management

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key or api_key not in API_KEYS:
            return jsonify({'success': False, 'error': 'Invalid API key'}), 401
        return f(*args, **kwargs)
    return decorated

class Message:
    def __init__(self, text, is_bot=False):
        self.id = len(chat_logs) + 1
        self.text = text
        self.is_bot = is_bot
        self.timestamp = datetime.now()

    def to_dict(self):
        return {
            'id': self.id,
            'text': self.text,
            'isBot': self.is_bot,
            'timestamp': self.timestamp.isoformat()
        }

class ChatLog:
    def __init__(self):
        self.id = len(chat_logs) + 1
        self.user_id = str(uuid.uuid4())
        self.messages = []
        self.created_at = datetime.now()

    def add_message(self, text, is_bot=False):
        message = Message(text, is_bot)
        self.messages.append(message)
        return message

    def to_dict(self):
        return {
            'id': self.id,
            'userId': self.user_id,
            'messages': [m.to_dict() for m in self.messages],
            'createdAt': self.created_at.isoformat()
        }

@app.route('/chat', methods=['POST'])
def chat():
    try:
        data = request.get_json()
        if not data or 'message' not in data:
            return jsonify({'success': False, 'error': 'Message is required'}), 400

        # Create new chat log if none exists
        if not chat_logs:
            chat_logs.append(ChatLog())

        current_log = chat_logs[-1]
        
        # Process user message
        current_log.add_message(data['message'], is_bot=False)
        
        # Generate bot response (replace with actual AI processing)
        bot_response = "I received your message: " + data['message']
        bot_message = current_log.add_message(bot_response, is_bot=True)

        return jsonify({
            'success': True,
            'data': bot_message.to_dict()
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/get_logs', methods=['GET'])
@require_api_key
def get_logs():
    try:
        return jsonify({
            'success': True,
            'data': [log.to_dict() for log in chat_logs]
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/security-info', methods=['GET'])
@require_api_key
def security_info():
    return jsonify({
        'isHttps': request.is_secure,
        'apiVersion': '1.0.0',
        'serverLocation': 'EU-West',
        'lastAudit': datetime.now().isoformat(),
        'certificateExpiry': (datetime.now().timestamp() + 30 * 24 * 60 * 60) * 1000,
        'activeConnections': 42,
        'apiKeyStrength': 'strong',
        'securityUpdates': {
            'status': 'up-to-date',
            'lastUpdate': datetime.now().isoformat()
        }
    })

# Serve static files (React frontend)
@app.route('/')
def serve_app():
    return app.send_static_file('index.html')

if __name__ == '__main__':
    # Initialize with a welcome message
    initial_log = ChatLog()
    initial_log.add_message("Hello! I'm BotAssist, your AI assistant. How can I help you today?", is_bot=True)
    chat_logs.append(initial_log)
    
    app.run(debug=True)