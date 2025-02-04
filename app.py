from flask import Flask, request, jsonify, render_template
from jinja2 import Environment, StrictUndefined, meta
from datetime import datetime, timedelta, UTC
import os
import jwt
import subprocess
import threading
import queue
from functools import wraps
from config import API_KEY
import requests

app = Flask(__name__, 
            static_folder='static',
            static_url_path='/static')

app.secret_key = os.urandom(24)

# Paths
LLAMA_BIN = "/home/developer/BostAssist/llama.cpp/build/bin/main"
LLAMA_MODEL = "/home/developer/BostAssist/models/phi-2.Q4_K_M.gguf"

# Queue for handling LLM requests asynchronously
llm_queue = queue.Queue()

# Global counter for messages
message_count = 0

# Command help messages
USER_COMMANDS = {
    "help": "Display all available commands",
    "time": "Get the current server time",
    "fetch <url>": "Fetch content from a localhost URL",
    "legal": "Display legal information and usage terms",
    "security": "Display basic security information"
}

ADMIN_COMMANDS = {
    **USER_COMMANDS,
    "admin/security": "Get detailed security information",
    "admin/messages": "Get message count since server start",
    "admin/render <template>": "Render a template for debugging (e.g., 'admin/render Hello {{name}}!')",
    "admin/debug": "Get debug information about the server"
}

SAFE_DIRECTORY = os.path.abspath(os.getcwd()) + os.sep # Restrict file access

# LLM Function
def query_llm(prompt):
    """Runs Phi-2 model using llama.cpp with low RAM optimization."""
    try:
        result = subprocess.run(
            [LLAMA_BIN, "-m", LLAMA_MODEL, "-p", prompt, "-n", "100", "--temp", "0.7"],
            capture_output=True, text=True, timeout=15
        )
        return result.stdout.strip()
    except Exception as e:
        return f"LLM error: {str(e)}"

# Background worker for LLM
def llm_worker():
    while True:
        prompt, response_queue = llm_queue.get()
        response = query_llm(prompt)
        response_queue.put(response)
        llm_queue.task_done()

# Start worker thread
threading.Thread(target=llm_worker, daemon=True).start()

def safe_render(template, **context):
    env = Environment(
        undefined=StrictUndefined,
        autoescape=True
    )
    # Parse template to analyze variables used
    parsed_content = env.parse(template)
    used_variables = meta.find_undeclared_variables(parsed_content)

    # Restrict dangerous variables
    blocked_vars = {'self', '__globals__', '__builtins__', '__class__', 'os', 'subprocess', 'exec', 'eval'}
    safe_context = {k: v for k, v in context.items() if k not in blocked_vars}

    # Remove access to __import__ (critical for importing dangerous modules)
    def restricted_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name in ["os", "subprocess"]:
            raise ImportError(f"Module {name} is restricted.")
        return __import__(name, globals, locals, fromlist, level)

    # Provide only minimal builtins and restrict access to harmful functions
    safe_context['safe_var'] = "Think harder 😉"
    safe_context['dir'] = dir  # Keep access to dir for introspection
    safe_context['getattr'] = getattr  # Allow safe getattr access
    safe_context['__import__'] = restricted_import  # Override __import__ to block dangerous imports
    
    # Disable dangerous functions in the environment
    env.globals.update({
        'open': None,  # Disallow file open
        'exec': None,  # Disallow exec() function
        'eval': None,  # Disallow eval() function
    })
    return env.from_string(template).render(safe_context)

def generate_help_message(is_admin=False):
    commands = ADMIN_COMMANDS if is_admin else USER_COMMANDS
    help_text = "Available commands:\n\n"
    for cmd, desc in commands.items():
        help_text += f"• {cmd}: {desc}\n"
    return help_text

def generate_token(api_key):
    try:
        payload = {
            'exp': datetime.now(UTC) + timedelta(hours=1),
            'iat': datetime.now(UTC),
            'sub': 'admin'
        }
        return jwt.encode(
            payload,
            app.secret_key,
            algorithm='HS256'
        )
    except Exception as e:
        return str(e)

def is_admin_token(token):
    try:
        jwt.decode(token, app.secret_key, algorithms=["HS256"])
        return True
    except:
        return False

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if ' ' in auth_header:
                token = auth_header.split(" ")[1]
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            data = jwt.decode(token, app.secret_key, algorithms=["HS256"])
            if data['sub'] != 'admin':
                return jsonify({'error': 'Invalid token'}), 401
        except:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    return decorated

@app.route('/chat', methods=['POST'])
def chat():
    global message_count
    try:
        data = request.get_json()
        if not data or 'message' not in data:
            return jsonify({'success': False, 'error': 'Message is required'}), 400
        
        message = data['message'].lower()
        message_count += 1

        # Check admin status
        token = request.headers.get('Authorization', '').split(' ')[1] if 'Authorization' in request.headers else None
        is_admin = is_admin_token(token) if token else False
        
        # Help command
        if message.strip() == 'help':
            response = generate_help_message(is_admin)
            
        # Admin commands
        elif is_admin and message.startswith('admin/'):
            if message.startswith('admin/render'):
                template = message[len('admin/render'):].strip()
                try:
                    rendered = safe_render(template)  # Use sandboxed rendering for safety
                    response = f"Template rendered successfully:\n{rendered}"
                except Exception as e:
                    response = f"Error rendering template: {str(e)}"       
            elif message == 'admin/messages':
                response = f"Total messages since server start: {message_count}\nServer started at: {app.start_time.isoformat()}"
                
            elif message == 'admin/security':
                security_info = {
                    'isHttps': request.is_secure,
                    'apiVersion': '1.0.0',
                    'serverLocation': 'EU-West',
                    'lastAudit': datetime.now().isoformat(),
                    'certificateExpiry': (datetime.now().timestamp() + 30 * 24 * 60 * 60) * 1000,
                    'securityUpdates': 'up-to-date',
                    'firewallRules': ['block_external_ips', 'allow_localhost_only']
                }
                response = "Security Information:\n" + "\n".join(f"• {k}: {v}" for k, v in security_info.items())
                
            elif message == 'admin/debug':
                debug_info = {
                    'server_time': datetime.now().isoformat(),
                    'python_version': os.sys.version,
                    'message_count': message_count,
                    'uptime': str(datetime.now(UTC) - app.start_time)
                }
                response = "Debug Information:\n" + "\n".join(f"• {k}: {v}" for k, v in debug_info.items())
                
            else:
                response = "Unknown admin command. Type 'help' to see available commands."
        
        # Basic user commands
        elif 'time' in message:
            response = f"Current time is: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        elif message.startswith('fetch'):
            url = message.split('fetch')[-1].strip()

            # Check if the URL starts with 'http://localhost' or 'https://localhost'
            if url.startswith('http://localhost') or url.startswith('https://localhost'):
                try:
                    # Fetch content via HTTP request
                    r = requests.get(url)
                    response = f"Content fetched from {url}: {r.text[:200]}..."
                except Exception as e:
                    response = f"Error fetching URL: {str(e)}"
            # What could go wrong if I let people check files on the server
            elif url.startswith('/') or url.startswith('..') or url.startswith('./'):
                file_path = os.path.join(SAFE_DIRECTORY, message.split('fetch')[-1].strip())
                #update : I changed my mind and decided to add this little security buff just in case
                # my website should be pretty safe now
                if not os.path.abspath(file_path).startswith(SAFE_DIRECTORY):
                    response = "Access denied: Invalid file path"
                else:
                    try:
                        # Try opening the file specified by the path in the URL
                        with open(url, 'r') as file:
                            response = f"Content fetched from {url}: {file.read()[:200]}..."
                    except PermissionError:
                        response = f"Permission error: Unable to access {url}. You might not have the required permissions."
                    except FileNotFoundError:
                        response = f"Error: The file {url} was not found."
                    except Exception as e:
                        response = f"Error fetching file: {str(e)}"
            else:
                response = "Only localhost URLs and local file paths are allowed"
        elif 'legal' in message or 'usage' in message:
            response = "BotAssist is for authorized use only. All interactions are logged and monitored."
        elif 'security' in message:
            response = "Basic security information: HTTPS enabled, regular security audits performed."
        else:
            # Use LLM when no command matches
            response_queue = queue.Queue()
            llm_queue.put((message, response_queue))
            response = response_queue.get()  # Wait for LLM response            
        
        return jsonify({
            'success': True,
            'data': {
                'text': response,
                'isBot': True,
                'timestamp': datetime.now().isoformat()
            }
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/')
def index():
    token = request.cookies.get('token')
    is_admin = is_admin_token(token) if token else False
    return render_template('index.html', is_admin=is_admin)

@app.route('/login', methods=['POST'])
def login():
    auth_key = request.headers.get('X-API-Key')
    
    if not auth_key or auth_key != API_KEY:
        return jsonify({'error': 'Invalid API key'}), 401
    
    token = generate_token(auth_key)
    return jsonify({
        'token': token,
        'message': 'Successfully logged in as admin'
    })

# Store startup time
app.start_time = datetime.now(UTC)

if __name__ == '__main__':
    from waitress import serve
    print(f"Server started. Use API key from config.py to log in as admin")
    print(f"Test admin login with:")
    print(f"curl -X POST -H 'X-API-Key: {API_KEY}' http://localhost:5000/login")
    print(f"Then use the token in subsequent requests:")
    print(f"curl -H 'Authorization: Bearer <token>' http://localhost:5000/chat")
    print(f"Available admin commands: {list(ADMIN_COMMANDS.keys())}")
    serve(app, host="0.0.0.0", port=5000)