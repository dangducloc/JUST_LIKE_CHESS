from flask import Flask, render_template
from flask_socketio import SocketIO
from flask_mail import Mail
from api.routes.index import api
import os
from dotenv import load_dotenv, find_dotenv
# Load .env file
load_dotenv(find_dotenv())
MAIL : str = os.getenv("MAIL")
APP_PASS :str = os.getenv("APP_PASS")
app: Flask = Flask(__name__, template_folder='api/templates')

# Flask-Mail config
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = MAIL
app.config['MAIL_PASSWORD'] = APP_PASS
app.config['MAIL_DEFAULT_SENDER'] = ('aloooo!!', 'dangloc2110@gmail.com')


mail = Mail(app)
socketio = SocketIO(app, cors_allowed_origins="*")
app.register_blueprint(api, url_prefix='/api')

# Initialize socket events
from api.routes.index import init_sockets
init_sockets(socketio)

@app.route('/')
def home() -> str:
    return "Hello, Flask!"

if __name__ == '__main__':
    socketio.run(app, debug=True)
