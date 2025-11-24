from flask import Flask
from flask_socketio import SocketIO
from flask_mail import Mail
from api.routes.index import api
from frontends.routes.index import fe
import os
from dotenv import load_dotenv, find_dotenv

# Load .env file
load_dotenv(find_dotenv())
MAIL : str = os.getenv("MAIL")
APP_PASS :str = os.getenv("APP_PASS")
app: Flask = Flask(__name__)

# Flask-Mail config
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = MAIL
app.config['MAIL_PASSWORD'] = APP_PASS
app.config['MAIL_DEFAULT_SENDER'] = ('aloooo!!', 'dangloc2110@gmail.com')


mail:Mail = Mail(app)
socketio:SocketIO = SocketIO(app, cors_allowed_origins="*")
app.register_blueprint(api, url_prefix='/api')
app.register_blueprint(fe, url_prefix='/')

# Initialize socket events
from api.routes.index import init_sockets
init_sockets(socketio)



if __name__ == '__main__':
    socketio.run(app, debug=True)
