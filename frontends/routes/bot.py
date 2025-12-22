# frontend/routes/bot.py
from flask import Blueprint,render_template


bot_frontend_bp = Blueprint('bot_frontend', __name__, 
                                 static_folder='../../static', 
                                 template_folder='../../templates')

@bot_frontend_bp.route("/game/bot",  methods=['GET'], strict_slashes=False)
def bot_game():
    return render_template("game/bot.html")        
    
