# frontends/routes/matching.py
from flask import Blueprint, render_template

matching_frontend_bp = Blueprint('matching_frontend', __name__, 
                                 static_folder='../../static', 
                                 template_folder='../../templates')

# =========== MATCHING PAGE ============
@matching_frontend_bp.route('/home', methods=['GET'], strict_slashes=False)
def matching_page():
    return render_template('matching/index.html')

# =========== GAME PAGE ============
@matching_frontend_bp.route('/game/<match_id>', methods=['GET'], strict_slashes=False)
def game_page(match_id):
    return render_template('game/index.html', match_id=match_id)