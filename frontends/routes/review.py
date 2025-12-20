# frontend/routes/review.py
from flask import Blueprint,render_template


review_frontends_bp = Blueprint('review_frontend', __name__, 
                                 static_folder='../../static', 
                                 template_folder='../../templates')

@review_frontends_bp.route("/review/<id_match>",  methods=['GET'], strict_slashes=False)
def review(id_match):
    return render_template("review/index.html",match_id=id_match)        
    
