# frontend/routes/review.py
from flask import Blueprint,render_template


review_frontends_bp = Blueprint('review_frontend', __name__, 
                                 static_folder='../../static', 
                                 template_folder='../../templates')

@review_frontends_bp.route("/review",  methods=['GET'], strict_slashes=False)
def review():
    return render_template("review/index.html")        
    
