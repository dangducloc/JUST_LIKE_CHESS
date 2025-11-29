from flask import request, jsonify
from functools import wraps
import re

class ValidationError(Exception):
    def __init__(self, message, status_code=400):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)

def validate_email(email):
    """Validate email format"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(pattern, email):
        raise ValidationError("Invalid email format")
    return email.strip().lower()

def validate_password(password):
    """Validate password strength"""
    if len(password) < 8:
        raise ValidationError("Password must be at least 8 characters")
    if not re.search(r'[A-Za-z]', password):
        raise ValidationError("Password must contain letters")
    if not re.search(r'\d', password):
        raise ValidationError("Password must contain numbers")
    return password

def validate_username(name):
    """Validate username"""
    name = name.strip()
    if len(name) < 2 or len(name) > 50:
        raise ValidationError("Name must be 2-50 characters")
    if not re.match(r'^[a-zA-Z0-9_\s]+$', name):
        raise ValidationError("Name can only contain letters, numbers, and underscores")
    return name

def validate_elo(elo):
    """Validate ELO rating"""
    try:
        elo_int = int(elo)
        if elo_int < 0 or elo_int > 3500:
            raise ValidationError("ELO must be between 0 and 3500")
        return elo_int
    except ValueError:
        raise ValidationError("ELO must be a number")

def require_fields(*fields):
    """Decorator to validate required fields"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            data = request.get_json() or {}
            missing = [field for field in fields if not data.get(field)]
            
            if missing:
                return jsonify({
                    "message": f"Missing required fields: {', '.join(missing)}"
                }), 400
            
            return f(*args, **kwargs)
        return decorated
    return decorator

# ============ ERROR HANDLERS ============
def register_error_handlers(app):
    """Register global error handlers"""
    
    @app.errorhandler(ValidationError)
    def handle_validation_error(e):
        return jsonify({"message": e.message}), e.status_code
    
    @app.errorhandler(400)
    def bad_request(e):
        return jsonify({"message": "Bad request"}), 400
    
    @app.errorhandler(401)
    def unauthorized(e):
        return jsonify({"message": "Unauthorized"}), 401
    
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"message": "Resource not found"}), 404
    
    @app.errorhandler(500)
    def internal_error(e):
        return jsonify({"message": "Internal server error"}), 500


# ============ USAGE EXAMPLE ============
"""
from utils.validators import require_fields, validate_email, validate_password

@auth_bp.route('/register', methods=['POST'])
@require_fields('mail', 'password', 'name')
def register():
    data = request.get_json()
    
    try:
        mail = validate_email(data['mail'])
        passwd = validate_password(data['password'])
        name = validate_username(data['name'])
    except ValidationError as e:
        return jsonify({"message": e.message}), e.status_code
    
    # ... rest of logic
"""