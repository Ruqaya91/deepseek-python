from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from datetime import datetime, timedelta
import jwt
import os
from dotenv import load_dotenv
from passlib.hash import pbkdf2_sha256

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'true').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')
app.config['JWT_SECRET'] = os.getenv('JWT_SECRET', app.config['SECRET_KEY'])
app.config['JWT_EXPIRATION'] = int(os.getenv('JWT_EXPIRATION', 3600))  # 1 hour expiration

# Initialize extensions
db = SQLAlchemy(app)
mail = Mail(app)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    reset_token = db.Column(db.String(256))
    reset_token_expiration = db.Column(db.DateTime)

    def set_password(self, password):
        self.password_hash = pbkdf2_sha256.hash(password)

    def check_password(self, password):
        return pbkdf2_sha256.verify(password, self.password_hash)

# Helper Functions
def generate_reset_token(user_id):
    expiration = datetime.utcnow() + timedelta(seconds=app.config['JWT_EXPIRATION'])
    payload = {
        'user_id': user_id,
        'exp': expiration,
        'purpose': 'password_reset'
    }
    return jwt.encode(payload, app.config['JWT_SECRET'], algorithm='HS256')

def send_reset_email(user_email, token):
    reset_url = f"http://yourdomain.com/reset-password?token={token}"
    msg = Message(
        "Password Reset Request",
        recipients=[user_email],
        html=f"""
        <h1>Password Reset</h1>
        <p>Click the link below to reset your password:</p>
        <a href="{reset_url}">{reset_url}</a>
        <p>This link will expire in 1 hour.</p>
        """
    )
    mail.send(msg)

# Routes
@app.route('/api/request-password-reset', methods=['POST'])
def request_password_reset():
    data = request.get_json()
    email = data.get('email')
    
    if not email:
        return jsonify({'error': 'Email is required'}), 400
    
    user = User.query.filter_by(email=email).first()
    if not user:
        # For security, don't reveal if user doesn't exist
        return jsonify({'message': 'If an account exists with this email, a reset link has been sent'}), 200
    
    # Generate and save token
    token = generate_reset_token(user.id)
    user.reset_token = token
    user.reset_token_expiration = datetime.utcnow() + timedelta(seconds=app.config['JWT_EXPIRATION'])
    db.session.commit()
    
    # Send email
    send_reset_email(user.email, token)
    
    return jsonify({'message': 'If an account exists with this email, a reset link has been sent'}), 200

@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('new_password')
    
    if not token or not new_password:
        return jsonify({'error': 'Token and new password are required'}), 400
    
    try:
        # Verify token
        payload = jwt.decode(token, app.config['JWT_SECRET'], algorithms=['HS256'])
        if payload.get('purpose') != 'password_reset':
            return jsonify({'error': 'Invalid token purpose'}), 400
        
        user_id = payload.get('user_id')
        user = User.query.get(user_id)
        
        if not user or user.reset_token != token:
            return jsonify({'error': 'Invalid or expired token'}), 400
        
        if datetime.utcnow() > user.reset_token_expiration:
            return jsonify({'error': 'Token has expired'}), 400
        
        # Update password
        user.set_password(new_password)
        user.reset_token = None
        user.reset_token_expiration = None
        db.session.commit()
        
        return jsonify({'message': 'Password has been reset successfully'}), 200
    
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token has expired'}), 400
    except jwt.InvalidTokenError:
        return jsonify({'error': 'Invalid token'}), 400

# Create database tables (for development)
@app.before_first_request
def create_tables():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)
