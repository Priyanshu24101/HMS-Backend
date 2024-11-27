from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:priya@localhost:3306/signup_db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

# Route for signup
@app.route('/signup', methods=['POST'])
def signup():
    data = request.form
    username = data.get('full_name')
    email = data.get('email')
    password = data.get('password')
    print(data, username, email, password)

    # Validation checks
    if not username or not email or not password:
        print("Not all fills")
        return jsonify({'status': 'error', 'message': 'All fields are required!'}), 400
    if len(password) < 8:
        print("Pass length not 8")
        return jsonify({'status': 'error', 'message': 'Password must be at least 8 characters long!'}), 400
    if User.query.filter_by(email=email).first():
        print("email already")
        return jsonify({'status': 'error', 'message': 'Email is already registered!'}), 400

    # Save user to the database
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    new_user = User(username=username, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'status': 'success', 'message': 'Signup successful!'}), 200

@app.route('/login', methods=['POST'])
def login():
    data = request.form
    email = data.get('email')
    password = data.get('password')

    # Validation checks
    if not email or not password:
        print("Both email and password are required")
        return jsonify({'status': 'error', 'message': 'Both email and password are required!'}), 400

    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password, password):
        print("Invalid email or password")
        return jsonify({'status': 'error', 'message': 'Invalid email or password!'}), 400

    return jsonify({'status': 'success', 'message': 'Login successful!'}), 200

# Initialize the database
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
    app.run(debug=True)

