from flask import Flask, request, jsonify
from passlib.hash import bcrypt
from backend.tools import *

app = Flask(__name__)

@app.route('/signup', methods=['POST'])
def signup():
    # Get the user's input
    username = request.json.get('username')
    email = request.json.get('email')
    password = request.json.get('password')
    
    if fields_empty(username, email, password):
        return jsonify({'error': 'Please fill in all fields'}), 400
    else:
        valid_inputs, error = check_if_valid_inputs(email, password)
        if not valid_inputs:
            return jsonify({'error': error}), 400
        else:
            if check_if_user_exists(email):
                return jsonify({'error': 'User already exists'}), 400
            elif username_taken(username):
                return jsonify({'error': 'Username already taken'}), 400
            else:
                hashed_password = bcrypt.hash(password)
                add_user(email, hashed_password, username)
                return jsonify({'message': 'User created successfully'}), 201


@app.route('/login', methods=['POST'])
def login_route():
    # Get email and password from the request
    data = request.json
    email = data.get('email')
    password = data.get('password')
    
    # Check if both fields are provided
    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400
    
    # Validate password format (can reuse your existing validation function)
    password_valid, error = valid_password(password)
    if not password_valid:
        return jsonify({'error': error}), 400
    
    # Call the login function and get the response
    result, status_code = login(email, password)
    
    # Return the response
    return jsonify(result), status_code
