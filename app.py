from flask import Flask, request, jsonify
from passlib.hash import bcrypt

app = Flask(__name__)

@app.route('/hash', methods=['POST'])
def hash_password():
    data = request.get_json()
    password = data.get('password')

    if not password:
        return jsonify({'error': 'Password is required'}), 400

    hashed_password = bcrypt.hash(password)
    return jsonify({'hashed_password': hashed_password})

@app.route('/verify', methods=['POST'])
def verify_password():
    data = request.get_json()
    password = data.get('password')
    hashed_password = data.get('hashed_password')

    if not password or not hashed_password:
        return jsonify({'error': 'Password and hashed_password are required'}), 400

    is_valid = bcrypt.verify(password, hashed_password)
    return jsonify({'is_valid': is_valid})

if __name__ == '__main__':
    app.run(debug=True)
