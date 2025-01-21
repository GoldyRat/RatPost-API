import firebase_admin
from firebase_admin import credentials, db
import re
import bcrypt
from dotenv import load_dotenv
import os

load_dotenv()

firebase_credentials_path = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')

# Initialize Firebase with your service account key
cred = credentials.Certificate(firebase_credentials_path)
firebase_admin.initialize_app(cred, {
    'databaseURL': "https://ratpost-d7a07-default-rtdb.firebaseio.com"  # Replace with your actual database URL
})

""" 
    Get a reference to the database path : ref = db.reference('users/user_id') 
    Set data at the specified path : 
    ref.set({
        'name': 'John Doe', 'email': 'email...'
    })
    Retrieve the data : user_data = ref.get()
    Update a specific field :
    ref.update({
        'email': 'new.email@example.com'
    })
    Delete a field : ref.delete()
"""

ref = db.reference('users')

def get_previous_users():
    return ref.get()

def add_user(email, password, username):
    new_user_ref = ref.push()  # Firebase creates a unique ID
    new_user_ref.set({
        'email': email,
        'password': password,
        'username': username
    })


def check_if_user_exists(email):
    # Firebase query to check if the email exists
    result = ref.order_by_child('email').equal_to(email).get()
    return bool(result)  # Return True if a user with this email exists


def username_taken(username):
    # Firebase query to check if the email exists
    result = ref.order_by_child('username').equal_to(username).get()
    return bool(result)  # Return True if a user with this email exists


def fields_empty(username, email, password):
    return not username or not email or not password

def check_if_valid_inputs(email, password):
    password_valid, error = valid_password(password)
    email_valid, error = valid_email(email)
    if not password_valid or not email_valid:
        return False, error
    else:
        return True, None
    


def valid_password(password):
    # Check if password length is at least 8 characters
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    
    # Check for at least one uppercase letter
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter."
    
    # Check for at least one lowercase letter
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter."
    
    # Check for at least one digit
    if not re.search(r'\d', password):
        return False, "Password must contain at least one digit."
    
    # Check for at least one special character
    if not re.search(r'[@$!%*?&]', password):
        return False, "Password must contain at least one special character."
    
    # If all conditions are met
    return True, "Password is valid."

import re

def valid_email(email):
    # Regular expression for basic email validation
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    # Check if the email matches the regex
    if re.match(email_regex, email):
        return True, "Email is valid."
    else:
        return False, "Invalid email format."




def hash_password(password):
    # Check if password is provided
    if not password:
        raise ValueError('Password is required')

    # Hash the password using bcrypt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # Return the hashed password as a string (since it's in bytes, we'll decode it)
    return hashed_password.decode('utf-8')


""" Next part is login related functions """

# Function to handle the login process
def login(email, password):
    # 1. Check if the user exists
    if not check_if_user_exists(email):
        return {'error': 'Invalid email or password'}, 400
    
    # 2. Get the user data from Firebase based on email
    previous_users = ref.order_by_child('email').equal_to(email).get()
    user_data = next(iter(previous_users.values()))  # Get the first matching user
    
    stored_hashed_password = user_data['password']
    
    # 3. Compare the provided password with the stored hashed password
    if bcrypt.checkpw(password.encode('utf-8'), stored_hashed_password.encode('utf-8')):
        # Password matches, return success
        return {'message': 'Login successful'}, 200
    else:
        # Password doesn't match
        return {'error': 'Invalid email or password'}, 400