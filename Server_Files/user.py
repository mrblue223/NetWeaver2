import bcrypt
import json
import os

# Define the path to the user data file
USER_DATA_FILE = 'users.json'

def _load_users():
    """Loads user data from the JSON file."""
    if not os.path.exists(USER_DATA_FILE):
        return {}
    with open(USER_DATA_FILE, 'r') as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return {} # Return empty dict if file is empty or corrupted

def _save_users(users):
    """Saves user data to the JSON file."""
    with open(USER_DATA_FILE, 'w') as f:
        json.dump(users, f, indent=4)

def hash_password(password):
    """Hashes a password using bcrypt."""
    # Generate a salt and hash the password
    # bcrypt.gensalt() generates a new salt each time,
    # making brute-force attacks more difficult
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')

def check_password(password, hashed_password):
    """Checks if a plain password matches a hashed password."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    except ValueError:
        # This can happen if the hashed_password is not a valid bcrypt hash
        return False

def add_user(username, password):
    """Adds a new user to the system."""
    users = _load_users()
    if username in users:
        return False, "Username already exists."
    
    users[username] = hash_password(password)
    _save_users(users)
    return True, "User added successfully."

def authenticate_user(username, password):
    """Authenticates a user."""
    users = _load_users()
    hashed_password = users.get(username)

    if hashed_password and check_password(password, hashed_password):
        return True, "Authentication successful."
    return False, "Invalid username or password."

# Example usage (for testing/initial setup):
if __name__ == "__main__":
    print("--- User Management Utility ---")

    while True:
        choice = input("\n(1) Add User, (2) Authenticate User, (3) Exit: ")
        if choice == '1':
            new_username = input("Enter new username: ")
            new_password = input("Enter new password: ")
            success, message = add_user(new_username, new_password)
            print(message)
        elif choice == '2':
            auth_username = input("Enter username: ")
            auth_password = input("Enter password: ")
            success, message = authenticate_user(auth_username, auth_password)
            print(message)
        elif choice == '3':
            break
        else:
            print("Invalid choice. Please try again.")

    print("Exiting.")