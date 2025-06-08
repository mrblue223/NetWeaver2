import bcrypt
import json
import os
import time
from cryptography.fernet import Fernet

# Define the path to the user data file
USER_DATA_FILE = 'users.json'

# Define the path to the encryption key file
KEY_FILE = 'encryption_key.key'

# Global variable to store the Fernet cipher suite instance.
# It will be initialized only once when _get_cipher_suite() is first called.
_cipher_suite_instance = None

# Global flag to track if the encryption key was newly generated in this session.
# This ensures the "key generated" message is printed only once per application run.
_key_was_newly_generated_this_session = False

# Global dictionary to store failed login attempts and lockout times for brute-force prevention
# Format: {username: {'failures': int, 'last_attempt_time': float, 'locked_until': float}}
_login_cooldowns = {}

# Constants for brute-force prevention
MAX_FAILED_ATTEMPTS = 3
LOCKOUT_DURATION_SECONDS = 300 # 5 minutes

# --- RBAC: Role Definitions ---
ROLE_ADMIN = "admin" # Changed from "administrator" to "admin"
ROLE_OPERATOR = "operator"
ROLE_GUEST = "guest"
DEFAULT_NEW_USER_ROLE = ROLE_GUEST # Default role for newly added users
# --- End RBAC Role Definitions ---

def _load_or_generate_key():
    """
    Loads the encryption key from a file, or generates a new one if it doesn't exist.
    Sets the global flag `_key_was_newly_generated_this_session` based on key creation.
    """
    global _key_was_newly_generated_this_session
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            key = f.read()
        _key_was_newly_generated_this_session = False # Key already existed
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
        _key_was_newly_generated_this_session = True # New key was generated
    return key

def _get_cipher_suite():
    """
    Ensures the Fernet cipher suite is initialized and returns it.
    This function will load/generate the key and create the cipher suite
    only once per application run.
    """
    global _cipher_suite_instance
    if _cipher_suite_instance is None:
        encryption_key = _load_or_generate_key()
        _cipher_suite_instance = Fernet(encryption_key)
    return _cipher_suite_instance

def _load_users():
    """
    Loads user data from the encrypted JSON file.
    Handles backward compatibility for users stored without roles.
    """
    cipher_suite = _get_cipher_suite()
    if not os.path.exists(USER_DATA_FILE):
        return {}
    with open(USER_DATA_FILE, 'rb') as f:
        encrypted_data = f.read()
        if not encrypted_data:
            return {}

        try:
            decrypted_data = cipher_suite.decrypt(encrypted_data)
            users = json.loads(decrypted_data.decode('utf-8'))
            
            # --- RBAC: Backward compatibility check ---
            for username, user_data in users.items():
                if isinstance(user_data, str): # Old format: just hashed password
                    users[username] = {
                        "password": user_data,
                        "role": DEFAULT_NEW_USER_ROLE # Assign a default role
                    }
                # Ensure role exists for new structure but potentially missing role key
                elif "role" not in user_data:
                    users[username]["role"] = DEFAULT_NEW_USER_ROLE
            # --- End RBAC compatibility check ---
            
            return users
        except Exception as e:
            print(f"Error decrypting or decoding user data: {e}")
            return {}

def _save_users(users):
    """Saves user data to the encrypted JSON file."""
    cipher_suite = _get_cipher_suite()
    plain_text_data = json.dumps(users, indent=4).encode('utf-8')
    encrypted_data = cipher_suite.encrypt(plain_text_data)
    with open(USER_DATA_FILE, 'wb') as f:
        f.write(encrypted_data)

def hash_password(password):
    """Hashes a password using bcrypt."""
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')

def check_password(password, hashed_password):
    """Checks if a plain password matches a hashed password."""
    try:
        return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))
    except ValueError:
        return False

def add_user(username, password, role=DEFAULT_NEW_USER_ROLE):
    """
    Adds a new user to the system with an assigned role.
    Defaults to ROLE_GUEST if no role is specified.
    """
    global _key_was_newly_generated_this_session
    
    users = _load_users() 
    
    if username in users:
        return False, "Username already exists.", None # Return None for role

    # --- RBAC: Store password and role in a dictionary ---
    users[username] = {
        "password": hash_password(password),
        "role": role
    }
    # --- End RBAC ---
    _save_users(users)

    if _key_was_newly_generated_this_session:
        print(f"Encryption key generated and saved to '{KEY_FILE}'. Keep this file secure!")
        _key_was_newly_generated_this_session = False
        return True, "User added successfully. Encryption key generated.", role
    
    return True, "User added successfully.", role

def authenticate_user(username, password):
    """Authenticates a user with brute-force protection and returns their role."""
    users = _load_users()
    current_time = time.time()

    user_cooldown = _login_cooldowns.get(username, {'failures': 0, 'last_attempt_time': 0, 'locked_until': 0})

    # Check if the user is currently locked out
    if user_cooldown['locked_until'] > current_time:
        remaining_time = int(user_cooldown['locked_until'] - current_time)
        return False, f"Account locked. Try again in {remaining_time // 60} minutes and {remaining_time % 60} seconds.", None

    user_data = users.get(username) # Get the user's dictionary
    if user_data:
        hashed_password = user_data.get("password")
        user_role = user_data.get("role", DEFAULT_NEW_USER_ROLE) # Get role, default if missing
    else:
        hashed_password = None
        user_role = None # No user found, no role

    if hashed_password and check_password(password, hashed_password):
        # Authentication successful, clear any failed attempt records
        if username in _login_cooldowns:
            del _login_cooldowns[username]
        return True, "Authentication successful.", user_role
    else:
        # Authentication failed
        user_cooldown['failures'] += 1
        user_cooldown['last_attempt_time'] = current_time

        if user_cooldown['failures'] >= MAX_FAILED_ATTEMPTS:
            user_cooldown['locked_until'] = current_time + LOCKOUT_DURATION_SECONDS
            user_cooldown['failures'] = 0 # Reset failures after lockout is applied or prevent accumulating
            _login_cooldowns[username] = user_cooldown
            return False, "Too many failed login attempts. Account locked for 5 minutes.", None
        
        _login_cooldowns[username] = user_cooldown
        return False, "Invalid username or password.", None

def delete_user(username):
    """Deletes a user from the system."""
    users = _load_users()
    if username not in users:
        return False, "User not found."
    
    del users[username]
    _save_users(users)
    # Also clear any lockout data if user is deleted
    if username in _login_cooldowns:
        del _login_cooldowns[username]
    return True, "User deleted successfully."

def update_user_password(username, new_password):
    """Updates the password for an existing user."""
    users = _load_users()
    user_data = users.get(username)
    if not user_data:
        return False, "User not found."
    
    # Update password within the user's dictionary
    user_data["password"] = hash_password(new_password)
    users[username] = user_data # Ensure the updated dictionary is put back
    _save_users(users)
    # If password is updated, clear any failed attempt records for this user
    if username in _login_cooldowns:
        del _login_cooldowns[username]
    return True, "Password updated successfully."

def update_user_role(username, new_role):
    """Updates the role for an existing user."""
    users = _load_users()
    user_data = users.get(username)
    if not user_data:
        return False, "User not found."
    
    if new_role not in [ROLE_ADMIN, ROLE_OPERATOR, ROLE_GUEST]:
        return False, "Invalid role specified."

    user_data["role"] = new_role
    users[username] = user_data
    _save_users(users)
    return True, f"Role updated successfully for '{username}' to '{new_role}'."

def get_all_users():
    """Returns a list of all registered usernames and their roles."""
    users = _load_users()
    # Return a list of tuples or dictionaries for clarity, e.g., [(username, role), ...]
    return [(username, user_data.get("role", DEFAULT_NEW_USER_ROLE)) for username, user_data in users.items()]


# Example usage (for testing/initial setup):
if __name__ == "__main__":
    print("--- User Management Utility ---")

    # --- TEMPORARY: Ensure an admin user exists for initial setup ---
    users = _load_users()
    admin_exists = False
    for user_data in users.values():
        if user_data.get("role") == ROLE_ADMIN:
            admin_exists = True
            break
            
    if not admin_exists:
        print("\n[INFO] No 'admin' user found. Creating default 'admin' user with password 'admin'.")
        # Remove existing 'admin' if it has a non-admin role
        if 'admin' in users and users['admin'].get("role") != ROLE_ADMIN:
            print("[INFO] Existing 'admin' user found with non-admin role. Deleting and recreating.")
            delete_user('admin') # Use the delete function to clean up
        
        # Add the 'admin' user with the 'administrator' role
        success, message, role = add_user('admin', 'admin', ROLE_ADMIN)
        if success:
            print(f"[INFO] Default 'admin' user created successfully. Please log in with 'admin'/'admin'.")
        else:
            print(f"[ERROR] Failed to create default 'admin' user: {message}")
    # --- END TEMPORARY BLOCK ---


    while True:
        choice = input("\n(1) Add User, (2) Authenticate User, (3) Delete User, (4) Update Password, (5) List Users, (6) Exit: ")
        if choice == '1':
            new_username = input("Enter new username: ")
            new_password = input("Enter new password: ")
            user_role_input = input(f"Enter role ({ROLE_ADMIN}/{ROLE_OPERATOR}/{ROLE_GUEST}, default: {DEFAULT_NEW_USER_ROLE}): ").strip().lower()
            if user_role_input in [ROLE_ADMIN, ROLE_OPERATOR, ROLE_GUEST]:
                success, message, role = add_user(new_username, new_password, user_role_input)
            else:
                success, message, role = add_user(new_username, new_password) # Use default role
            print(f"{message} (Role: {role})")
        elif choice == '2':
            auth_username = input("Enter username: ")
            auth_password = input("Enter password: ")
            success, message, role = authenticate_user(auth_username, auth_password)
            print(f"{message} (Role: {role})" if role else message)
        elif choice == '3':
            del_username = input("Enter username to delete: ")
            success, message = delete_user(del_username)
            print(message)
        elif choice == '4':
            upd_username = input("Enter username to update password for: ")
            upd_new_password = input("Enter new password: ")
            success, message = update_user_password(upd_username, upd_new_password)
            print(message)
        elif choice == '5':
            users_list = get_all_users()
            if users_list:
                print("Registered Users:")
                for user, role in users_list:
                    print(f"- {user} (Role: {role})")
            else:
                print("No users registered.")
        elif choice == '6':
            break
        else:
            print("Invalid choice. Please try again.")

    print("Exiting.")