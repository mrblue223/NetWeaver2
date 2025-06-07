import bcrypt
import json
import os
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
    """Loads user data from the encrypted JSON file."""
    cipher_suite = _get_cipher_suite() # Ensure cipher_suite is initialized
    if not os.path.exists(USER_DATA_FILE):
        return {}
    with open(USER_DATA_FILE, 'rb') as f: # Read as binary
        encrypted_data = f.read()
        if not encrypted_data:
            return {} # Return empty dict if file is empty

        try:
            decrypted_data = cipher_suite.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode('utf-8'))
        except Exception as e:
            # In a GUI application, consider using a logging callback instead of print
            print(f"Error decrypting or decoding user data: {e}")
            return {} # Return empty dict if decryption fails or data is corrupted

def _save_users(users):
    """Saves user data to the encrypted JSON file."""
    cipher_suite = _get_cipher_suite() # Ensure cipher_suite is initialized
    plain_text_data = json.dumps(users, indent=4).encode('utf-8')
    encrypted_data = cipher_suite.encrypt(plain_text_data)
    with open(USER_DATA_FILE, 'wb') as f: # Write as binary
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
        # This can happen if the hashed_password is not a valid bcrypt hash
        return False

def add_user(username, password):
    """Adds a new user to the system."""
    global _key_was_newly_generated_this_session
    
    # This call will implicitly trigger _get_cipher_suite() and _load_or_generate_key()
    # if they haven't been called yet in this session, setting _key_was_newly_generated_this_session.
    users = _load_users() 
    
    if username in users:
        return False, "Username already exists."
    
    users[username] = hash_password(password)
    _save_users(users)

    # Print the key generation message ONLY if a new key was generated
    # in this session and this is the first time we're acknowledging it.
    if _key_was_newly_generated_this_session:
        print(f"Encryption key generated and saved to '{KEY_FILE}'. Keep this file secure!")
        # Reset the flag to ensure the message is not printed again in the same session.
        _key_was_newly_generated_this_session = False
        return True, "User added successfully. Encryption key generated."
    
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
