import json
from cryptography.fernet import Fernet
import os

# --- Configuration ---
# The path to your encrypted user data file
USER_DATA_FILE = 'users.json' 
# The encryption key you provided. 
# Make sure this is the exact key used to encrypt your users.json file.
# Note: For security, never hardcode sensitive keys in production code.
# This is for a one-off decryption task.
ENCRYPTION_KEY = b"<encryption key>" # Change this !!!
# Ensure the key is a bytes object (prefix with 'b')

# --- Decryption Logic ---
def decrypt_users_file(file_path, key):
    """
    Decrypts the users.json file using the provided Fernet key.
    
    Args:
        file_path (str): The path to the encrypted users.json file.
        key (bytes): The Fernet encryption key as bytes.
        
    Returns:
        dict: The decrypted user data as a Python dictionary.
        None: If decryption fails or the file doesn't exist/is empty.
    """
    if not os.path.exists(file_path):
        print(f"Error: File '{file_path}' not found.")
        return None

    try:
        cipher_suite = Fernet(key)
        
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
            
        if not encrypted_data:
            print("Warning: users.json file is empty. Returning empty data.")
            return {}

        decrypted_data = cipher_suite.decrypt(encrypted_data)
        users = json.loads(decrypted_data.decode('utf-8'))
        return users
        
    except Exception as e:
        print(f"Error during decryption or JSON parsing: {e}")
        print("Please ensure the key is correct and the file is not corrupted.")
        return None

if __name__ == "__main__":
    print(f"Attempting to decrypt '{USER_DATA_FILE}' with the provided key...")
    decrypted_users = decrypt_users_file(USER_DATA_FILE, ENCRYPTION_KEY)

    if decrypted_users is not None:
        print("\n--- Decrypted User Data ---")
        print(json.dumps(decrypted_users, indent=4))
        print("\n---------------------------\n")
    else:
        print("\nDecryption failed.")

    print("Remember to handle decrypted data securely. Do not leave sensitive information exposed.")