import json
from cryptography.fernet import Fernet
import os

# --- Configuration ---
# The path to your user data file (will be overwritten with encrypted data)
USER_DATA_FILE = 'users.json' 
# The encryption key. This MUST be the same key used for decryption.
ENCRYPTION_KEY = b"<encryption key>" # Change this !!! 
# Ensure the key is a bytes object (prefix with 'b')

# --- Encryption Logic ---
def encrypt_and_save_users_file(users_data, file_path, key):
    """
    Encrypts the provided user data and saves it to the specified file.
    
    Args:
        users_data (dict): The plaintext user data as a Python dictionary.
        file_path (str): The path where the encrypted users.json file will be saved.
        key (bytes): The Fernet encryption key as bytes.
        
    Returns:
        bool: True if encryption and saving were successful, False otherwise.
    """
    try:
        cipher_suite = Fernet(key)
        
        # Convert the dictionary back to a JSON string and encode to bytes
        plain_text_data = json.dumps(users_data, indent=4).encode('utf-8')
        
        # Encrypt the data
        encrypted_data = cipher_suite.encrypt(plain_text_data)
        
        # Save the encrypted data to the file
        with open(file_path, 'wb') as f: # Write as binary
            f.write(encrypted_data)
            
        print(f"Successfully encrypted and saved data to '{file_path}'.")
        return True
        
    except Exception as e:
        print(f"Error during encryption or saving file: {e}")
        print("Please ensure the key is correct and the data is valid JSON.")
        return False

if __name__ == "__main__":
    print("--- User Data Encryption Utility ---")
    
    decrypted_input_file = input("Enter the path to the plaintext (decrypted) JSON file to encrypt: ")
    modified_users = None

    if os.path.exists(decrypted_input_file):
        try:
            with open(decrypted_input_file, 'r', encoding='utf-8') as f:
                modified_users = json.load(f)
            print(f"Loaded data from '{decrypted_input_file}'.")
        except json.JSONDecodeError:
            print(f"Error: '{decrypted_input_file}' is not a valid JSON file. Please check its content.")
        except Exception as e:
            print(f"An unexpected error occurred while reading '{decrypted_input_file}': {e}")
    else:
        print(f"Error: File '{decrypted_input_file}' not found.")
        print("Please ensure you provide the correct path to your plaintext JSON file.")

    if modified_users is not None:
        print(f"\nAttempting to encrypt data from '{decrypted_input_file}' and save to '{USER_DATA_FILE}'...")
        encrypt_and_save_users_file(modified_users, USER_DATA_FILE, ENCRYPTION_KEY)
    else:
        print("No valid data to encrypt. Encryption aborted.")

    print("\nRemember to handle decrypted data securely. Do not leave sensitive information exposed.")
