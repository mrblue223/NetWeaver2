## NetWeaver - Password Recovery Process

This guide outlines the steps to recover or reset a forgotten password for any user account in NetWeaver. This process involves directly manipulating the encrypted users.json file using the provided utility scripts.

## IMPORTANT SECURITY NOTICE:
This recovery method requires direct access to your project files and the encryption key (encryption_key.key). Handling decrypted user data, especially passwords (even if hashed), introduces a security risk. Ensure you perform these steps in a secure environment and delete any temporary plaintext files immediately after the process is complete.
Prerequisites

Before starting the recovery process, ensure you have:

    Access to your NetWeaver project directory and all its files.

    The encryption_key.key file. This file is absolutely critical for decrypting your user data. Without it, recovery is impossible.

    The decrypt_users.py utility script.

    The encrypt_users.py utility script.

    A text editor capable of editing JSON files (e.g., VS Code, Notepad++, Sublime Text).

    Your Python virtual environment activated.

## Password Recovery Steps

Follow these steps carefully to recover or reset a password:
Step 1: Stop the NetWeaver Application

Ensure the NetWeaver GUI application is completely closed before proceeding. If the server is running or the GUI is open, it might overwrite your changes or lock the users.json file.
Step 2: Decrypt the users.json File

This step will convert your encrypted user data into a human-readable JSON format.

    Open your terminal or command prompt and navigate to your NetWeaver project directory.

    Activate your virtual environment (if you haven't already):

        Windows: .\venv\Scripts\activate

        macOS/Linux: source venv/bin/activate

    Run the decryption script:

    python decrypt_users.py 

    The decrypted content will be printed directly to your terminal. It will look like a standard JSON object containing usernames, hashed passwords, and roles.

    Copy this entire decrypted JSON output.

    Paste the copied content into a new file using your text editor. Save this new file in your project directory with a distinct name, for example: users.json.decrypted

        Example of decrypted content structure:

        {
            "admin": {
                "password": "$2b$12$EXAMPLE_HASH_ADMIN_ABCDEF...",
                "role": "admin"
            },
            "operator_user": {
                "password": "$2b$12$EXAMPLE_HASH_OPERATOR_XYZ...",
                "role": "operator"
            },
            "forgotten_user": {
                "password": "$2b$12$EXAMPLE_HASH_FORGOTTEN_USER_123...",
                "role": "guest"
            }
        }

Step 3: Generate a New Hashed Password

To set a new password, you need its hashed version. You can use the user.py script's functionality to generate this hash.

    While still in your activated virtual environment and project directory, you can temporarily add a print statement to user.py or create a small temporary script to generate a hash.

        Option A (Temporary Script - Recommended): Create a new Python file (e.g., generate_hash.py) in your project directory with the following content:

        from user import hash_password

        new_plain_password = input("Enter your NEW desired password: ")
        hashed = hash_password(new_plain_password)
        print(f"Your new hashed password: {hashed}")

        Then, run it: python generate_hash.py

        Option B (Modify user.py temporarily): Open user.py, scroll to the if __name__ == "__main__": block, and temporarily add these lines (or similar) to generate a hash:

        # TEMPORARY HASH GENERATION - REMOVE AFTER USE
        # new_password_to_hash = "mySecretNewPass" # Replace with your actual new password
        # print(f"Hashed password for '{new_password_to_hash}': {hash_password(new_password_to_hash)}")
        # END TEMPORARY

        Then run python user.py (you can exit after it prints the hash).

    Copy the generated hashed password. It will be a long string starting with $2b$....

Step 4: Modify the Decrypted User Data

Now, you will update the password for the desired user in your users.json.decrypted file.

    Open users.json.decrypted (the file you saved in Step 2) in your text editor.

    Locate the user account for which you want to reset the password (e.g., "forgotten_user").

    Replace the existing password hash for that user with the new hash you generated in Step 3.

        Example (changing password for forgotten_user):

        {
            "admin": {
                "password": "$2b$12$EXAMPLE_HASH_ADMIN_ABCDEF...",
                "role": "admin"
            },
            "operator_user": {
                "password": "$2b$12$EXAMPLE_HASH_OPERATOR_XYZ...",
                "role": "operator"
            },
            "forgotten_user": {
                "password": "PASTE_YOUR_NEW_GENERATED_HASH_HERE",  <-- REPLACE THIS
                "role": "guest"
            }
        }

    Save the users.json.decrypted file.

        Double-check: Ensure the JSON structure remains valid (correct commas, braces, quotes). Invalid JSON will cause the encryption step to fail.

Step 5: Encrypt the Modified User Data

This step will encrypt your updated plaintext data and save it back to users.json.

    In your terminal (with the virtual environment still active and in the project directory), run the encryption script:

    python encrypt_users.py

    The script will prompt you: Enter the path to the plaintext (decrypted) JSON file to encrypt: 

    Type or paste the full path to your users.json.decrypted file (e.g., users.json.decrypted) and press Enter.

    The script will encrypt the data and overwrite your existing users.json file. You should see a success message.

Step 6: Clean Up and Restart NetWeaver

    Delete users.json.decrypted: Once encrypt_users.py confirms successful encryption, immediately delete the users.json.decrypted file from your system. This file contains sensitive plaintext data and should not be left exposed.

    Remove temporary hash generation script/code: If you created generate_hash.py or added temporary lines to user.py, remove them.

    Restart NetWeaver: Run python main.py again. You should now be able to log in with the new password for the account you modified.

By following these steps, you can safely recover or reset user passwords in your NetWeaver application.
