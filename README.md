## NetWeaver2

NetWeaver is a powerful and user-friendly server application built with Python's Tkinter GUI framework. It's designed to simplify the process of setting up and managing various network servers, including basic TCP, HTTP Web servers, secure HTTPS servers, and FTP servers. With its intuitive dark-themed interface, real-time monitoring, and robust security features like Role-Based Access Control and brute-force protection, NetWeaver provides a comprehensive solution for your local server needs.

## Table of Contents
- [Pictures](#Pictures)
- [Features](#Features)
- [Setup and Installation](#Setup-and-Installation)
- [Usage](#Usage)
- [File Structure (Key Files)](#File-Structure-(Key-Files))
- [Contributing](#Contributing)

## Pictures

![login_page.png](login_page.png)

![Netweaver2_page.png](Netweaver2_page.png)

## Features

NetWeaver offers a rich set of functionalities to enhance your server management experience:
1. Multi-Mode Server Operation

NetWeaver supports four distinct server modes, configurable via the GUI:

    TCP Server:

        Purpose: Establishes a raw TCP socket server. Ideal for custom client-server applications that require direct byte-stream communication.

        Functionality: Listens for incoming TCP connections and can be configured to handle them according to custom logic (implemented in tcp_handler.py).

    Web Server (HTTP):

        Purpose: Serves static web content (HTML, CSS, JavaScript, images) over HTTP.

        Functionality: Allows you to designate a "Web Root Directory" where your website files are stored. When clients request files, the server fetches them from this directory and sends them back.

    HTTPS Server:

        Purpose: A secure version of the Web Server, using SSL/TLS encryption for all communications. Essential for serving content where data privacy is critical.

        Functionality: Requires valid SSL certificate (.pem or .crt) and key (.pem or .key) files. All data exchanged between the server and clients is encrypted, protecting against eavesdropping and tampering.

    FTP Server:

        Purpose: Facilitates file transfers between the server and FTP clients.

        Functionality: Designate an "FTP Root Directory" from which files can be uploaded to or downloaded from the server. Includes basic FTP commands for navigation and file operations. Default login: ftpuser / ftppass.

2. Intuitive Graphical User Interface (GUI)

The NetWeaver GUI is built with Tkinter, offering a modern and responsive user experience:

    Modern Dark Theme: Enjoy a visually appealing interface designed for readability and comfort, especially during extended use.

    Centralized Server Control: Start and stop any server mode with dedicated buttons.

    Configurable Settings: Easily adjust server parameters such as the listening Port and Max Concurrent Connections directly from the GUI.

    Dynamic Mode Selection: Switch between server modes effortlessly using intuitive radio buttons. The settings interface adapts dynamically to show only relevant configuration options for the selected mode.

    Real-time Activity Log: A dedicated "Server Log" tab provides continuous, color-coded feedback on server operations, client connections, and any warnings or errors encountered.

    Network Status Monitoring: The "Network Status" tab displays real-time information, including the server's IP address, current port, the number of active client connections, and a placeholder for data transfer rates.

    Persistent Configuration: All your server settings (port, chosen mode, directory paths, SSL file paths, max connections) are automatically saved to settings.json upon changes and loaded on application startup, so your configurations persist across sessions.

3. Role-Based Access Control (RBAC)

NetWeaver implements a robust RBAC system to ensure secure management and operation, assigning distinct permissions based on user roles:
Defined Roles:

    admin (Administrator):

        Full Control: Has unrestricted access to all features.

        Server Operations: Can start and stop the server.

        Configuration: Can modify all server settings (port, server mode, root directories, SSL files, max connections).

        User Management: Possesses complete administrative rights within the "User Management" tab, allowing them to add, delete, update passwords, and assign/change roles for any user.

        Monitoring: Can view server logs and network status.

        This is the primary role for server setup, maintenance, and user administration.

    operator (Operator):

        Operational Access: Can monitor server activities but has limited operational control.

        Server Operations: Cannot start or stop the server.

        Configuration: Cannot modify any server settings.

        User Management: Has no access to user management functionalities.

        Monitoring: Can view server logs and network status.

        This role is ideal for individuals responsible for monitoring server health and performance without the ability to alter critical configurations or user accounts.

    guest (Guest):

        Read-Only Access: The most restrictive role, providing basic visibility.

        Server Operations: Cannot start or stop the server.

        Configuration: Cannot modify any server settings.

        User Management: Has no access to user management functionalities.

        Monitoring: Can only view server logs and network status.

        Suitable for general oversight or informational purposes, where interaction with server controls is not required.

GUI Integration for RBAC:

The GUI intelligently adapts to the logged-in user's role:

    Dynamic Button States: Interactive elements like "Start Server," "Stop Server," and settings fields are dynamically enabled or disabled.

    Tab Access Control: The "User Management" and "Server Settings" tabs might be disabled or hidden for roles that don't have permission to access them, ensuring a clean and secure interface.

    Role Display: The sidebar prominently displays the role of the currently logged-in user.

4. Brute-Force Protection

To safeguard against unauthorized access attempts, the login system includes a brute-force prevention mechanism:

    Failed Attempt Limit: If a user attempts to log in unsuccessfully 3 times consecutively for a specific username.

    Temporary Account Lockout: The system will temporarily lock out that user account.

    Lockout Duration: The user will be unable to attempt login for that username for a period of 5 minutes.

    User Feedback: The login screen provides clear messages, informing the user about the lockout and the remaining time until they can try again.

5. User Management via GUI (Admin Only)

The "User Management" tab, exclusively accessible to admin users, provides comprehensive tools for managing accounts:

    Add New Users: Create new user accounts, assigning their initial role (admin, operator, or guest) directly from the GUI.

    Delete Existing Users: Securely remove any user account from the system.

    Update User Passwords: Change passwords for existing users.

    Update User Roles: Modify the role of any existing user (e.g., promoting a guest to an operator or admin).

    User List: A table displays all registered users along with their assigned roles, offering a clear overview.

6. Initial Administrator Setup

For ease of first-time setup or recovery scenarios:

    A temporary safety mechanism in user.py checks for the presence of an admin user.

    If no user with the admin role is found in users.json, the application will automatically create a default admin user with the username admin and password admin, assigning it the admin role.

    Important Recommendation: After successfully logging in as admin:admin and confirming full administrative access, it is highly recommended to remove this temporary code block from the if __name__ == "__main__": section of user.py. This prevents it from automatically re-creating the default admin on every startup and potentially interfering with your custom user setup.

7. User Data Encryption/Decryption Utilities

To ensure the security of sensitive user information (like hashed passwords and roles) stored in users.json, the file is encrypted. For scenarios requiring manual inspection or modification of this data, two command-line utility scripts are provided:

    decrypt_users.py:

        Purpose: To decrypt the users.json file into its human-readable plaintext JSON format.

        Usage: Run this script from your terminal. It will read users.json and print the decrypted content to your console.

        Workflow: You should copy this printed output and paste it into a new temporary file (e.g., users.json.decrypted). This temporary file is where you will make your edits.

    encrypt_users.py:

        Purpose: To encrypt a plaintext JSON file (containing user data you've modified) back into the users.json file, overwriting the existing encrypted data.

        Usage: Run this script from the command line. It will prompt you to enter the path to the plaintext JSON file you wish to encrypt.

        Critical Note: Ensure you use the exact same ENCRYPTION_KEY across both decryption and encryption processes. Also, verify that the plaintext JSON file you're encrypting is structurally valid to avoid errors.

Security Advisory: Always handle decrypted user data with extreme caution. Delete any temporary plaintext files (like users.json.decrypted) immediately after you have successfully re-encrypted your users.json file.

## Setup and Installation

To get NetWeaver up and running on your system, follow these detailed steps:

    Prerequisites:

        Python 3.x: Ensure you have Python 3.6 or newer installed. You can download it from python.org.

        pip: Python's package installer, which usually comes bundled with Python installations.

    Download the Project:

        Obtain the NetWeaver project files. If it's a Git repository, you can clone it:

        git clone <repository_url>
        cd NetWeaver

        Otherwise, download the zip archive and extract it to your desired location.

    Create and Activate a Virtual Environment (Highly Recommended):
    Using a virtual environment is crucial for managing project-specific dependencies. It isolates the libraries needed for NetWeaver from other Python projects, preventing conflicts.

        Navigate to your project directory: Open your terminal or command prompt and change your current directory to the root of the NetWeaver project (where main.py is located).

        Create the virtual environment:

        python -m venv venv

        This command creates a new directory named venv (you can choose another name) containing the Python executable and pip.

        Activate the virtual environment:

            On Windows (Command Prompt):

            .\venv\Scripts\activate

            On Windows (PowerShell):

            .\venv\Scripts\Activate.ps1

            On macOS/Linux:

            source venv/bin/activate

        Once activated, your terminal prompt will usually show (venv) at the beginning, indicating that you are now working within the isolated environment.

    Install Dependencies:
    With your virtual environment active, install the necessary Python libraries using pip:

    pip install pillow bcrypt cryptography

        Pillow: Used for image processing, specifically for loading the application icon.

        bcrypt: Provides secure password hashing for user authentication.

        cryptography: Enables strong encryption (Fernet symmetric encryption) for your users.json file.

        Note: tkinter is part of Python's standard library and typically does not require a separate pip install.

    Prepare Directory Structure (for Web/FTP/HTTPS modes):

        Web and FTP Roots: For the Web (HTTP/HTTPS) and FTP server modes, you need dedicated directories to serve files from. Create empty folders named web_root and ftp_root directly within your main NetWeaver project directory.

        NetWeaver/
        ├── main.py
        ├── gui.py
        ├── server_core.py
        ├── user.py
        ├── constants.py
        ├── tcp_handler.py
        ├── web_handler.py
        ├── ftp_handler.py
        ├── users.json
        ├── settings.json
        ├── encryption_key.key
        ├── decrypt_users.py
        ├── encrypt_users.py
        ├── assets/
        │   └── icons8-server-40.png
        ├── venv/
        ├── web_root/  <-- Create this
        └── ftp_root/  <-- Create this

        SSL/TLS Files (for HTTPS): If you plan to use the HTTPS server, you will need an SSL certificate file (e.g., server.crt or server.pem) and its corresponding private key file (e.g., server.key or server.pem). You can generate self-signed certificates for testing or obtain them from a Certificate Authority. Place these files in a secure location and specify their full paths in the GUI's "Server Settings" tab when configuring HTTPS mode.

    Initial Administrator User:

        The first time you run main.py (or if your users.json file is deleted), the application will automatically create a default administrator account.

        Username: admin

        Password: admin

        You will use these credentials to log in and gain full administrative privileges to manage the server and other users.

        Important: After successfully logging in as admin:admin and verifying that you can start/stop the server and manage users, it is highly recommended to remove the temporary code block from the if __name__ == "__main__": section of user.py. This prevents the default admin from being recreated on every startup, which could overwrite any custom admin users you create or pose a minor security risk in a production environment.

## Usage

Once NetWeaver is set up and its dependencies are installed within your virtual environment, you can start using it:

    Start the Application:

        Ensure your virtual environment is active (you should see (venv) in your terminal prompt).

        From your project's root directory, run the main script:

        python main.py

        The NetWeaver login window will appear.

    Login:

        Enter your username and password. For the initial setup, use admin for both.

        Click the "Login" button.

        If authentication is successful, the main NetWeaver GUI window will appear.

        If you make too many failed attempts, the brute-force protection will temporarily lock the account.

        You can also click "Register" to create new guest users directly from this screen.

    Navigate the GUI:
    The main GUI is divided into a left sidebar for server control and management, and a main content area with tabs for different functionalities:

        Sidebar (Server Control):

            Logged in as: Displays your current username and assigned role (e.g., Role: ADMIN).

            Status: Shows whether the server is "Running" or "Stopped".

            Port: Enter the port number for the server to listen on (e.g., 8080).

            Start Server / Stop Server: Buttons to control the server's operational state. These are only enabled for admin users.

            Server Mode: Select your desired server type:

                TCP

                Web (HTTP)

                HTTPS

                FTP

                Changing the mode will dynamically update the "Server Settings" tab to show relevant options.

        Main Content Tabs:

            Server Log: Provides a live stream of server events, including connection attempts, data transfers, and system messages, categorized by color (info, success, warning, error).

            Server Settings: This tab allows you to configure specific parameters for each server mode:

                Max Concurrent Connections: Set the maximum number of clients that can connect simultaneously.

                Web/HTTPS Mode: Specify the Web Root Directory by typing the path or using the "Browse Web Root" button. This is where your web files will be located.

                HTTPS Mode Only: Provide the full paths to your SSL Certificate File and SSL Key File using the respective "Browse" buttons.

                FTP Mode: Specify the FTP Root Directory using the "Browse FTP Root" button. This will be the home directory for FTP users.

                Note: All fields and browse buttons in the "Server Settings" tab are only editable by admin users.

            User Management: (Accessible only by admin users) This is where you manage user accounts:

                The main area displays a table of all registered users, showing their Username and Role.

                Add User:

                    Enter a desired Username and Password in the input fields.

                    Select the Role (admin, operator, or guest) for the new user from the dropdown.

                    Click the "Add User" button.

                Update Password:

                    Select a user from the table.

                    Enter a new Password in the input field.

                    Click the "Update Password" button.

                Update Role:

                    Select a user from the table.

                    Choose the desired Role (admin, operator, or guest) from the dropdown.

                    Click the "Update Role" button.

                Delete User:

                    Select a user from the table.

                    Click the "Delete User" button. A confirmation dialog will appear.

            Network Status: Displays live network metrics:

                Server IP Address: Your machine's local IP address.

                Server Port: The port the server is currently listening on.

                Active Connections: The number of currently active client connections.

                Data Transfer Rate (KB/s): A placeholder for future implementation of real-time data transfer statistics.

    Closing the Application:

        To safely exit NetWeaver, close the main GUI window using the 'X' button or by pressing Alt+F4 (Windows).

        A confirmation dialog will appear. If the server is running, it will attempt a graceful shutdown before the application closes.

## File Structure (Key Files)

Here's an overview of the main files and their roles in the NetWeaver project:

    main.py: The application's entry point. It initializes the Tkinter root window, handles the login process, and launches the TCPServerGUI.

    gui.py: Contains the core GUI logic, including the TCPServerGUI class (for the main application window) and the LoginWindow class. It manages all widgets, layouts, and GUI-driven interactions with the backend.

    server_core.py: The heart of the server functionality. This module handles the creation, binding, listening, and acceptance of network sockets for all server modes. It spawns threads for client handling.

    user.py: Dedicated to user management. It handles user registration, authentication, password hashing using bcrypt, role assignment, and the encryption/decryption of users.json using cryptography's Fernet. Also includes the brute-force protection logic.

    constants.py: A central place for application-wide constants, such as theme colors, default server parameters, and placeholder values for network status.

    tcp_handler.py: Contains the logic for handling individual client connections when the server is operating in TCP mode.

    web_handler.py: Implements the HTTP/HTTPS request handling, including parsing HTTP requests, serving files from the web root, and sending appropriate HTTP responses.

    ftp_handler.py: Manages the FTP protocol, handling FTP commands (e.g., USER, PASS, PORT, PASV, RETR, STOR) and file transfers for FTP clients.

    users.json: This file stores all registered user accounts, their hashed passwords, and assigned roles. It is encrypted for security.

    settings.json: Stores the last-used server settings (port, mode, directory paths, SSL file paths, etc.) for persistence across sessions.

    encryption_key.key: A binary file that holds the Fernet encryption key used to encrypt and decrypt users.json. It is absolutely critical to keep this file secure and private! If this key is lost or compromised, your users.json data cannot be decrypted, and your user accounts may become inaccessible or vulnerable.

    decrypt_users.py (Utility): A standalone Python script designed to decrypt the users.json file to a human-readable format. Useful for debugging or manual modifications.

    encrypt_users.py (Utility): A standalone Python script designed to encrypt a plaintext user data file back into users.json. Essential after manually modifying decrypted user data.

    assets/: A directory containing static assets, primarily the application icon (icons8-server-40.png).

## Contributing

We welcome contributions to the NetWeaver project! If you encounter any bugs, have suggestions for new features, or would like to improve the existing codebase, please feel free to:

    Report issues through the GitHub Issues tracker.

    Submit feature requests or ideas.

    Fork the repository and submit pull requests with your changes.

License

This project is licensed under The Unlicense. This means you are free to use, modify, distribute, and even sell the software, without any restrictions.
