## NetWeaver - Multi-Protocol Server GUI

NetWeaver is a versatile, multi-threaded server application with a Tkinter-based Graphical User Interface (GUI). It allows you to run various types of servers (TCP, Web, HTTPS, FTP) from a single application, providing logging, network status monitoring, and robust user management with Role-Based Access Control (RBAC) and encrypted settings.

## 📝  Table of Contents


- [✨ Features](#-features)
  - [Modes](#tcp-server)
  - [User Management & RBAC](#user-management--rbac)
- [🚀 Getting Started](#-getting-started)
  - [Prerequisites](#prerequisites)
- [📦 Installation](#-installation)
- [▶️ Running the Application](#-running-the-application)
- [🔐 Initial Login & User Management](#-initial-login--user-management)
  - [Admin](#admin)
  - [Operator](#operator)
  - [Guest](#guest)
  - [Important](#important)
- [🖥️ Using the Application GUI](#-using-the-application-gui)
- [🛑 Shutting Down](#-shutting-down)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

## ✨ Features

### Multi-Protocol Support: Run servers in different modes:

### TCP Server:
       
          For basic client-server communication.
          
### Web Server (HTTP):
        
        Serve static web content from a specified root directory (supports index.html by default).

### HTTPS Server:
  
        Secure web serving with SSL/TLS encryption (requires certificate and key files).
        
### FTP Server:

        Basic FTP functionality for file transfer (LIST, RETR, STOR, CWD, PWD, PORT, PASV).

### User Management & RBAC:

        Secure user authentication with password hashing (bcrypt) and encryption (Fernet).

        Role-Based Access Control (RBAC) with predefined roles: admin, operator, guest.

        Admin users can add, delete, update passwords, and manage roles for other users.

        Operator users have restricted access.

        Guest users have limited access (can view logs and network status).

        Brute-force prevention with account lockout after multiple failed login attempts.

    Persistent Settings: Server configurations (port, mode, root directories, SSL files, max connections) are saved and loaded securely from an encrypted settings.json file.

    Network Status Monitoring: View the server's IP address, port, active connections, and data transfer rate.

    Threaded Operations: Server operations run in separate threads to keep the GUI responsive.

## 🚀 Getting Started

Follow these instructions to set up and run the NetWeaver application.

### Prerequisites

    Python 3.x installed on your system.

    pip (Python package installer)

## 📦 Installation

To prepare your environment and install all necessary Python dependencies, use the provided install_dependencies.sh script.

    Navigate to the project directory: Open your terminal or command prompt and change your current directory to where the NetWeaver files are located.

    cd NetWeaver2/

    Make the script executable: If the script is not already executable, run the following command:

    chmod +x install_dependencies.sh

    Run the installation script: Execute the script to create a virtual environment and install dependencies:

    ./install_dependencies.sh

    This script will:

        Check for Python 3.

        Create a virtual environment named venv (if it doesn't exist).

        Activate the venv.

        Install Pillow, bcrypt, and cryptography libraries.

    You will see colored output in your terminal indicating the progress.

## ▶️ Running the Application

After successful installation, you can launch NetWeaver:

    Ensure virtual environment is activated: If you closed your terminal or the environment deactivated, you can reactivate it by running:

    source venv/bin/activate

    Start the GUI application:

    python main.py

## 🔐 Initial Login & User Management

Upon the first run, NetWeaver will automatically create some default users if users.json is not found or an admin user is missing.

Default Credentials (First Run):

### Admin:

        Username: admin
        
        Password: admin
        
        Role: admin

### Operator:
        
        Username: operator
        
        Password: operator_pass
        
        Role: operator

### Guest:

        Username: guest
        
        Password: guest_pass
        
        Role: guest

### Important: 

      For security, change these default passwords immediately after your first login as an admin.

Login Window

You will be presented with a login screen. Enter the username and password for one of the default accounts. You can also register a new guest user from this screen.
User Roles and Permissions

NetWeaver implements RBAC to control access to various GUI functionalities:

### Admin (admin role):

        Can start and stop the server.

        Can configure all server settings (port, mode, root directories, SSL files, max connections).

        Can manage users (add, delete, update passwords, and change roles).

        Can view logs and network status.

        Has access to all tabs in the GUI.

### Operator (operator role):

        Cannot start or stop the server.

        Cannot change server settings (entries are disabled).

        Cannot manage users.

        Can view logs, network status, and server settings.

        Has access to "Server Log", "Network Status", and "Server Settings" tabs.

### Guest (guest role):

        Cannot start or stop the server.

        Cannot change server settings.

        Cannot manage users.

        Can only view logs and network status.

        Has access only to "Server Log" and "Network Status" tabs.

## 🖥️ Using the Application GUI

After logging in, the main NetWeaver GUI will appear.
Sidebar (Left Pane)

    Server Control: Displays current server status (Stopped/Running) and the logged-in user's role.

    Port: Set the port for the server to listen on.

    Start Server / Stop Server: Buttons to control the server's lifecycle (Admin only).

    Server Mode: Select the desired server type (TCP, Web, HTTPS, FTP). Selecting a mode will dynamically show relevant settings in the "Server Settings" tab.

    Navigation Buttons: Quick access to different tabs: "Settings", "Logs", "User Management", "Network Status".

Main Content Area (Right Pane - Tabs)
1. Server Log Tab

    Displays real-time logs from the server operations, client connections, and errors.

    Messages are color-coded for easy identification:

        White/Grey: Information

        Green: Success

        Gold: Warning

        Red: Error

2. Server Settings Tab

    Max Concurrent Connections: Set the maximum number of simultaneous client connections the server can handle.

    Mode-Specific Settings:

        Web/HTTPS Mode: Configure the Web Root Directory from which static files will be served.

        HTTPS Mode: Specify paths for your SSL Certificate File and SSL Key File (both in .pem format).

        FTP Mode: Define the FTP Root Directory for file transfers.

    Use the "Browse" buttons to easily select directories or files.

    Note: Changes here are automatically saved and loaded on subsequent runs. These settings can only be changed by an admin user when the server is stopped.

3. User Management Tab

    User List: A table displaying all registered usernames and their assigned roles.

    User Actions:

        Username / Password: Input fields for user credentials.

        Role: A dropdown to select the role (admin, operator, guest) for new users or when updating a user's role.

        Add User: Register a new user with the specified username, password, and role.

        Update Password: Change the password for a selected user.

        Delete User: Remove a selected user from the system.

        Update Role: Change the role of a selected user.

    Note: All user management actions are restricted to admin users.

4. Network Status Tab

    Server IP Address: Displays the local IP address of the server.

    Server Port: Shows the currently configured server port.

    Active Connections: Monitors the number of active client connections.

    Data Transfer Rate (KB/s): A placeholder for future implementation of real-time data transfer metrics.

## 🛑 Shutting Down

To properly shut down NetWeaver, simply close the application window. You will be prompted to confirm if you wish to quit. The application will attempt to stop the server gracefully and save any current settings before exiting.

## 🤝 Contributing

Contributions are welcome! If you have suggestions for improvements or new features, please feel free to open an issue or submit a pull request.

## 📄 License

This project is licensed under The Unlicense.
