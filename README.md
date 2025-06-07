## NetWeaver2 | Multi-Protocol Server GUI

NetWeaver is a versatile, multi-threaded server application equipped with an intuitive graphical user interface (GUI) built using Tkinter. It empowers users to host and manage various network services directly from their desktop, supporting TCP, Web (HTTP/HTTPS), and FTP protocols.
Features

    Multi-Protocol Support: Host TCP, HTTP, HTTPS, and FTP services.

    User Management: Securely manage user accounts with bcrypt password hashing for application access.

    Intuitive GUI: A modern, dark-themed interface for easy server control, configuration, and monitoring.

    Real-time Logging: View detailed server activity and connection logs directly within the application.

    Dynamic Settings: Configure server parameters like ports, web root directories, FTP root directories, and SSL certificates through the GUI.

    Network Status: Monitor the server's local IP address and active port.

## Installation

It is recommended to use a virtual environment to manage NetWeaver's dependencies.

    Activate the Virtual Environment:
    If you have already created a virtual environment named venv in your project directory:

        On Windows:

        .\venv\Scripts\activate


        On macOS/Linux:

        source venv/bin/activate


    You will see (venv) pre-pended to your terminal prompt, indicating the virtual environment is active.

    Deactivate the Virtual Environment (when you're done working with NetWeaver):
    Simply type:

    deactivate


    This will exit the virtual environment.

## Usage

Running the Application

To start NetWeaver, ensure your virtual environment is activated, then navigate to the project directory in your terminal and run the main.py file:

python main.py


Initial Login (IMPORTANT SECURITY NOTE!)

Upon launching NetWeaver, you will be presented with a login screen.

DEFAULT CREDENTIALS: For first-time use are in users.json, the default administrative username and password are:

    Username: admin

    Password: admin

## SECURITY RECOMMENDATION:

It is HIGHLY recommended that you immediately delete the users.json file (if it exists) and register a new, strong username and password for the application's login to ensure security. The users.json file stores hashed user credentials.

After logging in, the main NetWeaver GUI will appear.
Navigating the GUI

The main GUI consists of a sidebar for server controls and a tabbed area for different functionalities:

    Server Control (Sidebar):

        Status: Displays if the server is Running or Stopped.

        Port: Set the port for the server to listen on.

        Start Server / Stop Server: Buttons to control the server's operation.

        Server Mode: Radio buttons to select the desired protocol (TCP, Web, HTTPS, FTP).

        Navigation Buttons: Quick links to the "Settings", "Logs", "User Management", and "Network Status" tabs.

    Server Log Tab: Shows real-time activity and error messages from the server.

    Server Settings Tab: Provides mode-specific configuration options (e.g., Web Root Directory, SSL certificate paths, FTP Root Directory).

    User Management Tab: Allows you to add new users and test user authentication for the application's login.

    Network Status Tab: Displays the server's local IP address and the currently active port.

## Starting and Stopping the Server

    Select a Server Mode: Choose between TCP, web(HTTP), HTTPS, or FTP using the buttons in the sidebar.

    Configure Settings (if necessary): If you select Web, HTTPS, or FTP mode, switch to the "Server Settings" tab and specify the required directories (Web Root, FTP Root) and SSL certificate/key files for HTTPS. Use the "Browse" buttons to easily select paths.

    Set the Port: Enter the desired port number (e.g., 8080 for web, 21 for FTP) in the "Port" entry.

    Start Server: Click the "Start Server" button. The server status will change to "Running".

    Stop Server: Click the "Stop Server" button to shut down the active server.

## Server Modes

TCP Server

A basic TCP server that listens for incoming connections and sends a simple "ACK!" response to any received data.
Web Server (HTTP)

Serves static files from the specified "Web Root Directory" over HTTP. Supports basic GET requests and serves index.html by default for directory requests. Includes basic directory traversal protection.
HTTPS Server

Extends the Web Server functionality by encrypting communication using SSL/TLS. Requires valid SSL certificate (.crt or .pem) and key (.key or .pem) files. These must be selected in the "Server Settings" tab.
FTP Server

A simple FTP server that allows clients to connect, authenticate, list directories, and transfer files (RETR for download, STOR for upload).

    Default FTP Protocol Credentials: For the FTP protocol itself (not the GUI login), the server currently uses hardcoded credentials:

        Username: ftpuser

        Password: ftppass

    FTP Root Directory: Files will be served from and stored in the specified "FTP Root Directory".

Contributing

Feel free to fork the repository, open issues, and submit pull requests.
License

This project is released under The Unlicense. For more details, see https://unlicense.org/
