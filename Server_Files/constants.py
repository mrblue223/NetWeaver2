import os
import socket # Added for socket.socket, though not strictly needed for just None
             # It's good practice if you plan to initialize it here directly,
             # but setting to None is fine for a global placeholder.

# Constants for the NetWeaver Server GUI

# Theme Colors
BG_DARK_PRIMARY = "#1E1E1E"       # Main background color
BG_DARK_SECONDARY = "#3C3C3C"     # Slightly lighter dark grey for secondary elements
BG_DARK_TERTIARY = "#4A4A4A"      # Even lighter dark grey for text areas
TEXT_COLOR = "#E0E0E0"            # Light grey for general text
ACCENT_BLUE = "#007ACC"           # VS Code-like accent blue
ACCENT_BLUE_HOVER = "#005F99"     # Darker blue for hover states
BUTTON_TEXT_COLOR = "#FFFFFF"     # White for button text

# Server Defaults
SERVER_RUNNING = False
SERVER_MODE = "tcp" # Default server mode: tcp, web, https, ftp
WEB_ROOT_DIR = os.path.join(os.getcwd(), "web_root") # Default web root directory
FTP_ROOT_DIR = os.path.join(os.getcwd(), "ftp_root") # Default FTP root directory
SSL_CERT_FILE = "" # Default SSL certificate file path
SSL_KEY_FILE = ""  # Default SSL key file path
MAX_CONNECTIONS = 10 # Default maximum concurrent connections
SERVER_SOCKET = None # Re-added: Will hold the server's socket object

# Network Status Placeholders (to be updated by server_core)
ACTIVE_CONNECTIONS = 0
DATA_TRANSFER_RATE = 0.0 # in KB/s