import tkinter as tk

# Global flags and variables
SERVER_RUNNING = False
SERVER_SOCKET = None
SERVER_MODE = "tcp"
WEB_ROOT_DIR = ""
FTP_ROOT_DIR = ""
SSL_CERT_FILE = ""
SSL_KEY_FILE = ""

# Theme settings
BG_DARK_PRIMARY = '#21252b'  # Main background color
BG_DARK_SECONDARY = '#2c313a'  # Background for frames/sidebar
BG_DARK_TERTIARY = '#1a1d21'  # Darkest for log area
TEXT_COLOR = '#abb2bf'  # Light grey text
ACCENT_BLUE = '#61afef'  # Primary accent blue
ACCENT_BLUE_HOVER = '#528bff'  # Darker blue for hover
BUTTON_TEXT_COLOR = 'white'  # White for button text
DISABLED_COLOR = '#4b525d'  # Grey for disabled elements
BORDER_COLOR = '#3e4452'  # Subtle border color