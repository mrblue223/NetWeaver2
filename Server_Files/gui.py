import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from PIL import Image, ImageTk
import threading
import time
import os
import socket

import constants
from server_core import _server_main_loop, stop_server
from user import authenticate_user, add_user

class TCPServerGUI:
    """
    A Tkinter-based GUI for a multi-threaded TCP/Web/FTP server.
    Designed with a modern, dark theme.
    """

    def __init__(self, master):
        """
        Initializes the TCPServerGUI.

        Args:
            master (tk.Tk): The root Tkinter window.
        """
        self.master = master
        master.title("NetWeaver - Server GUI")
        master.geometry("1000x700")
        master.resizable(True, True)

        # Set the window icon
        try:
            icon_image = Image.open("assets/icons8-server-40.png")
            self.app_icon = ImageTk.PhotoImage(icon_image)
            master.iconphoto(False, self.app_icon)
        except FileNotFoundError:
            self.log_message(
                "[-] Application icon (icons8-server-40.png) not found.",
                'warning'
            )
        except Exception as e:
            self.log_message(
                f"[-] Error loading application icon: {e}", 'error'
            )

        # --- Configure Modern Dark Theme ---
        self.master.tk_setPalette(background=constants.BG_DARK_PRIMARY,
                                  foreground=constants.TEXT_COLOR,
                                  activeBackground=constants.ACCENT_BLUE_HOVER,
                                  activeForeground=constants.BUTTON_TEXT_COLOR)

        self.style = ttk.Style(self.master) # Store style object
        self.style.theme_use('clam') # 'clam' is a good base for custom styling

        # General styles
        self.style.configure('TFrame', background=constants.BG_DARK_PRIMARY)
        self.style.configure('TLabel', background=constants.BG_DARK_PRIMARY, foreground=constants.TEXT_COLOR, font=('Arial', 10))
        self.style.configure('TButton', background=constants.ACCENT_BLUE, foreground=constants.BUTTON_TEXT_COLOR, font=('Arial', 10, 'bold'))
        self.style.map('TButton',
            background=[('active', constants.ACCENT_BLUE_HOVER)],
            foreground=[('active', constants.BUTTON_TEXT_COLOR)])
        self.style.configure('TEntry', fieldbackground=constants.BG_DARK_SECONDARY, foreground=constants.TEXT_COLOR, insertbackground=constants.ACCENT_BLUE, borderwidth=1, relief='solid')
        self.style.configure('TCheckbutton', background=constants.BG_DARK_PRIMARY, foreground=constants.TEXT_COLOR, font=('Arial', 10))
        # Removed the generic TRadiobutton config here, replaced by specific ones below

        self.style.configure('Horizontal.TScale', background=constants.BG_DARK_PRIMARY, troughcolor=constants.BG_DARK_SECONDARY, foreground=constants.TEXT_COLOR)
        self.style.configure('TNotebook', background=constants.BG_DARK_PRIMARY, borderwidth=0)
        self.style.configure('TNotebook.Tab', background=constants.BG_DARK_SECONDARY, foreground=constants.TEXT_COLOR, font=('Arial', 10))
        self.style.map('TNotebook.Tab', background=[('selected', constants.BG_DARK_PRIMARY)], foreground=[('selected', constants.ACCENT_BLUE)])

        # Scrollbar style
        self.style.configure('TScrollbar',
                        background=constants.BG_DARK_SECONDARY,
                        troughcolor=constants.BG_DARK_PRIMARY,
                        gripcount=0,
                        relief='flat')
        self.style.map('TScrollbar',
                  background=[('active', constants.ACCENT_BLUE)],
                  troughcolor=[('active', constants.BG_DARK_SECONDARY)])

        # --- Specific TRadiobutton styles to prevent shrinking ---
        # Default/Unselected state for radio buttons
        self.style.configure('Unselected.TRadiobutton',
                             background=constants.BG_DARK_SECONDARY,
                             foreground=constants.TEXT_COLOR,
                             font=('Arial', 10),
                             padding=[10, 5, 10, 5]) # [left, top, right, bottom]
        self.style.map('Unselected.TRadiobutton',
                       background=[('active', constants.BG_DARK_PRIMARY)],
                       foreground=[('active', constants.TEXT_COLOR)])

        # Selected state for radio buttons
        self.style.configure('Selected.TRadiobutton',
                             background=constants.ACCENT_BLUE,
                             foreground=constants.BUTTON_TEXT_COLOR,
                             font=('Arial', 10),
                             padding=[10, 5, 10, 5])
        self.style.map('Selected.TRadiobutton',
                       background=[('active', constants.ACCENT_BLUE_HOVER)],
                       foreground=[('active', constants.BUTTON_TEXT_COLOR)])


        # --- Main Layout ---
        self.main_frame = ttk.Frame(master)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        self.sidebar_frame = ttk.Frame(self.main_frame, width=200, style='TFrame', relief='solid', borderwidth=0)
        self.sidebar_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 1), pady=0) # Add 1px padding for border effect

        # Notebook for main content area
        self.notebook = ttk.Notebook(self.main_frame, style='TNotebook')
        self.notebook.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=10, pady=10)

        # --- Sidebar Widgets (Server Control) ---
        self.server_control_label = ttk.Label(self.sidebar_frame, text="Server Control", font=('Arial', 12, 'bold'), anchor='center')
        self.server_control_label.pack(pady=(20, 10), padx=10, fill=tk.X)

        # Server Status
        self.status_label = ttk.Label(self.sidebar_frame, text="Status:", font=('Arial', 10, 'bold'))
        self.status_label.pack(pady=2, padx=10, anchor='w')
        self.server_status_var = tk.StringVar(value="Stopped")
        self.server_status_display = ttk.Label(self.sidebar_frame, textvariable=self.server_status_var, foreground=constants.ACCENT_BLUE)
        self.server_status_display.pack(pady=2, padx=10, anchor='w')

        # Port input
        self.port_label = ttk.Label(self.sidebar_frame, text="Port:")
        self.port_label.pack(pady=2, padx=10, anchor='w')
        self.port_var = tk.StringVar(value="8080")
        self.port_entry = ttk.Entry(self.sidebar_frame, textvariable=self.port_var, width=25)
        self.port_entry.pack(pady=5, padx=10, fill=tk.X)

        # Start/Stop Buttons
        self.start_button = ttk.Button(self.sidebar_frame, text="Start Server", command=self.start_server_gui)
        self.start_button.pack(pady=(15, 5), padx=10, fill=tk.X)

        self.stop_button = ttk.Button(self.sidebar_frame, text="Stop Server", command=self.stop_server_gui, state=tk.DISABLED)
        self.stop_button.pack(pady=5, padx=10, fill=tk.X)

        # Server Mode Selection
        self.mode_label = ttk.Label(self.sidebar_frame, text="Server Mode:", anchor='w')
        self.mode_label.pack(pady=(10, 5), padx=10, fill=tk.X)

        self.server_mode_var = tk.StringVar(value=constants.SERVER_MODE)
        self.mode_buttons_frame = ttk.Frame(self.sidebar_frame)
        self.mode_buttons_frame.pack(pady=5, padx=10, fill=tk.X)

        modes = [("TCP", "tcp"), ("Web", "web"), ("HTTPS", "https"), ("FTP", "ftp")]
        self.mode_radio_buttons = {}
        for text, mode_value in modes:
            radio = ttk.Radiobutton(self.mode_buttons_frame, text=text, variable=self.server_mode_var,
                                    value=mode_value, command=self.update_mode_settings,
                                    style='Unselected.TRadiobutton') # Apply initial style
            radio.pack(side=tk.LEFT, expand=True, fill=tk.X)
            self.mode_radio_buttons[mode_value] = radio
            
        # --- Sidebar Buttons for Tabs ---
        self.separator = ttk.Separator(self.sidebar_frame, orient='horizontal')
        self.separator.pack(fill='x', pady=10, padx=10)

        self.sidebar_settings_button = ttk.Button(self.sidebar_frame, text="Settings",
                                                 command=lambda: self.notebook.select(self.settings_tab_frame))
        self.sidebar_settings_button.pack(pady=5, padx=10, fill=tk.X)

        self.sidebar_logs_button = ttk.Button(self.sidebar_frame, text="Logs",
                                              command=lambda: self.notebook.select(self.log_tab_frame))
        self.sidebar_logs_button.pack(pady=5, padx=10, fill=tk.X)

        self.sidebar_users_button = ttk.Button(self.sidebar_frame, text="User Management",
                                              command=lambda: self.notebook.select(self.user_tab_frame))
        self.sidebar_users_button.pack(pady=5, padx=10, fill=tk.X)

        self.sidebar_network_button = ttk.Button(self.sidebar_frame, text="Network Status",
                                              command=lambda: self.notebook.select(self.network_tab_frame))
        self.sidebar_network_button.pack(pady=5, padx=10, fill=tk.X)


        # --- Content Area (Tabs) ---

        # Server Log Tab
        self.log_tab_frame = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(self.log_tab_frame, text='Server Log')

        self.log_label = ttk.Label(self.log_tab_frame, text="Server Log:", font=('Arial', 12, 'bold'))
        self.log_label.pack(pady=(5, 5), padx=10, anchor='w')

        self.log_text = scrolledtext.ScrolledText(self.log_tab_frame, wrap=tk.WORD,
                                                  bg=constants.BG_DARK_TERTIARY, fg=constants.TEXT_COLOR,
                                                  font=('Consolas', 9), relief='flat', borderwidth=0)
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        self.log_text.config(state=tk.DISABLED) # Make it read-only

        # Configure tags for different log message types
        self.log_text.tag_config('info', foreground=constants.TEXT_COLOR)
        self.log_text.tag_config('success', foreground='#4CAF50') # Green
        self.log_text.tag_config('warning', foreground='#FFD700') # Gold
        self.log_text.tag_config('error', foreground='#DC3545')   # Red

        # NEW: Server Settings Tab
        self.settings_tab_frame = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(self.settings_tab_frame, text='Server Settings')

        self.settings_title_label = ttk.Label(self.settings_tab_frame, text="Mode-Specific Server Settings", font=('Arial', 12, 'bold'))
        self.settings_title_label.pack(pady=(20, 10), padx=20, anchor='center')

        # --- Mode-Specific Settings Frames (inside settings_tab_frame) ---
        self.web_settings_frame = ttk.Frame(self.settings_tab_frame, style='TFrame')
        self.https_settings_frame = ttk.Frame(self.settings_tab_frame, style='TFrame')
        self.ftp_settings_frame = ttk.Frame(self.settings_tab_frame, style='TFrame')
        
        # Web Root Directory (inside web_settings_frame)
        self.web_root_label = ttk.Label(self.web_settings_frame, text="Web Root Directory:")
        self.web_root_label.pack(pady=2, padx=10, anchor='w')
        self.web_root_var = tk.StringVar(value=constants.WEB_ROOT_DIR)
        self.web_root_entry = ttk.Entry(self.web_settings_frame, textvariable=self.web_root_var, width=50) # Increased width
        self.web_root_entry.pack(pady=5, padx=10, fill=tk.X)
        self.browse_web_button = ttk.Button(self.web_settings_frame, text="Browse Web Root", command=self.browse_web_root)
        self.browse_web_button.pack(pady=5, padx=10, fill=tk.X)

        # FTP Root Directory (inside ftp_settings_frame)
        self.ftp_root_label = ttk.Label(self.ftp_settings_frame, text="FTP Root Directory:")
        self.ftp_root_label.pack(pady=2, padx=10, anchor='w')
        self.ftp_root_var = tk.StringVar(value=constants.FTP_ROOT_DIR)
        self.ftp_root_entry = ttk.Entry(self.ftp_settings_frame, textvariable=self.ftp_root_var, width=50) # Increased width
        self.ftp_root_entry.pack(pady=5, padx=10, fill=tk.X)
        self.browse_ftp_button = ttk.Button(self.ftp_settings_frame, text="Browse FTP Root", command=self.browse_ftp_root)
        self.browse_ftp_button.pack(pady=5, padx=10, fill=tk.X)

        # SSL Certificate File (inside https_settings_frame)
        self.ssl_cert_label = ttk.Label(self.https_settings_frame, text="SSL Certificate File:")
        self.ssl_cert_label.pack(pady=2, padx=10, anchor='w')
        self.ssl_cert_var = tk.StringVar(value=constants.SSL_CERT_FILE)
        self.ssl_cert_entry = ttk.Entry(self.https_settings_frame, textvariable=self.ssl_cert_var, width=50) # Increased width
        self.ssl_cert_entry.pack(pady=5, padx=10, fill=tk.X)
        self.browse_ssl_cert_button = ttk.Button(self.https_settings_frame, text="Browse Cert", command=self.browse_ssl_cert)
        self.browse_ssl_cert_button.pack(pady=5, padx=10, fill=tk.X)

        # SSL Key File (inside https_settings_frame)
        self.ssl_key_label = ttk.Label(self.https_settings_frame, text="SSL Key File:")
        self.ssl_key_label.pack(pady=2, padx=10, anchor='w')
        self.ssl_key_var = tk.StringVar(value=constants.SSL_KEY_FILE)
        self.ssl_key_entry = ttk.Entry(self.https_settings_frame, textvariable=self.ssl_key_var, width=50) # Increased width
        self.ssl_key_entry.pack(pady=5, padx=10, fill=tk.X)
        self.browse_ssl_key_button = ttk.Button(self.https_settings_frame, text="Browse Key", command=self.browse_ssl_key)
        self.browse_ssl_key_button.pack(pady=5, padx=10, fill=tk.X)


        # User Management Tab
        self.user_tab_frame = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(self.user_tab_frame, text='User Management')

        self.user_management_label = ttk.Label(self.user_tab_frame, text="User Management", font=('Arial', 12, 'bold'))
        self.user_management_label.pack(pady=(20, 10), padx=20, anchor='center')

        self.user_username_label = ttk.Label(self.user_tab_frame, text="Username:")
        self.user_username_label.pack(pady=2, padx=20, anchor='w')
        self.user_username_entry = ttk.Entry(self.user_tab_frame, width=40)
        self.user_username_entry.pack(pady=5, padx=20, fill=tk.X)

        self.user_password_label = ttk.Label(self.user_tab_frame, text="Password:")
        self.user_password_label.pack(pady=2, padx=20, anchor='w')
        self.user_password_entry = ttk.Entry(self.user_tab_frame, show="*", width=40)
        self.user_password_entry.pack(pady=5, padx=20, fill=tk.X)

        self.user_action_frame = ttk.Frame(self.user_tab_frame, style='TFrame')
        self.user_action_frame.pack(pady=10)

        self.user_login_button = ttk.Button(self.user_action_frame, text="Login User", command=self._perform_user_tab_login)
        self.user_login_button.pack(side=tk.LEFT, padx=5)

        self.user_register_button = ttk.Button(self.user_action_frame, text="Register User", command=self._perform_user_tab_registration)
        self.user_register_button.pack(side=tk.LEFT, padx=5)

        self.user_message_label = ttk.Label(self.user_tab_frame, text="", foreground='red')
        self.user_message_label.pack(pady=10)


        # Network Status Tab
        self.network_tab_frame = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(self.network_tab_frame, text='Network Status')

        self.network_status_label = ttk.Label(self.network_tab_frame, text="Network Status", font=('Arial', 12, 'bold'))
        self.network_status_label.pack(pady=(20, 10), padx=20, anchor='center')

        # Current Server IP Address
        self.ip_address_display_label = ttk.Label(self.network_tab_frame, text="Server IP Address:", font=('Arial', 10, 'bold'))
        self.ip_address_display_label.pack(pady=5, padx=20, anchor='w')
        self.current_ip_var = tk.StringVar(value="Not running")
        self.current_ip_label = ttk.Label(self.network_tab_frame, textvariable=self.current_ip_var, font=('Arial', 10))
        self.current_ip_label.pack(pady=2, padx=20, anchor='w')

        # Current Server Port
        self.port_display_label = ttk.Label(self.network_tab_frame, text="Server Port:", font=('Arial', 10, 'bold'))
        self.port_display_label.pack(pady=5, padx=20, anchor='w')
        self.current_port_var = tk.StringVar(value="Not running")
        self.current_port_label = ttk.Label(self.network_tab_frame, textvariable=self.current_port_var, font=('Arial', 10))
        self.current_port_label.pack(pady=2, padx=20, anchor='w')

        # Set up window closing protocol
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Server thread holder
        self.server_thread = None

        # Call update_network_status when GUI starts
        self.update_network_status()
        # Initial update of mode settings (to hide everything except initial mode)
        self.update_mode_settings(starting=True)


    def log_message(self, message, message_type='info'):
        """
        Logs a message to the scrolled text widget with a specific tag for styling.
        """
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n", message_type)
        self.log_text.see(tk.END) # Scroll to the end
        self.log_text.config(state=tk.DISABLED)

    def update_gui_states(self):
        """
        Updates the state of GUI elements based on server_running flag.
        Also updates network status.
        """
        is_running = constants.SERVER_RUNNING
        self.start_button.config(state=tk.DISABLED if is_running else tk.NORMAL)
        self.stop_button.config(state=tk.NORMAL if is_running else tk.DISABLED)
        self.port_entry.config(state=tk.DISABLED if is_running else tk.NORMAL)

        # Disable/enable mode radio buttons when server is running
        for mode, radio in self.mode_radio_buttons.items():
            radio.config(state=tk.DISABLED if is_running else tk.NORMAL)

        # Update server status display
        self.server_status_var.set("Running" if is_running else "Stopped")
        self.server_status_display.config(foreground='#4CAF50' if is_running else '#DC3545') # Green for running, Red for stopped

        # Re-apply mode-specific settings after updating general states
        self.update_mode_settings()
        self.update_network_status()


    def start_server_gui(self):
        """Starts the server in a new thread."""
        if constants.SERVER_RUNNING:
            self.log_message("[*] Server is already running.", 'warning')
            return

        try:
            port = int(self.port_var.get())
            if not (1 <= port <= 65535):
                raise ValueError("Port must be between 1 and 65535.")
        except ValueError as e:
            messagebox.showerror("Invalid Port", f"Please enter a valid port number. {e}")
            return

        server_mode = self.server_mode_var.get()
        web_root_dir = self.web_root_var.get()
        ftp_root_dir = self.ftp_root_var.get()
        ssl_cert_file = self.ssl_cert_var.get()
        ssl_key_file = self.ssl_key_var.get()

        if server_mode in ["web", "https"] and not web_root_dir:
            messagebox.showerror("Configuration Error", "Web mode requires a Web Root Directory.")
            return

        if server_mode == "ftp" and not ftp_root_dir:
            messagebox.showerror("Configuration Error", "FTP mode requires an FTP Root Directory.")
            return

        if server_mode == "https":
            if not ssl_cert_file or not ssl_key_file:
                messagebox.showerror("Configuration Error", "HTTPS mode requires both SSL Certificate and Key files.")
                return
            if not os.path.exists(ssl_cert_file):
                messagebox.showerror("File Error", f"SSL Certificate file not found: {ssl_cert_file}")
                return
            if not os.path.exists(ssl_key_file):
                messagebox.showerror("File Error", f"SSL Key file not found: {ssl_key_file}")
                return

        constants.SERVER_RUNNING = True
        self.update_gui_states() # Update states immediately before thread starts
        self.log_message(f"[*] Starting {server_mode.upper()} server on port {port}...", 'info')

        # Pass root directories and SSL files to the server_main_loop
        self.server_thread = threading.Thread(
            target=_server_main_loop,
            args=(port, self.log_message, self.update_gui_states,
                  server_mode, web_root_dir, ftp_root_dir,
                  ssl_cert_file, ssl_key_file),
            daemon=True # Daemon thread exits when main program exits
        )
        self.server_thread.start()


    def stop_server_gui(self):
        """Stops the server."""
        if not constants.SERVER_RUNNING:
            self.log_message("[*] Server is not running.", 'warning')
            return

        stop_server(self.log_message, self.update_gui_states)
        # Give server thread a moment to shut down gracefully
        # If server_thread.join() was called here, it would block the GUI
        # If it's a daemon thread, it will exit when the main app exits.
        # update_gui_states will be called by stop_server after logic completes.

    def browse_web_root(self):
        """Opens a directory dialog for selecting the web root."""
        directory = filedialog.askdirectory(parent=self.master, title="Select Web Root Directory")
        if directory:
            self.web_root_var.set(directory)
            constants.WEB_ROOT_DIR = directory # Update global constant

    def browse_ftp_root(self):
        """Opens a directory dialog for selecting the FTP root."""
        directory = filedialog.askdirectory(parent=self.master, title="Select FTP Root Directory")
        if directory:
            self.ftp_root_var.set(directory)
            constants.FTP_ROOT_DIR = directory # Update global constant

    def browse_ssl_cert(self):
        """Opens a file dialog for selecting the SSL certificate file."""
        file_path = filedialog.askopenfilename(parent=self.master, title="Select SSL Certificate File",
                                               filetypes=[("Certificate files", "*.crt;*.pem"), ("All files", "*.*")])
        if file_path:
            self.ssl_cert_var.set(file_path)
            constants.SSL_CERT_FILE = file_path

    def browse_ssl_key(self):
        """Opens a file dialog for selecting the SSL key file."""
        file_path = filedialog.askopenfilename(parent=self.master, title="Select SSL Key File",
                                               filetypes=[("Key files", "*.key;*.pem"), ("All files", "*.*")])
        if file_path:
            self.ssl_key_var.set(file_path)
            constants.SSL_KEY_FILE = file_path

    def update_sidebar_mode_button_highlight(self, selected_mode):
        """Updates the visual highlight for the selected mode button."""
        for mode, radio_button in self.mode_radio_buttons.items():
            if mode == selected_mode:
                radio_button.config(style='Selected.TRadiobutton')
            else:
                radio_button.config(style='Unselected.TRadiobutton')


    def update_mode_settings(self, starting=False):
        """
        Dynamically shows/hides configuration options based on the selected server mode.
        If a mode with specific settings is chosen, it also switches to the Settings tab.
        """
        current_mode = self.server_mode_var.get()
        control_state = tk.NORMAL if not constants.SERVER_RUNNING else tk.DISABLED

        # Hide all mode-specific setting frames within the settings tab
        self.web_settings_frame.pack_forget()
        self.https_settings_frame.pack_forget()
        self.ftp_settings_frame.pack_forget()

        # Pack and configure the relevant frame based on current mode
        if current_mode == "web":
            self.web_settings_frame.pack(pady=5, padx=10, fill=tk.X)
            self.web_root_entry.config(state=control_state)
            self.browse_web_button.config(state=control_state)
            self.notebook.select(self.settings_tab_frame) # Switch to settings tab
        elif current_mode == "https":
            self.https_settings_frame.pack(pady=5, padx=10, fill=tk.X)
            # All settings for HTTPS are now within this frame
            self.web_root_entry.config(state=control_state)
            self.browse_web_button.config(state=control_state)
            self.ssl_cert_entry.config(state=control_state)
            self.browse_ssl_cert_button.config(state=control_state)
            self.ssl_key_entry.config(state=control_state)
            self.browse_ssl_key_button.config(state=control_state)
            self.notebook.select(self.settings_tab_frame) # Switch to settings tab
        elif current_mode == "ftp":
            self.ftp_settings_frame.pack(pady=5, padx=10, fill=tk.X)
            self.ftp_root_entry.config(state=control_state)
            self.browse_ftp_button.config(state=control_state)
            self.notebook.select(self.settings_tab_frame) # Switch to settings tab
        # For TCP, no specific settings are shown, and we don't force a tab switch

        # Re-apply highlight for the currently selected mode
        self.update_sidebar_mode_button_highlight(self.server_mode_var.get())

        if not starting:
            self.log_message(f"[*] Server mode set to {current_mode.upper()}.", 'info')

    def update_network_status(self):
        """Updates the IP address and port displayed in the Network Status tab."""
        if constants.SERVER_RUNNING:
            try:
                # Get the server's own IP address
                # This tries to connect to an external server (Google DNS)
                # to get the local IP used for outgoing connections.
                # It doesn't actually send data.
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.connect(("8.8.8.8", 80))
                ip_address = s.getsockname()[0]
                s.close()
                self.current_ip_var.set(ip_address)
            except Exception as e:
                self.current_ip_var.set(f"N/A (Error: {e})")
                self.log_message(f"[-] Could not determine server IP: {e}", 'error')

            self.current_port_var.set(self.port_var.get())
        else:
            self.current_ip_var.set("Not running")
            self.current_port_var.set("Not running")


    def _perform_user_tab_login(self):
        """Handles login action from the User Management tab."""
        username = self.user_username_entry.get()
        password = self.user_password_entry.get()

        if not username or not password:
            self.user_message_label.config(text="Please enter both username and password.", foreground='red')
            return

        success, message = authenticate_user(username, password)
        if success:
            self.user_message_label.config(text=f"Login successful: {message}", foreground='green')
            self.log_message(f"[+] User '{username}' logged in via GUI user management.", 'success')
            # Clear fields after successful login
            self.user_username_entry.delete(0, tk.END)
            self.user_password_entry.delete(0, tk.END)
        else:
            self.user_message_label.config(text=message, foreground='red')
            self.log_message(f"[-] Failed login attempt for user '{username}' via GUI user management.", 'warning')
            self.user_password_entry.delete(0, tk.END) # Clear password field on failed attempt

    def _perform_user_tab_registration(self):
        """Handles registration action from the User Management tab."""
        username = self.user_username_entry.get()
        password = self.user_password_entry.get()

        if not username or not password:
            self.user_message_label.config(text="Please enter both username and password for registration.", foreground='red')
            return

        success, message = add_user(username, password)
        if success:
            self.user_message_label.config(text=f"Registration successful: {message}", foreground='green')
            self.log_message(f"[+] User '{username}' registered via GUI user management.", 'success')
            # Clear fields after successful registration
            self.user_username_entry.delete(0, tk.END)
            self.user_password_entry.delete(0, tk.END)
        else:
            self.user_message_label.config(text=message, foreground='red')
            self.log_message(f"[-] Failed registration attempt for user '{username}' via GUI user management: {message}", 'warning')


    def on_closing(self):
        """
        Handles the window closing event.
        Prompts the user to confirm quitting and stops the server if it's
        running.
        """
        if messagebox.askokcancel("Quit", "Do you want to quit NetWeaver?"):
            self.stop_server_gui()
            # Give a moment for the server thread to potentially clean up
            time.sleep(0.1) # Small delay to allow stop_server to initiate
            self.master.destroy()


class LoginWindow:
    """
    A Tkinter-based GUI for a secure login screen.
    """
    def __init__(self, master):
        self.master = master
        self.authenticated = False # Flag to indicate successful authentication

        self.top_level = tk.Toplevel(master)
        self.top_level.title("NetWeaver - Login")
        self.top_level.geometry("400x300")
        self.top_level.resizable(False, False)
        self.top_level.grab_set() # Make it modal

        # Center the login window on the screen
        self.top_level.update_idletasks() # Ensure window dimensions are calculated

        width = self.top_level.winfo_width()
        height = self.top_level.winfo_height()

        screen_width = self.top_level.winfo_screenwidth()
        screen_height = self.top_level.winfo_screenheight()

        # Calculate x and y coordinates for the center of the screen
        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)

        self.top_level.geometry(f"{width}x{height}+{x}+{y}") # Apply calculated position


        # Set theme colors
        self.top_level.configure(bg=constants.BG_DARK_PRIMARY)
        style = ttk.Style(self.top_level)
        style.theme_use('clam')
        style.configure('TFrame', background=constants.BG_DARK_PRIMARY)
        style.configure('TLabel', background=constants.BG_DARK_PRIMARY, foreground=constants.TEXT_COLOR, font=('Arial', 10))
        style.configure('TEntry', fieldbackground=constants.BG_DARK_SECONDARY, foreground=constants.TEXT_COLOR, insertbackground=constants.ACCENT_BLUE)
        style.configure('TButton', background=constants.ACCENT_BLUE, foreground=constants.BUTTON_TEXT_COLOR, font=('Arial', 10, 'bold'))
        style.map('TButton',
            background=[('active', constants.ACCENT_BLUE_HOVER)],
            foreground=[('active', constants.BUTTON_TEXT_COLOR)])

        # Create widgets
        self.login_frame = ttk.Frame(self.top_level, padding="20")
        self.login_frame.pack(expand=True)

        self.username_label = ttk.Label(self.login_frame, text="Username:")
        self.username_label.pack(pady=5)
        self.username_entry = ttk.Entry(self.login_frame, width=30)
        self.username_entry.pack(pady=5)

        self.password_label = ttk.Label(self.login_frame, text="Password:")
        self.password_label.pack(pady=5)
        self.password_entry = ttk.Entry(self.login_frame, show="*", width=30)
        self.password_entry.pack(pady=5)

        self.login_button = ttk.Button(self.login_frame, text="Login", command=self._perform_login)
        self.login_button.pack(pady=10)

        self.register_button = ttk.Button(self.login_frame, text="Register", command=self._perform_registration)
        self.register_button.pack(pady=5)

        self.message_label = ttk.Label(self.login_frame, text="", foreground='red')
        self.message_label.pack(pady=5)

        # Bind <Return> key to login function
        self.top_level.bind('<Return>', lambda event=None: self._perform_login())
        # Handle window close event
        self.top_level.protocol("WM_DELETE_WINDOW", self._on_closing)


    def _perform_login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            self.message_label.config(text="Please enter both username and password.")
            return

        success, message = authenticate_user(username, password)
        if success:
            self.authenticated = True
            self.top_level.destroy() # Close the login window
        else:
            self.message_label.config(text=message)
            self.password_entry.delete(0, tk.END) # Clear password field on failed attempt

    def _perform_registration(self):
        username = self.username_entry.get()
        password = self.password_entry.get()

        if not username or not password:
            self.message_label.config(text="Please enter both username and password for registration.")
            return

        success, message = add_user(username, password)
        if success:
            self.message_label.config(text=f"Registration successful: {message}", foreground='green')
            # Optionally, automatically log in the new user or prompt them to log in
        else:
            self.message_label.config(text=message, foreground='red')

    def _on_closing(self):
        """Handle the window closing event for the login window."""
        if messagebox.askokcancel("Quit", "Do you want to quit NetWeaver?"):
            self.top_level.destroy()
            self.master.destroy() # Close the main root window as well