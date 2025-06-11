import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from PIL import Image, ImageTk
import threading
import time
import os
import socket
import json # Added for settings persistence

import constants
from server_core import _server_main_loop, stop_server
from user import (
    authenticate_user, add_user, delete_user, update_user_password,
    get_all_users, ROLE_ADMIN, ROLE_OPERATOR, ROLE_GUEST, DEFAULT_NEW_USER_ROLE, # Added role imports
    _get_cipher_suite # Import the cipher suite utility
)

class TCPServerGUI:
    """
    A Tkinter-based GUI for a multi-threaded TCP/Web/FTP server.
    Designed with a modern, dark theme.
    """

    def __init__(self, master, user_role): # Added user_role argument
        """
        Initializes the TCPServerGUI.

        Args:
            master (tk.Tk): The root Tkinter window.
            user_role (str): The role of the currently authenticated user.
        """
        self.master = master
        self.current_user_role = user_role # Store the current user's role
        
        # --- DEBUG PRINT: Confirming role received by TCPServerGUI ---
        print(f"[DEBUG] TCPServerGUI initialized with role: {self.current_user_role}")
        # --- END DEBUG PRINT ---

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

        # Current User Role Display
        self.role_label = ttk.Label(self.sidebar_frame, text="Logged in as:", font=('Arial', 9, 'bold'))
        self.role_label.pack(pady=2, padx=10, anchor='w')
        self.current_role_var = tk.StringVar(value=f"Role: {self.current_user_role.upper()}")
        self.current_role_display = ttk.Label(self.sidebar_frame, textvariable=self.current_role_var, foreground=constants.ACCENT_BLUE)
        self.current_role_display.pack(pady=2, padx=10, anchor='w')
        
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

        # Server Settings Tab
        self.settings_tab_frame = ttk.Frame(self.notebook, style='TFrame')
        self.notebook.add(self.settings_tab_frame, text='Server Settings')

        self.settings_title_label = ttk.Label(self.settings_tab_frame, text="Mode-Specific Server Settings", font=('Arial', 12, 'bold'))
        self.settings_title_label.pack(pady=(20, 10), padx=20, anchor='center')

        # Connection Limit
        self.max_connections_label = ttk.Label(self.settings_tab_frame, text="Max Concurrent Connections:")
        self.max_connections_label.pack(pady=2, padx=10, anchor='w')
        self.max_connections_var = tk.IntVar(value=constants.MAX_CONNECTIONS)
        self.max_connections_entry = ttk.Entry(self.settings_tab_frame, textvariable=self.max_connections_var, width=10)
        self.max_connections_entry.pack(pady=5, padx=10, anchor='w')


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

        # User List (Treeview)
        self.user_list_frame = ttk.Frame(self.user_tab_frame, style='TFrame')
        self.user_list_frame.pack(pady=10, padx=20, fill=tk.BOTH, expand=True)

        self.user_tree = ttk.Treeview(self.user_list_frame, columns=("Username", "Role"), show="headings") # Added Role column
        self.user_tree.heading("Username", text="Username")
        self.user_tree.heading("Role", text="Role") # Heading for Role column
        self.user_tree.column("Username", width=150, anchor='center')
        self.user_tree.column("Role", width=100, anchor='center') # Column for Role
        self.user_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.user_tree_scrollbar = ttk.Scrollbar(self.user_list_frame, orient="vertical", command=self.user_tree.yview)
        self.user_tree_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.user_tree.config(yscrollcommand=self.user_tree_scrollbar.set)

        # User Action Frame (Add/Update/Delete)
        self.user_input_frame = ttk.Frame(self.user_tab_frame, style='TFrame')
        self.user_input_frame.pack(pady=10, padx=20, fill=tk.X)

        ttk.Label(self.user_input_frame, text="Username:").grid(row=0, column=0, padx=5, pady=2, sticky='w')
        self.manage_username_entry = ttk.Entry(self.user_input_frame, width=30)
        self.manage_username_entry.grid(row=0, column=1, padx=5, pady=2, sticky='ew')

        ttk.Label(self.user_input_frame, text="Password:").grid(row=1, column=0, padx=5, pady=2, sticky='w')
        self.manage_password_entry = ttk.Entry(self.user_input_frame, show="*", width=30)
        self.manage_password_entry.grid(row=1, column=1, padx=5, pady=2, sticky='ew')

        # RBAC: Role selection for new users
        ttk.Label(self.user_input_frame, text="Role:").grid(row=2, column=0, padx=5, pady=2, sticky='w')
        self.new_user_role_var = tk.StringVar(value=DEFAULT_NEW_USER_ROLE)
        self.new_user_role_combobox = ttk.Combobox(self.user_input_frame, textvariable=self.new_user_role_var,
                                                   values=[ROLE_ADMIN, ROLE_OPERATOR, ROLE_GUEST], state="readonly")
        self.new_user_role_combobox.grid(row=2, column=1, padx=5, pady=2, sticky='ew')
        
        self.user_action_buttons_frame = ttk.Frame(self.user_input_frame, style='TFrame')
        self.user_action_buttons_frame.grid(row=3, column=0, columnspan=2, pady=10) # Adjusted row

        self.add_user_button = ttk.Button(self.user_action_buttons_frame, text="Add User", command=self._add_user_gui)
        self.add_user_button.pack(side=tk.LEFT, padx=5)

        self.update_user_button = ttk.Button(self.user_action_buttons_frame, text="Update Password", command=self._update_user_password_gui)
        self.update_user_button.pack(side=tk.LEFT, padx=5)

        self.delete_user_button = ttk.Button(self.user_action_buttons_frame, text="Delete User", command=self._delete_user_gui)
        self.delete_user_button.pack(side=tk.LEFT, padx=5)
        
        # New button for updating user role
        self.update_role_button = ttk.Button(self.user_action_buttons_frame, text="Update Role", command=self._update_user_role_gui)
        self.update_role_button.pack(side=tk.LEFT, padx=5)

        self.manage_user_message_label = ttk.Label(self.user_tab_frame, text="", foreground='red')
        self.manage_user_message_label.pack(pady=5)

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

        # Active Connections
        self.active_connections_label = ttk.Label(self.network_tab_frame, text="Active Connections:", font=('Arial', 10, 'bold'))
        self.active_connections_label.pack(pady=5, padx=20, anchor='w')
        self.active_connections_var = tk.StringVar(value="0")
        self.active_connections_display = ttk.Label(self.network_tab_frame, textvariable=self.active_connections_var, font=('Arial', 10))
        self.active_connections_display.pack(pady=2, padx=20, anchor='w')

        # Data Transfer Rate (Placeholder)
        self.data_rate_label = ttk.Label(self.network_tab_frame, text="Data Transfer Rate (KB/s):", font=('Arial', 10, 'bold'))
        self.data_rate_label.pack(pady=5, padx=20, anchor='w')
        self.data_rate_var = tk.StringVar(value="0.00")
        self.data_rate_display = ttk.Label(self.network_tab_frame, textvariable=self.data_rate_var, font=('Arial', 10))
        self.data_rate_display.pack(pady=2, padx=20, anchor='w')


        # Set up window closing protocol
        self.master.protocol("WM_DELETE_WINDOW", self.on_closing)

        # Server thread holder
        self.server_thread = None

        # Load settings at startup
        self._load_settings()

        # Call update_network_status when GUI starts
        self.update_network_status()
        # Initial update of mode settings (to hide everything except initial mode)
        self.update_mode_settings(starting=True)
        # Populate user list
        self._populate_user_list()
        
        # Start periodic network status update
        self._start_network_status_updater()

        # Apply initial RBAC permissions
        self._apply_rbac_permissions()


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
        Updates the state of GUI elements based on server_running flag AND user role.
        Also updates network status.
        """
        is_running = constants.SERVER_RUNNING
        
        # Server Control Buttons (Start/Stop) - Only for Admin
        if self.current_user_role == ROLE_ADMIN:
            self.start_button.config(state=tk.DISABLED if is_running else tk.NORMAL)
            self.stop_button.config(state=tk.NORMAL if is_running else tk.DISABLED)
            self.port_entry.config(state=tk.DISABLED if is_running else tk.NORMAL)
            self.max_connections_entry.config(state=tk.DISABLED if is_running else tk.NORMAL)
        else:
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.DISABLED)
            self.port_entry.config(state=tk.DISABLED)
            self.max_connections_entry.config(state=tk.DISABLED)

        # Disable/enable mode radio buttons when server is running, or based on role
        for mode, radio in self.mode_radio_buttons.items():
            if self.current_user_role == ROLE_ADMIN:
                radio.config(state=tk.DISABLED if is_running else tk.NORMAL)
            else:
                radio.config(state=tk.DISABLED) # Non-admin cannot change mode


        # Update server status display
        self.server_status_var.set("Running" if is_running else "Stopped")
        self.server_status_display.config(foreground='#4CAF50' if is_running else '#DC3545') # Green for running, Red for stopped

        # Re-apply mode-specific settings after updating general states
        self.update_mode_settings()
        self.update_network_status()
        self._apply_rbac_permissions() # Re-apply all RBAC permissions after state changes


    def start_server_gui(self):
        """Starts the server in a new thread. Requires admin role."""
        if self.current_user_role != ROLE_ADMIN:
            messagebox.showerror("Permission Denied", "Only admins can start the server.") # Changed message
            self.log_message("[-] Non-admin user attempted to start server.", 'error')
            return

        if constants.SERVER_RUNNING:
            self.log_message("[*] Server is already running.", 'warning')
            return

        try:
            port = int(self.port_var.get())
            if not (1 <= port <= 65535):
                raise ValueError("Port must be between 1 and 65535.")
            max_connections = self.max_connections_var.get()
            if not (1 <= max_connections <= 1000): # Arbitrary reasonable limit
                raise ValueError("Max connections must be between 1 and 1000.")

        except ValueError as e:
            messagebox.showerror("Invalid Input", f"Please enter valid numbers. {e}")
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
        constants.MAX_CONNECTIONS = max_connections # Update constant
        self._save_settings() # Save current settings before starting
        self.update_gui_states() # Update states immediately before thread starts
        self.log_message(f"[*] Starting {server_mode.upper()} server on port {port} with max connections {max_connections}...", 'info')

        # Pass root directories and SSL files to the server_main_loop
        self.server_thread = threading.Thread(
            target=_server_main_loop,
            args=(port, self.log_message, self.update_gui_states,
                  server_mode, web_root_dir, ftp_root_dir,
                  ssl_cert_file, ssl_key_file, max_connections),
            daemon=True # Daemon thread exits when main program exits
        )
        self.server_thread.start()


    def stop_server_gui(self):
        """Stops the server. Requires admin role."""
        if self.current_user_role != ROLE_ADMIN:
            messagebox.showerror("Permission Denied", "Only admins can stop the server.") # Changed message
            self.log_message("[-] Non-admin user attempted to stop server.", 'error')
            return

        if not constants.SERVER_RUNNING:
            self.log_message("[*] Server is not running.", 'warning')
            return

        stop_server(self.log_message, self.update_gui_states)
        # Give server thread a moment to shut down gracefully
        # If server_thread.join() was called here, it would block the GUI
        # If it's a daemon thread, it will exit when the main app exits.
        # update_gui_states will be called by stop_server after logic completes.

    def browse_web_root(self):
        """Opens a directory dialog for selecting the web root. Requires admin role."""
        if self.current_user_role != ROLE_ADMIN: return
        directory = filedialog.askdirectory(parent=self.master, title="Select Web Root Directory")
        if directory:
            self.web_root_var.set(directory)
            constants.WEB_ROOT_DIR = directory # Update global constant
            self._save_settings() # Save settings after change

    def browse_ftp_root(self):
        """Opens a directory dialog for selecting the FTP root. Requires admin role."""
        if self.current_user_role != ROLE_ADMIN: return
        directory = filedialog.askdirectory(parent=self.master, title="Select FTP Root Directory")
        if directory:
            self.ftp_root_var.set(directory)
            constants.FTP_ROOT_DIR = directory # Update global constant
            self._save_settings() # Save settings after change

    def browse_ssl_cert(self):
        """Opens a file dialog for selecting the SSL certificate file. Requires admin role."""
        if self.current_user_role != ROLE_ADMIN: return
        file_path = filedialog.askopenfilename(parent=self.master, title="Select SSL Certificate File",
                                               filetypes=[("Certificate files", "*.crt;*.pem"), ("All files", "*.*")])
        if file_path:
            self.ssl_cert_var.set(file_path)
            constants.SSL_CERT_FILE = file_path
            self._save_settings() # Save settings after change

    def browse_ssl_key(self):
        """Opens a file dialog for selecting the SSL key file. Requires admin role."""
        if self.current_user_role != ROLE_ADMIN: return
        file_path = filedialog.askopenfilename(parent=self.master, title="Select SSL Key File",
                                               filetypes=[("Key files", "*.key;*.pem"), ("All files", "*.*")])
        if file_path:
            self.ssl_key_var.set(file_path)
            constants.SSL_KEY_FILE = file_path
            self._save_settings() # Save settings after change

    def update_sidebar_mode_button_highlight(self, selected_mode):
        """Updates the visual highlight for the selected mode button."""
        for mode, radio_button in self.mode_radio_buttons.items():
            if mode == selected_mode:
                radio_button.config(style='Selected.TRadiobutton')
            else:
                radio_button.config(style='Unselected.TRadiobutton')


    def update_mode_settings(self, starting=False):
        """
        Dynamically shows/hides configuration options based on the selected server mode
        and the user's role.
        If a mode with specific settings is chosen, it also switches to the Settings tab.
        """
        current_mode = self.server_mode_var.get()
        
        # Disable/enable based on server running state AND admin role
        if self.current_user_role == ROLE_ADMIN:
            control_state = tk.NORMAL if not constants.SERVER_RUNNING else tk.DISABLED
        else:
            control_state = tk.DISABLED # Non-admin cannot change settings

        # Hide all mode-specific setting frames within the settings tab
        self.web_settings_frame.pack_forget()
        self.https_settings_frame.pack_forget()
        self.ftp_settings_frame.pack_forget()

        # Pack and configure the relevant frame based on current mode
        if current_mode == "web":
            self.web_settings_frame.pack(pady=5, padx=10, fill=tk.X)
            self.web_root_entry.config(state=control_state)
            self.browse_web_button.config(state=control_state)
            if not starting and self.current_user_role == ROLE_ADMIN: # Only switch tab if admin
                self.notebook.select(self.settings_tab_frame)
        elif current_mode == "https":
            self.https_settings_frame.pack(pady=5, padx=10, fill=tk.X)
            self.web_root_entry.config(state=control_state)
            self.browse_web_button.config(state=control_state)
            self.ssl_cert_entry.config(state=control_state)
            self.browse_ssl_cert_button.config(state=control_state)
            self.ssl_key_entry.config(state=control_state)
            self.browse_ssl_key_button.config(state=control_state)
            if not starting and self.current_user_role == ROLE_ADMIN: # Only switch tab if admin
                self.notebook.select(self.settings_tab_frame)
        elif current_mode == "ftp":
            self.ftp_settings_frame.pack(pady=5, padx=10, fill=tk.X)
            self.ftp_root_entry.config(state=control_state)
            self.browse_ftp_button.config(state=control_state)
            if not starting and self.current_user_role == ROLE_ADMIN: # Only switch tab if admin
                self.notebook.select(self.settings_tab_frame)
        # For TCP, no specific settings are shown, and we don't force a tab switch

        # Re-apply highlight for the currently selected mode
        self.update_sidebar_mode_button_highlight(self.server_mode_var.get())

        if not starting:
            self.log_message(f"[*] Server mode set to {current_mode.upper()}.", 'info')
            if self.current_user_role == ROLE_ADMIN: # Only save settings if admin
                self._save_settings()

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
            # These values would come from server_core.py if it exposed them
            # For now, they are static or placeholder
            self.active_connections_var.set(str(constants.ACTIVE_CONNECTIONS)) # Assuming a global constant updated by server_core
            self.data_rate_var.set(f"{constants.DATA_TRANSFER_RATE:.2f}") # Assuming a global constant updated by server_core
        else:
            self.current_ip_var.set("Not running")
            self.current_port_var.set("Not running")
            self.active_connections_var.set("0")
            self.data_rate_var.set("0.00")

    def _start_network_status_updater(self):
        """Starts a recurring update for network status."""
        self.update_network_status()
        self.master.after(1000, self._start_network_status_updater) # Update every 1 second

    def _save_settings(self):
        """Saves current server settings to an encrypted JSON file. Requires admin role."""
        if self.current_user_role != ROLE_ADMIN: return
        settings = {
            "port": self.port_var.get(),
            "server_mode": self.server_mode_var.get(),
            "web_root_dir": self.web_root_var.get(),
            "ftp_root_dir": self.ftp_root_var.get(),
            "ssl_cert_file": self.ssl_cert_var.get(),
            "ssl_key_file": self.ssl_key_var.get(),
            "max_connections": self.max_connections_var.get()
        }
        try:
            cipher_suite = _get_cipher_suite()
            plain_text_data = json.dumps(settings, indent=4).encode('utf-8')
            encrypted_data = cipher_suite.encrypt(plain_text_data)
            with open(constants.SETTINGS_FILE, "wb") as f:
                f.write(encrypted_data)
            self.log_message("[*] Server settings saved (encrypted).", 'info')
        except Exception as e:
            self.log_message(f"[-] Error saving settings: {e}", 'error')

    def _load_settings(self):
        """Loads server settings from an encrypted JSON file."""
        try:
            if os.path.exists(constants.SETTINGS_FILE):
                cipher_suite = _get_cipher_suite()
                with open(constants.SETTINGS_FILE, "rb") as f:
                    encrypted_data = f.read()
                    if not encrypted_data:
                        self.log_message("[*] settings.json is empty. Using default settings.", 'warning')
                        return
                
                try:
                    decrypted_data = cipher_suite.decrypt(encrypted_data)
                    settings = json.loads(decrypted_data.decode('utf-8'))
                except Exception as e:
                    self.log_message(f"[-] Error decrypting or decoding settings data: {e}. Using default settings.", 'error')
                    return
                
                self.port_var.set(settings.get("port", "8080"))
                self.server_mode_var.set(settings.get("server_mode", "tcp"))
                self.web_root_var.set(settings.get("web_root_dir", os.getcwd())) # Default to current dir
                self.ftp_root_var.set(settings.get("ftp_root_dir", os.getcwd())) # Default to current dir
                self.ssl_cert_var.set(settings.get("ssl_cert_file", ""))
                self.ssl_key_var.set(settings.get("ssl_key_file", ""))
                self.max_connections_var.set(settings.get("max_connections", constants.MAX_CONNECTIONS))
                
                # Update constants with loaded values
                constants.SERVER_MODE = self.server_mode_var.get()
                constants.WEB_ROOT_DIR = self.web_root_var.get()
                constants.FTP_ROOT_DIR = self.ftp_root_var.get()
                constants.SSL_CERT_FILE = self.ssl_cert_var.get()
                constants.SSL_KEY_FILE = self.ssl_key_var.get()
                constants.MAX_CONNECTIONS = self.max_connections_var.get()

                self.log_message("[*] Server settings loaded (decrypted).", 'info')
            else:
                self.log_message("[*] settings.json not found. Using default settings.", 'warning')
        except Exception as e:
            self.log_message(f"[-] Error loading settings: {e}", 'error')

    def _populate_user_list(self):
        """Populates the Treeview with registered users and their roles."""
        for item in self.user_tree.get_children():
            self.user_tree.delete(item) # Clear existing entries

        users = get_all_users() # This now returns (username, role) tuples
        for user, role in users:
            self.user_tree.insert("", tk.END, values=(user, role)) # Insert both username and role

    def _add_user_gui(self):
        """Handles adding a new user from the User Management tab. Requires admin role."""
        if self.current_user_role != ROLE_ADMIN:
            self.manage_user_message_label.config(text="Permission Denied: Only admins can add users.", foreground='red') # Changed message
            self.log_message("[-] Non-admin user attempted to add user.", 'error')
            return

        username = self.manage_username_entry.get()
        password = self.manage_password_entry.get()
        role = self.new_user_role_combobox.get() # Get selected role

        if not username or not password:
            self.manage_user_message_label.config(text="Please enter both username and password.", foreground='red')
            return

        success, message, _ = add_user(username, password, role) # Pass role to add_user
        if success:
            self.manage_user_message_label.config(text=f"User added: {message}", foreground='green')
            self.log_message(f"[+] User '{username}' ({role}) added via GUI user management.", 'success')
            self._populate_user_list()
            self.manage_username_entry.delete(0, tk.END)
            self.manage_password_entry.delete(0, tk.END)
            self.new_user_role_combobox.set(DEFAULT_NEW_USER_ROLE) # Reset role combobox
        else:
            self.manage_user_message_label.config(text=message, foreground='red')
            self.log_message(f"[-] Failed to add user '{username}' via GUI user management: {message}", 'warning')

    def _delete_user_gui(self):
        """Handles deleting a user from the User Management tab. Requires admin role."""
        if self.current_user_role != ROLE_ADMIN:
            self.manage_user_message_label.config(text="Permission Denied: Only admins can delete users.", foreground='red') # Changed message
            self.log_message("[-] Non-admin user attempted to delete user.", 'error')
            return

        selected_item = self.user_tree.selection()
        if not selected_item:
            self.manage_user_message_label.config(text="Please select a user to delete.", foreground='red')
            return

        username_to_delete = self.user_tree.item(selected_item, 'values')[0]

        if messagebox.askyesno("Confirm Deletion", f"Are you sure you want to delete user '{username_to_delete}'?"):
            success, message = delete_user(username_to_delete)
            if success:
                self.manage_user_message_label.config(text=f"User deleted: {message}", foreground='green')
                self.log_message(f"[+] User '{username_to_delete}' deleted via GUI user management.", 'success')
                self._populate_user_list()
            else:
                self.manage_user_message_label.config(text=message, foreground='red')
                self.log_message(f"[-] Failed to delete user '{username_to_delete}' via GUI user management: {message}", 'warning')

    def _update_user_password_gui(self):
        """Handles updating a user's password from the User Management tab. Requires admin role."""
        if self.current_user_role != ROLE_ADMIN:
            self.manage_user_message_label.config(text="Permission Denied: Only admins can update passwords.", foreground='red') # Changed message
            self.log_message("[-] Non-admin user attempted to update password.", 'error')
            return

        selected_item = self.user_tree.selection()
        if not selected_item:
            self.manage_user_message_label.config(text="Please select a user to update.", foreground='red')
            return

        username_to_update = self.user_tree.item(selected_item, 'values')[0]
        new_password = self.manage_password_entry.get()

        if not new_password:
            self.manage_user_message_label.config(text="Please enter a new password.", foreground='red')
            return

        success, message = update_user_password(username_to_update, new_password)
        if success:
            self.manage_user_message_label.config(text=f"Password updated for '{username_to_update}': {message}", foreground='green')
            self.log_message(f"[+] Password updated for user '{username_to_update}' via GUI user management.", 'success')
            self.manage_password_entry.delete(0, tk.END)
        else:
            self.manage_user_message_label.config(text=message, foreground='red')
            self.log_message(f"[-] Failed to update password for user '{username_to_update}' via GUI user management: {message}", 'warning')

    def _update_user_role_gui(self):
        """Handles updating a user's role from the User Management tab. Requires admin role."""
        if self.current_user_role != ROLE_ADMIN:
            self.manage_user_message_label.config(text="Permission Denied: Only admins can update user roles.", foreground='red') # Changed message
            self.log_message("[-] Non-admin user attempted to update user role.", 'error')
            return

        selected_item = self.user_tree.selection()
        if not selected_item:
            self.manage_user_message_label.config(text="Please select a user to update their role.", foreground='red')
            return

        username_to_update = self.user_tree.item(selected_item, 'values')[0]
        new_role = self.new_user_role_combobox.get() # Get selected role for update

        if not new_role or new_role not in [ROLE_ADMIN, ROLE_OPERATOR, ROLE_GUEST]:
            self.manage_user_message_label.config(text="Please select a valid role.", foreground='red')
            return
        
        # Import update_user_role from user.py
        from user import update_user_role
        success, message = update_user_role(username_to_update, new_role)

        if success:
            self.manage_user_message_label.config(text=f"Role updated for '{username_to_update}' to '{new_role}': {message}", foreground='green')
            self.log_message(f"[+] Role updated for user '{username_to_update}' to '{new_role}' via GUI user management.", 'success')
            self._populate_user_list() # Refresh the list to show the new role
        else:
            self.manage_user_message_label.config(text=message, foreground='red')
            self.log_message(f"[-] Failed to update role for user '{username_to_update}': {message}", 'warning')

    def _apply_rbac_permissions(self):
        """Applies permissions based on the current user's role."""
        is_admin = (self.current_user_role == ROLE_ADMIN)
        is_operator = (self.current_user_role == ROLE_OPERATOR)
        is_guest = (self.current_user_role == ROLE_GUEST)

        # Server Control (Start/Stop, Port, Max Connections)
        # These are handled by update_gui_states already which calls this.
        # So no explicit changes needed here for these.

        # Settings Tab elements (Web/FTP/SSL directory browsing, etc.)
        # The state of entry fields and browse buttons is already managed by update_mode_settings.
        # This function just needs to ensure the overall tab access/visibility is correct.

        # User Management Tab elements
        self.add_user_button.config(state=tk.NORMAL if is_admin else tk.DISABLED)
        self.update_user_button.config(state=tk.NORMAL if is_admin else tk.DISABLED)
        self.delete_user_button.config(state=tk.NORMAL if is_admin else tk.DISABLED)
        self.update_role_button.config(state=tk.NORMAL if is_admin else tk.DISABLED) # New update role button
        self.manage_username_entry.config(state=tk.NORMAL if is_admin else tk.DISABLED)
        self.manage_password_entry.config(state=tk.NORMAL if is_admin else tk.DISABLED)
        self.new_user_role_combobox.config(state="readonly" if is_admin else "disabled")


        # Notebook tab visibility (if you want to hide tabs entirely for certain roles)
        # For simplicity, we are just disabling controls within the tabs.
        # To hide tabs: self.notebook.hide(self.notebook.index(self.settings_tab_frame))
        # And to show: self.notebook.add(self.settings_tab_frame, text='Server Settings')
        # This requires careful management as add/hide changes the order.
        # For now, disabling controls is sufficient and less prone to layout issues.

        # Example: Restricting navigation to tabs for guests/operators
        # Guest: Can only see Logs and Network Status
        if is_guest:
            for tab_id in self.notebook.tabs():
                tab_name = self.notebook.tab(tab_id, "text")
                if tab_name not in ['Server Log', 'Network Status']:
                    self.notebook.tab(tab_id, state='disabled')
                else:
                    self.notebook.tab(tab_id, state='normal')
        elif is_operator:
            for tab_id in self.notebook.tabs():
                tab_name = self.notebook.tab(tab_id, "text")
                if tab_name not in ['Server Log', 'Network Status', 'Server Settings']: # Operators can view settings
                    self.notebook.tab(tab_id, state='disabled')
                else:
                    self.notebook.tab(tab_id, state='normal')
        else: # Admin - all tabs are normal
             for tab_id in self.notebook.tabs():
                self.notebook.tab(tab_id, state='normal')


    def on_closing(self):
        """
        Handles the window closing event.
        Prompts the user to confirm quitting and stops the server if it's
        running.
        """
        if messagebox.askokcancel("Quit", "Do you want to quit NetWeaver?"):
            self.stop_server_gui()
            self._save_settings() # Save settings on close
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
        self.authenticated_user_role = None # Store the role of the authenticated user

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

        # Modified to unpack the third return value (role)
        success, message, user_role = authenticate_user(username, password)

        # --- DEBUG PRINT: Confirming role returned by authenticate_user ---
        print(f"[DEBUG] authenticate_user returned: success={success}, message='{message}', role={user_role}")
        # --- END DEBUG PRINT ---

        if success:
            self.authenticated = True
            self.authenticated_user_role = user_role # Store the role
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
        
        # By default, new users registered from the login screen will be GUESTS
        success, message, _ = add_user(username, password, role=DEFAULT_NEW_USER_ROLE) 
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
