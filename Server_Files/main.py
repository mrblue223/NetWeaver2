import tkinter as tk
import signal
import time
import socket # Added for socket.SHUT_RDWR

from gui import TCPServerGUI, LoginWindow
from constants import SERVER_MODE # Removed SERVER_RUNNING and SERVER_SOCKET
import constants # Import constants for SERVER_RUNNING check
from server_core import stop_server # Import stop_server for fallback

# You'll need to get SERVER_RUNNING and the actual server socket
# from server_core or pass them around if you want to manage them
# at this top level. For now, let's rely on server_core's internal
# management of SERVER_RUNNING and SERVER_SOCKET for shutdown.
# The `stop_server` function in `server_core.py` already handles this.

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    root = tk.Tk()
    root.withdraw() # Hide the root window initially

    login_success = False
    login_window = LoginWindow(root)
    root.wait_window(login_window.top_level) # Wait for the login window to close

    if login_window.authenticated: # Check if authentication was successful
        root.deiconify() # Show the root window
        # Pass the authenticated user's role to the main GUI application
        app = TCPServerGUI(root, login_window.authenticated_user_role)
        root.mainloop()

        # When the GUI is closed (mainloop exits), `app.on_closing` is called.
        # `on_closing` already handles stopping the server.
        # The following block is largely redundant if on_closing works as expected,
        # but it acts as a fallback for unexpected exits.
        # We need to rely on the `stop_server` function from `server_core`
        # which modifies the global `constants.SERVER_RUNNING` and closes the socket.
        # Since `SERVER_RUNNING` is a global in `constants`, we can check it.
        # Also need to import `stop_server` from `server_core` here for a clean shutdown.
        
        if constants.SERVER_RUNNING: # Check the global constant directly
            print("[*] GUI closed, attempting to stop server via fallback...")
            # Call the stop_server function which will handle the flag and socket
            stop_server(app.log_message, app.update_gui_states)
            time.sleep(0.5) # Give a moment for threads to acknowledge stop
    else:
        print("[-] Login failed or cancelled. Exiting application.")
        root.destroy() # Destroy root if not authenticated