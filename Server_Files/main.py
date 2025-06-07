import tkinter as tk
import signal
import time
from gui import TCPServerGUI
from constants import SERVER_RUNNING, SERVER_SOCKET, SERVER_MODE
# Import the new LoginWindow
from gui import LoginWindow # Assuming you'll add LoginWindow to gui.py

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal.SIG_IGN)

    root = tk.Tk()
    root.withdraw() # Hide the root window initially

    login_success = False
    login_window = LoginWindow(root)
    root.wait_window(login_window.top_level) # Wait for the login window to close

    if login_window.authenticated: # Check if authentication was successful
        root.deiconify() # Show the root window
        app = TCPServerGUI(root)
        root.mainloop()

        # Ensure server is stopped if GUI is closed directly
        if SERVER_RUNNING:
            print("[*] GUI closed, attempting to stop server...")
            SERVER_RUNNING = False
            if SERVER_SOCKET:
                try:
                    SERVER_SOCKET.shutdown(socket.SHUT_RDWR)
                    SERVER_SOCKET.close()
                    print("[*] Server socket closed.")
                except Exception as e:
                    print(f"[-] Error closing server socket during shutdown: {e}")
            time.sleep(0.5) # Give a moment for threads to acknowledge stop
    else:
        print("[-] Login failed or cancelled. Exiting application.")
        root.destroy() # Destroy root if not authenticated