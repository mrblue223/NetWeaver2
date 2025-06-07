import socket
import ssl
import threading
import os
import time

import constants
from tcp_handler import handle_tcp_client
from web_handler import handle_web_client
from ftp_handler import handle_ftp_client

def _server_main_loop(port, log_callback, update_gui_states_callback,
                      server_mode, web_root_dir, ftp_root_dir,
                      ssl_cert_file, ssl_key_file):
    """
    The main loop for the server, run in a separate thread.
    Listens for incoming connections and spawns client handlers.

    Args:
        port (int): The port number to bind the server to.
        log_callback (function): A callback function to log messages to the GUI.
        update_gui_states_callback (function): A callback function to update
                                               GUI elements.
        server_mode (str): The current server mode ("tcp", "web", "https", "ftp").
        web_root_dir (str): The root directory for web serving.
        ftp_root_dir (str): The root directory for FTP serving.
        ssl_cert_file (str): Path to the SSL certificate file.
        ssl_key_file (str): Path to the SSL key file.
    """
    constants.WEB_ROOT_DIR = web_root_dir
    constants.FTP_ROOT_DIR = ftp_root_dir
    constants.SSL_CERT_FILE = ssl_cert_file
    constants.SSL_KEY_FILE = ssl_key_file
    constants.SERVER_MODE = server_mode

    if constants.SERVER_MODE == "web" or constants.SERVER_MODE == "https":
        if not constants.WEB_ROOT_DIR or not os.path.isdir(constants.WEB_ROOT_DIR):
            log_callback(
                "[-] Web Server mode selected, but Web Root Directory is "
                "invalid or not set.", 'error'
            )
            log_callback(
                "[-] Please select a valid directory for web hosting.",
                'error'
            )
            constants.SERVER_RUNNING = False
            update_gui_states_callback()
            return
        log_callback(
            f"[*] Web Server Mode ({constants.SERVER_MODE.upper()}): "
            f"Serving files from: {constants.WEB_ROOT_DIR}", 'info'
        )

    if constants.SERVER_MODE == "https":
        if not constants.SSL_CERT_FILE or not os.path.isfile(constants.SSL_CERT_FILE):
            log_callback(
                "[-] HTTPS mode selected, but SSL Certificate file is "
                "invalid or not set.", 'error'
            )
            log_callback(
                "[-] Please select a valid .pem certificate file.",
                'error'
            )
            constants.SERVER_RUNNING = False
            update_gui_states_callback()
            return
        if not constants.SSL_KEY_FILE or not os.path.isfile(constants.SSL_KEY_FILE):
            log_callback(
                "[-] HTTPS mode selected, but SSL Key file is invalid or "
                "not set.", 'error'
            )
            log_callback(
                "[-] Please select a valid .pem key file.", 'error'
            )
            constants.SERVER_RUNNING = False
            update_gui_states_callback()
            return
        log_callback(
            f"[*] HTTPS Mode: Using Certificate: {constants.SSL_CERT_FILE}", 'info'
        )
        log_callback(f"[*] HTTPS Mode: Using Key: {constants.SSL_KEY_FILE}", 'info')

    elif constants.SERVER_MODE == "ftp":
        if not constants.FTP_ROOT_DIR or not os.path.isdir(constants.FTP_ROOT_DIR):
            log_callback(
                "[-] FTP Server mode selected, but FTP Root Directory is "
                "invalid or not set.", 'error'
            )
            log_callback(
                "[-] Please select a valid directory for FTP hosting.",
                'error'
            )
            constants.SERVER_RUNNING = False
            update_gui_states_callback()
            return
        log_callback(
            f"[*] FTP Server Mode: Serving files from: {constants.FTP_ROOT_DIR}",
            'info'
        )
        log_callback("[*] FTP Login: User 'ftpuser', Pass 'ftppass'", 'info')

    bind_ip = "0.0.0.0"

    constants.SERVER_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    constants.SERVER_SOCKET.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        constants.SERVER_SOCKET.bind((bind_ip, port))
    except socket.error as e:
        log_callback(
            f"[-] Could not bind to port {port}: {e}", 'error'
        )
        log_callback(
            "[-] Please check if the port is already in use or if you "
            "have sufficient permissions.", 'error'
        )
        constants.SERVER_RUNNING = False
        update_gui_states_callback()
        return

    constants.SERVER_SOCKET.listen(5)
    log_callback(f"[*] Listening on {bind_ip}:{port}", 'info')

    # Wrap socket with SSL if in HTTPS mode
    if constants.SERVER_MODE == "https":
        try:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=constants.SSL_CERT_FILE,
                                    keyfile=constants.SSL_KEY_FILE)
            constants.SERVER_SOCKET = context.wrap_socket(constants.SERVER_SOCKET,
                                                          server_side=True)
            log_callback("[*] Server socket wrapped with SSL/TLS.", 'success')
        except ssl.SSLError as e:
            log_callback(f"[-] SSL Error wrapping socket: {e}", 'error')
            log_callback(
                "[-] Please check your SSL certificate and key files.",
                'error'
            )
            constants.SERVER_RUNNING = False
            constants.SERVER_SOCKET.close()
            update_gui_states_callback()
            return
        except FileNotFoundError as e:
            log_callback(
                f"[-] SSL Certificate or Key file not found: {e}", 'error'
            )
            constants.SERVER_RUNNING = False
            constants.SERVER_SOCKET.close()
            update_gui_states_callback()
            return
        except Exception as e:
            log_callback(
                f"[-] General error during SSL setup: {e}", 'error'
            )
            constants.SERVER_RUNNING = False
            constants.SERVER_SOCKET.close()
            update_gui_states_callback()
            return

    constants.SERVER_RUNNING = True
    update_gui_states_callback()
    constants.SERVER_SOCKET.settimeout(1.0)

    while constants.SERVER_RUNNING:
        try:
            client, addr = constants.SERVER_SOCKET.accept()
            log_callback(
                f"[*] Accepted connection from: {addr[0]}:{addr[1]} "
                f"(Mode: {constants.SERVER_MODE})", 'info'
            )

            if constants.SERVER_MODE == "tcp":
                client_handler = threading.Thread(
                    target=handle_tcp_client, args=(client, addr, log_callback)
                )
            elif constants.SERVER_MODE == "web" or constants.SERVER_MODE == "https":
                client_handler = threading.Thread(
                    target=handle_web_client, args=(client, addr, log_callback, constants.WEB_ROOT_DIR)
                )
            elif constants.SERVER_MODE == "ftp":
                client_handler = threading.Thread(
                    target=handle_ftp_client, args=(client, addr, log_callback, constants.FTP_ROOT_DIR)
                )
            else:
                log_callback(f"[-] Unknown server mode: {constants.SERVER_MODE}", 'error')
                client.close()
                continue

            client_handler.daemon = True
            client_handler.start()
        except socket.timeout:
            continue
        except ConnectionResetError:
            log_callback(
                f"[-] Server socket received a connection reset "
                f"during accept.", 'warning'
            )
            continue
        except Exception as e:
            if constants.SERVER_RUNNING:
                log_callback(
                    f"[-] Error accepting connection: {e}", 'error'
                )
            break

    log_callback("[*] Server main loop exited.", 'info')
    update_gui_states_callback()

def stop_server(log_callback, update_gui_states_callback):
    """
    Initiates the server shutdown process.
    Sets a global flag to stop the server's main loop and closes the
    server socket.
    """
    if not constants.SERVER_RUNNING:
        log_callback("[*] Server is not running.", 'warning')
        return

    log_callback("[*] Stopping server...", 'info')
    constants.SERVER_RUNNING = False

    time.sleep(0.1) # Give a moment for the main loop to see the flag change

    if constants.SERVER_SOCKET:
        try:
            # For HTTPS, shutdown might be different or not needed before close
            if constants.SERVER_MODE != "https":
                constants.SERVER_SOCKET.shutdown(socket.SHUT_RDWR)
            constants.SERVER_SOCKET.close()
            log_callback("[*] Server socket closed.", 'info')
        except Exception as e:
            log_callback(
                f"[-] Error closing server socket: {e}", 'error'
            )

    log_callback(
        "[*] Server stop signal sent. Waiting for thread to terminate...",
        'info'
    )
    update_gui_states_callback()