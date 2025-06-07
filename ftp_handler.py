import socket
import os
import ipaddress
import constants

def _ftp_send_response(sock, code, message, log_callback):
    """
    Sends an FTP response to the client.

    Args:
        sock (socket.socket): The client control socket.
        code (int): The FTP response code.
        message (str): The FTP response message.
        log_callback (function): A callback function to log messages.
    """
    response = f"{code} {message}\r\n"
    try:
        sock.sendall(response.encode('utf-8'))
        log_callback(f"[FTP] Sent {code}: {message}", 'info')
    except ConnectionResetError:
        log_callback(
            f"[-] FTP Client {sock.getpeername()[0]}:"
            f"{sock.getpeername()[1]} reset connection "
            f"during FTP response.", 'warning'
        )
    except Exception as e:
        log_callback(f"[-] FTP Send Error: {e}", 'error')

def _ftp_open_data_connection(data_addr, data_port, log_callback):
    """
    Attempts to establish an active mode FTP data connection.

    Args:
        data_addr (str): The IP address for the data connection.
        data_port (int): The port for the data connection.
        log_callback (function): A callback function to log messages.

    Returns:
        socket.socket or None: The data socket if successful, None otherwise.
    """
    data_socket = None
    try:
        data_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        data_socket.settimeout(10)
        data_socket.connect((data_addr, data_port))
        log_callback(
            f"[FTP] Active data connection established to "
            f"{data_addr}:{data_port}", 'info'
        )
        return data_socket
    except ConnectionResetError:
        log_callback(
            f"[-] FTP Client {data_addr}:{data_port} reset "
            f"connection during active data connect.", 'warning'
        )
        if data_socket:
            data_socket.close()
        return None
    except Exception as e:
        log_callback(f"[-] FTP Active Data Connect Error: {e}", 'error')
        if data_socket:
            data_socket.close()
        return None

def _ftp_start_pasv_listener(log_callback):
    """
    Starts a passive mode FTP data listener.

    Args:
        log_callback (function): A callback function to log messages.

    Returns:
        tuple: (listener_socket, address, port) if successful, (None, None, None) otherwise.
    """
    pasv_listener = None
    try:
        pasv_listener = socket.socket(
            socket.AF_INET, socket.SOCK_STREAM
        )
        pasv_listener.setsockopt(
            socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
        )
        pasv_listener.bind(('0.0.0.0', 0))
        pasv_listener.listen(1)
        addr, port = pasv_listener.getsockname()
        log_callback(
            f"[FTP] Passive listener started on {addr}:{port}",
            'info'
        )
        return pasv_listener, addr, port
    except Exception as e:
        log_callback(f"[-] FTP Passive Listener Error: {e}", 'error')
        if pasv_listener:
            pasv_listener.close()
        return None, None, None

def _ftp_accept_pasv_connection(pasv_listener, log_callback):
    """
    Accepts a passive mode FTP data connection.

    Args:
        pasv_listener (socket.socket): The passive listener socket.
        log_callback (function): A callback function to log messages.

    Returns:
        socket.socket or None: The data socket if accepted, None otherwise.
    """
    data_socket = None
    if not pasv_listener:
        return None
    try:
        data_socket, _ = pasv_listener.accept()
        data_socket.settimeout(10)
        log_callback("[FTP] Passive data connection accepted.", 'info')
        return data_socket
    except socket.timeout:
        log_callback("[-] FTP Passive Data Accept Timeout.", 'warning')
        if data_socket:
            data_socket.close()
        return None
    except ConnectionResetError:
        log_callback(
            f"[-] FTP Client reset connection during passive "
            f"data accept.", 'warning'
        )
        if data_socket:
            data_socket.close()
        return None
    except Exception as e:
        log_callback(f"[-] FTP Passive Data Accept Error: {e}", 'error')
        if data_socket:
            data_socket.close()
        return None
    finally:
        if pasv_listener:
            pasv_listener.close() # Close listener once connection is accepted or failed
            pasv_listener = None


def handle_ftp_client(client_socket, client_address, log_callback, ftp_root_dir):
    """
    Handles an individual FTP client connection.

    Args:
        client_socket (socket.socket): The socket object for the client connection.
        client_address (tuple): A tuple containing the client's IP address
                                and port.
        log_callback (function): A callback function to log messages to the GUI.
        ftp_root_dir (str): The configured FTP root directory.
    """
    authenticated = False
    ftp_username_attempt = None
    current_ftp_dir = os.path.abspath(ftp_root_dir) # Start at absolute path
    data_socket = None
    pasv_listener = None # Renamed to avoid confusion with data_socket

    _ftp_send_response(client_socket, 220,
                      "Welcome to the Python FTP Server.", log_callback)

    try:
        while constants.SERVER_RUNNING: # Check global server running flag
            try:
                client_socket.settimeout(0.5) # Short timeout to check SERVER_RUNNING
                command_line = client_socket.recv(1024).decode(
                    'utf-8', errors='ignore'
                ).strip()
            except socket.timeout:
                continue # Continue if no data, allowing SERVER_RUNNING to be checked
            except ConnectionResetError:
                log_callback(
                    f"[-] FTP Client {client_address[0]}:"
                    f"{client_address[1]} reset connection during "
                    f"command recv.", 'warning'
                )
                break
            except Exception as e:
                log_callback(
                    f"[-] FTP Client Recv Error {client_address[0]}:"
                    f"{client_address[1]}: {e}", 'error'
                )
                break

            if not command_line:
                log_callback(
                    f"[*] FTP Client {client_address[0]}:"
                    f"{client_address[1]} disconnected.", 'info'
                )
                break

            log_callback(
                f"[FTP] Received from {client_address[0]}:"
                f"{client_address[1]}: {command_line}", 'info'
            )

            parts = command_line.split(' ', 1)
            cmd = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""

            if cmd == "USER":
                if arg == "ftpuser": # Hardcoded username
                    _ftp_send_response(client_socket, 331,
                                      "Password required for ftpuser.", log_callback)
                    ftp_username_attempt = arg
                else:
                    ftp_username_attempt = None
                    _ftp_send_response(
                        client_socket, 530,
                        "Not logged in, username incorrect.", log_callback
                    )
            elif cmd == "PASS":
                if ftp_username_attempt == "ftpuser" and \
                        arg == "ftppass": # Hardcoded password
                    authenticated = True
                    _ftp_send_response(client_socket, 230,
                                      "User logged in, proceed.", log_callback)
                    # current_ftp_dir is already set to absolute FTP_ROOT_DIR
                    log_callback(
                        f"[FTP] Client {client_address[0]}:"
                        f"{client_address[1]} authenticated. Root: "
                        f"{current_ftp_dir}", 'success'
                    )
                else:
                    authenticated = False
                    _ftp_send_response(
                        client_socket, 530,
                        "Not logged in, password incorrect.", log_callback
                    )
            elif cmd == "QUIT":
                _ftp_send_response(client_socket, 221, "Goodbye.", log_callback)
                break

            elif not authenticated:
                _ftp_send_response(client_socket, 530, "Not logged in.", log_callback)

            elif cmd == "SYST":
                _ftp_send_response(client_socket, 215, "UNIX Type: L8", log_callback)
            elif cmd == "FEAT":
                _ftp_send_response(
                    client_socket, 211, "Extensions supported:\r\n "
                    "PASV\r\n QUIT", log_callback
                )
                _ftp_send_response(client_socket, 211, "End", log_callback) # End of FEAT response
            elif cmd == "PWD":
                # Ensure path is relative to the FTP_ROOT_DIR and starts with /
                display_path = os.path.relpath(
                    current_ftp_dir, ftp_root_dir
                ).replace('\\', '/')
                if display_path == '.':
                    display_path = '/'
                elif not display_path.startswith('/'):
                    display_path = '/' + display_path
                _ftp_send_response(
                    client_socket, 257,
                    f'"{display_path}" is current directory.', log_callback
                )
            elif cmd == "CWD":
                requested_path = os.path.normpath(
                    os.path.join(current_ftp_dir, arg)
                )
                abs_requested_path = os.path.abspath(requested_path)
                abs_ftp_root_dir = os.path.abspath(ftp_root_dir)

                # Prevent directory traversal
                if not abs_requested_path.startswith(abs_ftp_root_dir):
                    _ftp_send_response(
                        client_socket, 550,
                        "Permission denied. Cannot go outside root directory.", log_callback
                    )
                elif os.path.isdir(abs_requested_path):
                    current_ftp_dir = abs_requested_path
                    _ftp_send_response(client_socket, 250,
                                      "Directory successfully changed.", log_callback)
                else:
                    _ftp_send_response(
                        client_socket, 550,
                        "Failed to change directory. Directory not found.", log_callback
                    )

            elif cmd == "PORT":
                try:
                    parts = [int(x) for x in arg.split(',')]
                    data_addr = ".".join(map(str, parts[0:4]))
                    data_port = parts[4] * 256 + parts[5]

                    try:
                        ipaddress.ip_address(data_addr)
                    except ValueError:
                        _ftp_send_response(
                            client_socket, 501,
                            "Syntax error in parameters or arguments.", log_callback
                        )
                        continue

                    data_socket = _ftp_open_data_connection(data_addr, data_port, log_callback)
                    if data_socket:
                        _ftp_send_response(
                            client_socket, 200,
                            "PORT command successful. Consider using PASV.", log_callback
                        )
                    else:
                        _ftp_send_response(
                            client_socket, 425,
                            "Can't open data connection.", log_callback
                        )
                except Exception:
                    _ftp_send_response(
                        client_socket, 501,
                        "Syntax error in parameters or arguments.", log_callback
                    )
            elif cmd == "PASV":
                pasv_listener, addr, port = _ftp_start_pasv_listener(log_callback)
                if addr and port:
                    ip_parts = addr.split('.')
                    p1 = port // 256
                    p2 = port % 256
                    _ftp_send_response(
                        client_socket, 227,
                        f"Entering Passive Mode ({ip_parts[0]},"
                        f"{ip_parts[1]},{ip_parts[2]},{ip_parts[3]},"
                        f"{p1},{p2}).", log_callback
                    )
                else:
                    _ftp_send_response(
                        client_socket, 421,
                        "Service not available, closing control connection.", log_callback
                    )
                    break # Critical error, close connection

            elif cmd == "LIST":
                if data_socket or pasv_listener: # Check if either active or passive data connection is set up
                    _ftp_send_response(
                        client_socket, 150,
                        "Opening ASCII mode data connection for file list.", log_callback
                    )
                    # If passive listener is set up, accept the connection
                    if pasv_listener:
                        accepted_data_socket = _ftp_accept_pasv_connection(pasv_listener, log_callback)
                        if accepted_data_socket:
                            data_socket = accepted_data_socket # Use the newly accepted socket
                        else:
                            _ftp_send_response(
                                client_socket, 425,
                                "Can't open data connection.", log_callback
                            )
                            continue # Skip to next command if data connection failed to establish

                    if data_socket: # Now data_socket should be valid for both PORT and PASV
                        try:
                            files = os.listdir(current_ftp_dir)
                            list_output = ""
                            for item in files:
                                full_path = os.path.join(current_ftp_dir, item)
                                if os.path.isdir(full_path):
                                    list_output += (
                                        "drwxr-xr-x 1 ftp ftp 0 Jan 01 "
                                        "00:00 "
                                        f"{item}\r\n"
                                    )
                                else:
                                    size = os.path.getsize(full_path)
                                    list_output += (
                                        "-rw-r--r-- 1 ftp ftp "
                                        f"{size} Jan 01 00:00 {item}\r\n"
                                    )
                            data_socket.sendall(list_output.encode('utf-8'))
                            _ftp_send_response(client_socket, 226,
                                              "Transfer complete.", log_callback)
                        except (ConnectionResetError, socket.timeout) as e:
                            log_callback(
                                f"[-] FTP Data Transfer Error (LIST): {e}",
                                'warning'
                            )
                            _ftp_send_response(client_socket, 426,
                                              "Connection closed; transfer aborted.", log_callback)
                        except Exception as e:
                            _ftp_send_response(client_socket, 550,
                                              f"Failed to list directory: {e}", log_callback)
                        finally:
                            if data_socket:
                                data_socket.close()
                                data_socket = None
                    else: # Fallback if data_socket became None after accept attempt
                        _ftp_send_response(
                            client_socket, 425,
                            "Can't open data connection.", log_callback
                        )
                else:
                    _ftp_send_response(
                        client_socket, 425, "Use PORT or PASV first.", log_callback
                    )

            elif cmd == "RETR":
                file_to_retrieve = os.path.join(current_ftp_dir, arg)
                abs_file_path = os.path.abspath(file_to_retrieve)
                abs_ftp_root_dir = os.path.abspath(ftp_root_dir)

                if not abs_file_path.startswith(abs_ftp_root_dir):
                    _ftp_send_response(
                        client_socket, 550,
                        "Permission denied. Cannot retrieve file outside root.", log_callback
                    )
                elif not os.path.exists(file_to_retrieve) or \
                        not os.path.isfile(file_to_retrieve):
                    _ftp_send_response(client_socket, 550,
                                      "File not found.", log_callback)
                elif data_socket or pasv_listener:
                    _ftp_send_response(
                        client_socket, 150,
                        f"Opening BINARY mode data connection for {arg}.", log_callback
                    )
                    if pasv_listener:
                        accepted_data_socket = _ftp_accept_pasv_connection(pasv_listener, log_callback)
                        if accepted_data_socket:
                            data_socket = accepted_data_socket
                        else:
                            _ftp_send_response(
                                client_socket, 425,
                                "Can't open data connection.", log_callback
                            )
                            continue

                    if data_socket:
                        try:
                            with open(file_to_retrieve, 'rb') as f:
                                while True:
                                    chunk = f.read(4096)
                                    if not chunk:
                                        break
                                    data_socket.sendall(chunk)
                            _ftp_send_response(client_socket, 226,
                                              "Transfer complete.", log_callback)
                        except (ConnectionResetError, socket.timeout) as e:
                            log_callback(
                                f"[-] FTP Data Transfer Error (RETR): {e}",
                                'warning'
                            )
                            _ftp_send_response(client_socket, 426,
                                              "Connection closed; transfer aborted.", log_callback)
                        except Exception as e:
                            _ftp_send_response(client_socket, 550,
                                              f"Failed to retrieve file: {e}", log_callback)
                        finally:
                            if data_socket:
                                data_socket.close()
                                data_socket = None
                    else:
                        _ftp_send_response(
                            client_socket, 425,
                            "Can't open data connection.", log_callback
                        )
                else:
                    _ftp_send_response(
                        client_socket, 425, "Use PORT or PASV first.", log_callback
                    )

            elif cmd == "STOR":
                file_to_store = os.path.join(current_ftp_dir, arg)
                abs_file_path = os.path.abspath(file_to_store)
                abs_ftp_root_dir = os.path.abspath(ftp_root_dir)

                if not abs_file_path.startswith(abs_ftp_root_dir):
                    _ftp_send_response(
                        client_socket, 550,
                        "Permission denied. Cannot store file outside root.", log_callback
                    )
                elif data_socket or pasv_listener:
                    _ftp_send_response(
                        client_socket, 150,
                        f"Opening BINARY mode data connection for {arg}.", log_callback
                    )
                    if pasv_listener:
                        accepted_data_socket = _ftp_accept_pasv_connection(pasv_listener, log_callback)
                        if accepted_data_socket:
                            data_socket = accepted_data_socket
                        else:
                            _ftp_send_response(
                                client_socket, 425,
                                "Can't open data connection.", log_callback
                            )
                            continue

                    if data_socket:
                        try:
                            with open(file_to_store, 'wb') as f:
                                while True:
                                    chunk = data_socket.recv(4096)
                                    if not chunk:
                                        break
                                    f.write(chunk)
                            _ftp_send_response(client_socket, 226,
                                              "Transfer complete.", log_callback)
                        except (ConnectionResetError, socket.timeout) as e:
                            log_callback(
                                f"[-] FTP Data Transfer Error (STOR): {e}",
                                'warning'
                            )
                            _ftp_send_response(client_socket, 426,
                                              "Connection closed; transfer aborted.", log_callback)
                        except Exception as e:
                            _ftp_send_response(client_socket, 550,
                                              f"Failed to store file: {e}", log_callback)
                        finally:
                            if data_socket:
                                data_socket.close()
                                data_socket = None
                    else:
                        _ftp_send_response(
                            client_socket, 425,
                            "Can't open data connection.", log_callback
                        )
                else:
                    _ftp_send_response(
                        client_socket, 425, "Use PORT or PASV first.", log_callback
                    )

            else:
                _ftp_send_response(client_socket, 502,
                                  "Command not implemented.", log_callback)

    except Exception as e:
        log_callback(
            f"[-] FTP Client Error {client_address[0]}:"
            f"{client_address[1]}: {e}", 'error'
        )
    finally:
        if data_socket:
            data_socket.close()
        if pasv_listener: # Make sure the listener is closed if still open
            pasv_listener.close()
        client_socket.close()