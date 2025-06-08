import socket

def handle_tcp_client(client_socket, client_address, log_callback):
    """
    Handles an individual TCP client connection.

    Args:
        client_socket (socket.socket): The socket object for the client connection.
        client_address (tuple): A tuple containing the client's IP address and port.
        log_callback (function): A callback function to log messages to the GUI.
    """
    client_socket.settimeout(1.0)
    try:
        request = client_socket.recv(1024)
        if not request:
            log_callback(
                f"[*] Client {client_address[0]}:{client_address[1]} "
                f"disconnected.", 'info'
            )
            return
        log_callback(
            f"[*] Received from {client_address[0]}:"
            f"{client_address[1]}: "
            f"{request.decode('utf-8', errors='ignore')}", 'info'
        )
        client_socket.sendall(b"ACK!")
    except ConnectionResetError:
        log_callback(
            f"[-] Client {client_address[0]}:{client_address[1]} "
            f"reset the connection.", 'warning'
        )
    except socket.timeout:
        log_callback(
            f"[*] Client {client_address[0]}:{client_address[1]} "
            f"timed out (TCP).", 'info'
        )
    except Exception as e:
        log_callback(
            f"[-] Error handling client {client_address[0]}:"
            f"{client_address[1]}: {e}", 'error'
        )
    finally:
        client_socket.close()