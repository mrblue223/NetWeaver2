import os
import mimetypes
import socket
import ssl

def send_http_response(client_socket, status_code, status_message,
                       content, content_type="text/html", log_callback=None):
    """
    Sends an HTTP response to the client.

    Args:
        client_socket (socket.socket or ssl.SSLSocket):
            The client socket to send the response to.
        status_code (int): The HTTP status code (e.g., 200, 404, 500).
        status_message (str): The HTTP status message (e.g., "OK",
                              "Not Found").
        content (str or bytes): The content of the response body.
        content_type (str, optional): The MIME type of the content.
                                      Defaults to "text/html".
        log_callback (function, optional): A callback function to log messages.
                                           Defaults to None.
    """
    response_line = f"HTTP/1.1 {status_code} {status_message}\r\n"

    if isinstance(content, bytes):
        content_length = len(content)
    else:
        content_length = len(content.encode('utf-8'))

    headers = f"Content-Type: {content_type}\r\n"
    headers += f"Content-Length: {content_length}\r\n"
    headers += "Connection: close\r\n"
    headers += "\r\n"

    if isinstance(content, str):
        content_bytes = content.encode('utf-8')
    else:
        content_bytes = content

    response = response_line.encode('utf-8') + \
        headers.encode('utf-8') + content_bytes
    try:
        client_socket.sendall(response)
    except ConnectionResetError:
        if log_callback:
            peer_name = client_socket.getpeername()
            log_callback(
                f"[-] Client {peer_name[0]}:{peer_name[1]} reset connection "
                f"during HTTP response.", 'warning'
            )
    except Exception as e:
        if log_callback:
            log_callback(f"[-] Error sending HTTP response: {e}", 'error')

def handle_web_client(client_socket, client_address, log_callback, web_root_dir):
    """
    Handles an individual Web/HTTPS client connection.

    Args:
        client_socket (socket.socket or ssl.SSLSocket):
            The socket object for the client connection.
        client_address (tuple): A tuple containing the client's IP address
                                and port.
        log_callback (function): A callback function to log messages to the GUI.
        web_root_dir (str): The configured web root directory.
    """
    client_socket.settimeout(1.0)
    try:
        request_data = client_socket.recv(4096).decode(
            'utf-8', errors='ignore'
        )
        if not request_data:
            log_callback(
                f"[*] Web Client {client_address[0]}:{client_address[1]} "
                f"disconnected.", 'info'
            )
            return

        first_line = request_data.split('\n')[0]
        log_callback(
            f"[*] Web Request from {client_address[0]}:"
            f"{client_address[1]}: {first_line}", 'info'
        )

        parts = first_line.split(' ')
        if len(parts) < 2:
            send_http_response(
                client_socket, 400, "Bad Request",
                "<h1>400 Bad Request</h1>", log_callback=log_callback
            )
            log_callback(
                f"[-] Bad Web Request from {client_address[0]}:"
                f"{client_address[1]}", 'warning'
            )
            return

        method = parts[0]
        path = parts[1]

        if method != 'GET':
            send_http_response(
                client_socket, 405, "Method Not Allowed",
                "<h1>405 Method Not Allowed</h1>", log_callback=log_callback
            )
            log_callback(
                f"[-] Method Not Allowed: {method} from "
                f"{client_address[0]}:{client_address[1]}", 'warning'
            )
            return

        clean_path = os.path.normpath(path).replace('\\', '/')
        if clean_path.startswith('/'):
            clean_path = clean_path[1:]

        if not clean_path or clean_path.endswith('/'):
            clean_path = os.path.join(clean_path, 'index.html')

        file_path = os.path.join(web_root_dir, clean_path)

        abs_file_path = os.path.abspath(file_path)
        abs_web_root_dir = os.path.abspath(web_root_dir)

        if not abs_file_path.startswith(abs_web_root_dir):
            log_callback(
                f"[-] Attempted directory traversal: {file_path} from "
                f"{client_address[0]}:{client_address[1]}", 'error'
            )
            send_http_response(
                client_socket, 403, "Forbidden", "<h1>403 Forbidden</h1>",
                log_callback=log_callback
            )
            return

        if os.path.exists(file_path) and os.path.isfile(file_path):
            mimetype, _ = mimetypes.guess_type(file_path)
            if not mimetype:
                mimetype = 'application/octet-stream'

            with open(file_path, 'rb') as f:
                content = f.read()

            send_http_response(
                client_socket, 200, "OK", content, mimetype,
                log_callback=log_callback
            )
            log_callback(
                f"[+] Served: {file_path} (Type: {mimetype}) to "
                f"{client_address[0]}:{client_address[1]}", 'success'
            )
        else:
            send_http_response(
                client_socket, 404, "Not Found", "<h1>404 Not Found</h1>",
                log_callback=log_callback
            )
            log_callback(
                f"[-] File not found: {file_path} for "
                f"{client_address[0]}:{client_address[1]}", 'warning'
            )
    except socket.timeout:
        log_callback(
            f"[*] Web Client {client_address[0]}:{client_address[1]} "
            f"timed out (Web).", 'info'
        )
    except ssl.SSLError as e:
        log_callback(
            f"[-] SSL Error with client {client_address[0]}:"
            f"{client_address[1]}: {e}", 'warning'
        )
    except ConnectionResetError:
        log_callback(
            f"[-] Web Client {client_address[0]}:{client_address[1]} "
            f"reset connection during web request.", 'warning'
        )
    except Exception as e:
        log_callback(
            f"[-] Error handling web client {client_address[0]}:"
            f"{client_address[1]}: {e}", 'error'
        )
        send_http_response(
            client_socket, 500, "Internal Server Error",
            "<h1>500 Internal Server Error</h1>", log_callback=log_callback
        )
    finally:
        client_socket.close()