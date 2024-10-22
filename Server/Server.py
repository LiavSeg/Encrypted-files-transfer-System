"""
    Server class builds a multithreaded TCP server environment that handles client requests
    for file management and encryption using a SQLite database and pycryptodome lib
"""
import socket
import threading
import constants
import DefensiveDB
from requestHandler import RequestHandler
from DefensiveDB import DefensiveDB
from pathlib import Path
from CryptoHandler import CryptoHandler


class Server:
    def __init__(self):
        """ Constractor for Server class """
        self.database = DefensiveDB()
        self.crypto_handler = CryptoHandler(self.database)
        self.make_backup_path()

    def start_server(self):
        """
        Starts the server, binding it and start listening for incoming clients
        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as self.server_socket:
            listening = self.set_connection()
            while True and listening:
                self.accept_client()

    def handle_client(self, client_socket):
        """
            Handles Client communication with the server
            Parses client requests and sends responses back to the client
            Each communication is will be used in thread
           """
        request_handler = RequestHandler(client_socket, self.database, self.crypto_handler)
        try:
            while True:
                response = request_handler.handle_request()
                if not response:
                    break
                request_handler.send_response(response)
        except Exception as e:
            raise ValueError(f'Server error: While handling client {e}')
        finally:
            client_socket.close()

    def set_connection(self):
        """
            Binds the server socket to the host and port for listening
            Port data is on a file port.info, if this one does not exist
            The server will be connected to A protocol defined default port
        """
        host = '127.0.0.1'
        port = self.get_port_info()
        try:
            self.server_socket.bind((host, port))
            print(f'listening on {host}:{port}\n############################')
            self.server_socket.listen(0)
            return True
        except Exception as e:
            if isinstance(e, OSError):
                print(f"Server error: While setting connection could not bind to {host}:{port} - {e}")
            else:
                print(f"Server error: While setting connection {e}")
            return False

    def accept_client(self):
        """ Accepts a new client connection and starts a new thread to handle it """
        try:
            client_socket, addr = self.server_socket.accept()
            print(f'Client connected {str(addr)}')
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.start()
        except Exception as e:
            print(f'Server Error: While accepting new client {e}')

    def get_port_info(self):
        """Gets the port number from port.info file if it exists, otherwise returns the default protocol port"""
        port = constants.DEFUALT_PORT
        try:
            with open('port.info') as file:
                file_content = file.read()
                port_string = ''.join(file_content.split())
                port = int(port_string)
        except FileNotFoundError:
            print("Server warning: Port info file was not found - connecting to default port")
        return port

    def make_backup_path(self):
        """Creates a backup path for the clients files if it's not existed yet"""
        try:
            home = Path.home()
            path = home / constants.BACKUP_PATH_NAME
            path.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            print(f'Server error: Could not create backup path {e} ')
            exit(1)


def main():
    server = Server()
    server.start_server()


if __name__ == '__main__':
    main()
