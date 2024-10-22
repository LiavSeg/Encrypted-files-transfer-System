"""
    Request Handler class handles all client's requests related operations and responses
    Included data receiving and sending via socket
"""
import os
import socket
import struct
import uuid
import constants
from cksum import readfile
from DefensiveDB import DefensiveDB
import Exceptions
from CryptoHandler import CryptoHandler


class RequestHandler:
    def __init__(self, client_socket: socket, database: DefensiveDB, crypto_handler: CryptoHandler):
        self.database = database
        self.crypto_handler = crypto_handler
        self.client_socket = client_socket
        self.error_response = self.init_response(constants.VERSION, constants.GENERAL_ERROR, 0, b'')
        self.response_map = self.create_operations_map()

    # =========================== Packets handling  ===========================
    def handle_request(self) -> bytes:
        """ Receives a request from the client - a fixed size header followed by a dynamically sized payload
            returns a response for the client according the code request and protocol demands
        """
        try:
            data = self.client_socket.recv(constants.HEADER_SIZE)
            if len(data) == 0:
                return b''
            header = struct.unpack('<16sBHI', data)
            payload_size = header[constants.PAYLOAD_SIZE_INDEX]
            payload = self.receive_payload(payload_size)
            return self.req_select(header, payload)
        except Exception as e:
            print(f'Server error: while receiving request from the client {e}')  # handle it
            return b''

    def receive_payload(self, payload_size) -> bytes:
        to_get = min(payload_size, constants.CHUNK_SIZE)
        size = payload_size
        payload = bytearray()
        try:
            while size > 0:
                data = self.client_socket.recv(to_get)
                payload.extend(data)
                size -= to_get
                to_get = min(size, constants.CHUNK_SIZE)
        except ConnectionResetError or OSError as e:
            raise e
        return payload

    def send_response(self, response) -> bool:
        try:
            self.client_socket.sendall(response)
            return True
        except socket.error as e:
            print(f'Could not send data {e}')
            return False

    # =========================== Response Handlers ===========================

    def init_response(self, version: int, code: int, payload_size: int, payload: bytes) -> bytes:
        """Initializes a response by packing the version, code, payload size, and payload. """
        response = struct.pack(f'< BHI', version, code, payload_size) + payload
        return response

    # ===========================
    # New client registration process functions: client's request 825, server's response 1600/1601/error(1607)
    # ===========================
    def register_new_client(self, uid: bytes, version: int, payload: bytes) -> bytes:  # response 1600
        """
         Handles client request 825 - register as a new client to this server.
         This method checks if the username provided by the client is in the server's
         and responding accordingly:
         - username exists: registration failed (code 1601)
         - username does not exist: username being added to the db, registration succeeded (code 1600)
        """
        try:
            name = payload.decode('ascii')
            client_id, code = self.database.find_username(name)
            if code == constants.REGISTRATION_FAIL:
                print(f'Server Error: During registration process client {name[:-1]} is already registered')
                return self.init_response(constants.VERSION, code, len(client_id), client_id)
            else:
                client_id = self.add_new_client_to_db(name)
            return self.init_response(version, code, len(client_id.bytes), client_id.bytes)
        except Exception as e:
            return Exceptions.register_new_client_exceptions(e)

    def add_new_client_to_db(self, name):
        """This function generates UUID for a new client and adds user's details to the server's database """
        client_id = uuid.uuid4()
        self.database.add_new_client_db(client_id.bytes, name)
        print(f'Server: Client {name} was registered successfully')
        return client_id

    # ===========================
    # RSA and AES Key swapping process functions: client's request 826, server's response 1602/error(1607)
    # ===========================
    def handle_public_key(self, uid: bytes, version: int, payload: bytes) -> bytes:  # response 1602
        """
        Handles response 1602 for client request 802
        This method sets the public key for the specified user ID in the serve's SQLite database, generates a
        corresponding AES key, and constructs a response containing the user ID and the generated AES key.
        """
        try:
            self.set_public_key(uid, payload)
            aes = self.crypto_handler.generate_aes_key(uid)
            pay = b''.join([uid, aes])
            response = self.init_response(version, constants.IN_PUBLIC_KEY_OUT_AES, len(pay), pay)
            print('Server: Sending encrypted AES to the client')
            return response
        except Exception as e:
            print(f'Server error: During public key handling {e}')
            return self.error_response  # code = 1607

    def set_public_key(self, uid: bytes, payload: bytes) -> None:
        """ validates and sets into the server's db the public key that the client sent"""
        try:
            Exceptions.validate_public_key_payload(payload)
            name, public_key = struct.unpack(f'<{len(payload) - constants.PUBLIC_KEY}s{constants.PUBLIC_KEY}s',
                                             payload)
            self.database.update_entry(constants.CLIENTS_TABLE, uid, constants.PUBLIC_KEY_FIELD, public_key)
            print('Server: recieved RSA public key successfully ')
        except Exception as e:
            raise e

    # ===========================
    # Existing client Sign in  process : client's request 825, server's response: 1605-approved/1606-declined/1607-error
    # ===========================
    def handle_sign_in_reqeust(self, uid: bytes, version: int, payload: bytes) -> bytes:
        try:
            aes = self.crypto_handler.generate_aes_key(uid)  # raises
            payload = b''.join([uid, aes])
            print('Server: Client signed in successfully.\nServer: Sending encrypted AES key')
            return self.init_response(constants.VERSION, constants.RECCONECT_APPROVED, len(payload), payload)
        except Exception as e:
            print(f'Server error: During sign in process {e}')
            return self.init_response(constants.VERSION, constants.RECCONET_DENIED, len(uid), uid)  # resp code 1606

    # ===========================
    # File recieved correctly with CRC process : client's request 828, server's response: 1603-approved/1607-error
    # ===========================
    def handle_encrypted_file(self, uid: bytes, version: int, payload: bytes) -> bytes:
        """
        Handles file decryption that the client provided, updates the files database and saves
        the file decrypted file in the backup's server path.
        When the decryption process ends, CRC is calculated and sent to the client along with file's name, size,
        and owner's UUID
        """
        try:
            name = self.remove_pipe_padding(payload, constants.NAME_INDEX, constants.CONTENT_INDEX)  # raises
            decrypted_file = self.crypto_handler.decrypt_file(uid, payload)
            self.save_file(uid, name, decrypted_file)
            pay = self.build_decrypted_file_payload(uid, name, payload)
            response = self.init_response(constants.VERSION, constants.VALID_FILE_CRC, len(pay), pay)

        except Exception as e:
            print(f'Server error: During decryption process {e} ')
            return self.error_response
        return response

    # used by handle_encrypted_file
    def build_decrypted_file_payload(self, uid: bytes, filename: str, payload: bytes) -> bytes:
        """Packs response's 1603 payload """
        content_size = payload[:constants.UINT32_T]
        username = self.database.get_data('clients', uid, constants.USER_NAME_FIELD)
        crc = readfile(self.database.backup_path /username[:-1]/filename)
        print('Server: CRC was calculated successfully\nServer: Sending CRC for client\'s approval')
        return b''.join([uid, content_size, filename.encode(), struct.pack(f'<I', crc)])

    def save_file(self, uid: bytes, filename: str, decrypted_file) -> None:
        """Saves a file to the server's backup path"""
        try:
            username = self.database.get_data('clients', uid, constants.USER_NAME_FIELD)
            path = self.database.backup_path / username[:-1]
            path.mkdir(parents=True, exist_ok=True)
            path /= filename
            with open(path, 'wb') as file:
                file.write(decrypted_file)
            self.database.add_new_file_db(uid, filename, 0)
            print('Server: Decrypted file was backed up successfully')
        except Exception as e:
            Exceptions.save_file_exceptions(e, filename)

    # ===========================
    #  CRC is verified or CRC is wrong 3 times : client's request 900/902, server's response: 1604-approved/1607-error
    # ===========================
    def valid_or_abort(self, uid, code, payload):
        """
           Handles validation or abortion message based on the CRC validation status.
           This method processes the given payload (a filename)
           - If the `code` is `VALID_CRC`, the file is marked as approved and updated in the database.
           - If the `code` is `EXIT_CRC`, the file could not be validated after multiple attempts, so it is removed.
            Prints and returns a response based on the given code.
           """
        try:
            unpadded_filename = self.remove_pipe_padding(payload)
            if code == constants.VALID_CRC:
                self.database.update_entry(
                    constants.FILES_TABLE,
                    uid,
                    constants.VERIFIED_FIELD,
                    constants.TRUE,
                    True,
                    unpadded_filename
                )
                print('Server: CRC validated! File approved!\n############################\n')
            elif code == constants.EXIT_CRC:
                print('Server: Could not verify CRC for 3 times.')
                self.delete_from_backup(uid, unpadded_filename)
                self.database.delete_unverified(uid, unpadded_filename)
            return self.init_response(constants.VERSION, constants.FILE_APPROVAL, len(uid), uid)
        except Exception as e:
            print(f'Server error: While ending client interaction with code {code} - {e}')
            return self.error_response

    def delete_from_backup(self, uid, filename):
        try:
            username = self.database.get_data(constants.CLIENTS_TABLE,uid,constants.USER_NAME_FIELD)
            path = self.database.backup_path/username[:-1]/filename
            os.remove(path)
            print('Server: File deleted successfully\n############################\n')
        except Exception as e:
            print(e)
            return self.error_response
    # ===========================
    # CRC is not valid recalculate CRC : client's request 901, server's response: 1603-approved/1607-error
    # ===========================
    def resend_crc(self, uid: bytes, version: int, payload: bytes):
        """
        Handles client's request to resend a CRC validation request.
        This function is called after receiving the client's request (901) and awaits further 828 requests (3 at most).
        Returns the appropriate server response based on that request.
        """
        print('Server: CRC is not matching, receiving file again for revalidation')
        try:
            response = self.handle_request()
            return response
        except Exception as e:
            print(f'Server Error: while sending re-validating crc {e}')
            return self.error_response  # code = 1607

    # =========================== Utils Functions ===========================

    def remove_pipe_padding(self, payload: bytes, start: int = 0, end: int = constants.FILE_NAME_SIZE) -> str:
        """
        Handles padding removal of filenames that recieved from the client.
        Padding is being applied for making all filenames in the maximum size for easier parsing and handling
        """
        try:
            name = payload[start:end].decode('utf-8')
            return name.replace('|', '')  # removes padding made by the client
        except Exception as e:
            Exceptions.remove_pipe_padding_exceptions(e)

    def create_operations_map(self) -> dict:
        """ Creates a mapping between request codes and their corresponding handler functions
            Returns a dict where the keys are the op-codes and the values are the corresponding handler functions
        """
        functions_map = {
            constants.REGISTER: self.register_new_client,
            constants.S_PUBLIC_KEY: self.handle_public_key,
            constants.SEND_FILE: self.handle_encrypted_file,
            constants.RECONNECT: self.handle_sign_in_reqeust,
            constants.N_VALID_CRC: self.resend_crc,
            constants.EXIT_CRC: self.valid_or_abort,
            constants.VALID_CRC: self.valid_or_abort
        }
        return functions_map

    def req_select(self, header, payload: bytes):
        """
        Handles requests selection by selecting response with the corresponding request code with the response dict.
        returns an error in case that version is not right or an invalid op-code recieved by the client, otherwise
        returns a response according to the recieved request and protocol structure
        """
        uid, version, code, size = header
        if version is not constants.VERSION:
            print("Server error: Invalid server version cannot proceed")
            return self.error_response
        arg = code if code in {constants.EXIT_CRC, constants.VALID_CRC} else version
        func = self.response_map.get(code)
        response = func(uid, arg, payload)
        if not func:
            print("Server error: Invalid server code cannot proceed")
            return self.error_response
        return response
