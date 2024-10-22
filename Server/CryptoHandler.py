""" CryptoHandler class handles all cryptographic operations and processes that needed for the server's and
    client's communication.
    This class uses pycryptodome external library
"""
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
import constants
import DefensiveDB
import Exceptions


class CryptoHandler:

    """This class handles cryptographic operations for the serve"""
    def __init__(self, database: DefensiveDB):
        self.database = database

    def generate_aes_key(self, uid: bytes) -> bytes:
        """
        Handles aes key generation: Retrieves the user's public RSA key,Generates AES key to be sent to the client,
        Stores the AES key in the database for a given user,
        Encrypts the AES key using the user's public RSA key and returns it.
        """
        try:
            rsa_key = self.recover_public_key(uid)
            aes_key = get_random_bytes(constants.AES_KEY_SIZE)
            self.database.update_entry(constants.CLIENTS_TABLE, uid, constants.AES_KEY_FIELD, aes_key)
            cipher_key = PKCS1_OAEP.new(rsa_key)
            encrypted_aes_key = cipher_key.encrypt(aes_key)
            return encrypted_aes_key
        except Exception as e:
            raise e

    def recover_public_key(self, uid: bytes) -> RSA.RsaKey:  # raises
        """
          Retrieves and validates the public RSA key: Retrieves the binary public key from the database,
          checks if the key is not a placeholder and returns the RSA key
          """
        binary_public_key = self.database.get_data(constants.CLIENTS_TABLE, uid, constants.PUBLIC_KEY_FIELD)
        if b'public_key' == binary_public_key:
            raise Exceptions.InvalidPublicKeyException('Client did not send RSA public key, cannot proceed with the encryption process')
        rsa_key = RSA.importKey(binary_public_key)
        Exceptions.recover_public_key_exceptions(rsa_key)
        return rsa_key

    def decrypt_file(self, uid: bytes, payload: bytes) -> bytes:  # raises exception
        """
        Handles file decryption: retrieves the AES key of the user from the database, decrypts (AES-CBC) the payload
        and returns the decrypted file's data
        """
        try:
            restored_aes_key = self.database.get_data(constants.CLIENTS_TABLE, uid, constants.AES_KEY_FIELD)
            cipher = AES.new(bytes(restored_aes_key), AES.MODE_CBC, constants.IV)
            decrypted_file = unpad(cipher.decrypt(payload[constants.CONTENT_INDEX:]), AES.block_size)
            print('Server: File was decrypted successfully')
            return decrypted_file
        except Exception as e:
            raise Exceptions.DecryptionError(str(e))
