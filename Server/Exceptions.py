"""
    This module complies errors and exceptions which may raise or happen
    during the classes/modules operations for a cleaner and more detailed error handling
    Each function in the code handles specific types of exceptions that may
    occur in different stages of the server operation.
    InvalidPublicKeyException - for key handling functions
    DecryptionError - for any decryption related exception
    SaveFileException -  for any exceptions during saving the file the backup path
    ParsingDataException - for data parsing errors
    DefensiveDbException - for any database related exceptions
"""
import struct
import constants
import sqlite3

error_response = struct.pack(f'< BHI', constants.VERSION, constants.GENERAL_ERROR, 0) + b''


class InvalidPublicKeyException(Exception):
    pass


class DecryptionError(Exception):
    pass


class SaveFileException(Exception):
    pass


class ParsingDataException(Exception):
    pass


class DefensiveDbException(Exception):
    pass


def register_new_client_exceptions(err: Exception) -> bytes:
    """Exceptions and errors handling for register_new_client function in requestHandler class """
    if isinstance(err, UnicodeDecodeError):
        print('Server Error: During new client registration User name must be in ascii chars')
    elif isinstance(err, struct.error):
        print(f"Server Error: During new client registration Struct packing error {err}")
    else:
        print(f'Server Error: During new client registration {err}')
    return error_response


def validate_public_key_payload(payload) -> None:
    """ checks if the payload structure for request 826 (response 1602 is valid) - it must be greater than 160"""
    err = (
        InvalidPublicKeyException('Public key is too short') if len(payload) < constants.PUBLIC_KEY else
        InvalidPublicKeyException(f'Server Error: User name must contain at least one character') if len(
            payload) == constants.PUBLIC_KEY else
        None
    )
    if err:
        raise err


def recover_public_key_exceptions(rsa_key) -> None:
    """ checks if the public key was recovered successfully, or it's a private key"""
    err = (
        InvalidPublicKeyException('Could not recover RSA key') if rsa_key is None else
        InvalidPublicKeyException('Client sent RSA key with private component') if rsa_key.has_private() else
        None
    )
    if err:
        raise err


def remove_pipe_padding_exceptions(err: Exception) -> None:
    """Checks for invalid filenames or invalid payload during decryption process """
    if isinstance(err, UnicodeDecodeError):
        raise ParsingDataException('Could not decode file\'s name - must be ASCII')
    elif isinstance(err, IndexError):
        raise ParsingDataException('Did not receive encrypted file\'s name payload is too short')


def save_file_exceptions(e: Exception, name) -> None:
    err = (
        SaveFileException(f"Could not save Encrypted file: {name}") if isinstance(e, OSError) else
        SaveFileException(str(e))
    )
    raise err


def encryption_exceptions(e: Exception) -> bytes:
    print(f'Server error: During decryption process {e} ')
    return error_response  # code = 1607


def db_error_handler(e, table_name=''):
    if isinstance(e, sqlite3.IntegrityError):
        raise DefensiveDbException(f'in db {table_name} data inserted may violate constraints {e}')
    if isinstance(e, sqlite3.ProgrammingError):
        raise DefensiveDbException(f'invalid SQL operation {e}')
    if isinstance(e, sqlite3.OperationalError):
        raise DefensiveDbException(f'failed to create database {e}')
    if isinstance(e, Exception):
        raise DefensiveDbException(f'SQLite DB related error occurred {e}')