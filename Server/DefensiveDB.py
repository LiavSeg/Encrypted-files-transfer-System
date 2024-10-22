"""
    DefensiveDB class provides a thread-safe interface to interact with the defensive.db SQLite database.
    This class manages clients and files data on a multithreaded server.
"""
import sqlite3
from pathlib import Path
import constants
import datetime
import threading
from Exceptions import db_error_handler
from constants import DB_NAME


class DefensiveDB:
    def __init__(self):
        """
            DefensiveDB class constructor
            Initializes a backup path for the files and a locking mechanism for thread safety
        """
        self.create_db()
        self.backup_path = Path.home() / constants.BACKUP_PATH_NAME
        self.lock = threading.Lock()

    def create_db(self):
        """
            This function creates a new SQLite database named defensive.db [if it doesn't exist]
            The database contains two table - clients, files
            clients table contains: UUID field[primary key], Username string, public RSA key, last seen and AES key
            files table contains: UUID - primary key,file name, file path and verified (CRC)
        """
        try:
            connect_db = sqlite3.connect("defensive.db")
            cursor = connect_db.cursor()
            build_files_db_cmd = """CREATE TABLE IF NOT EXISTS files(
                uuid BLOB PRIMARY KEY,
                file_name TEXT,
                path_name TEXT,
                verified INTEGER
            );
            """
            build_client_db_cmd = """CREATE TABLE IF NOT EXISTS clients(
                uuid BLOB PRIMARY KEY,
                user_name TEXT,
                public_key BLOB,
                last_seen TEXT,
                 aes_key BLOB
            );
            """
            cursor.execute(build_files_db_cmd)   # creating files table for the db if not exists
            cursor.execute(build_client_db_cmd)  # creating clients table for the db if not exists
            connect_db.commit()
            connect_db.close()
        except Exception as e:
            db_error_handler(e)

    def thread_connect(self):
        """ returns a safe thread connection to the database"""
        try:
            return sqlite3.connect(DB_NAME, check_same_thread=False)
        except Exception as e:
            db_error_handler(e)

    def run_thread_query(self, query, params=(), fetch=False):
        """ This function wraps any database usage with the locking mechanism
            to enable reliable and safe multithreaded usage while using the 'critical section' of the server i.e. the db
            If the fetch flag is on (true) a data will be returned to the calling function, Otherwise no data is returned
        """
        with self.lock:
            connect = self.thread_connect()
            cursor = connect.cursor()
            cursor.execute(query, params)
            result = cursor.fetchone() if fetch else cursor.rowcount
            connect.commit()
            connect.close()
            return result

    def update_entry(self, table_name: str, uid: bytes, field_name: str, field_data, file=False, filename=''):
        """ Updates a table field for a given user (uuid) and a given table (files or clients) """
        try:
            update_query = f"UPDATE {table_name} SET {field_name} = ? WHERE uuid = ?;"
            if file and filename:
                update_query = f"UPDATE {table_name} SET {field_name} = ? WHERE uuid = ? AND file_name = ?;"
                self.run_thread_query(update_query, (field_data, uid, filename), False)
            else:
                self.run_thread_query(update_query, (field_data, uid), False)
            if table_name == constants.CLIENTS_TABLE:
                last_seen_query = f"UPDATE {constants.CLIENTS_TABLE} SET {constants.LAST_SEEN_FIELD} = ? WHERE uuid = ?;"
                self.run_thread_query(last_seen_query, (self.get_current_timedate(),uid), False)
        except Exception as e:
            db_error_handler(e, table_name)

    def get_data(self, table_name, uid, field_name):
        """"Gets data (field_name)  from a specific table(table_name) of a specific user(uid)  """
        try:
            select_query = f"SELECT {field_name} FROM {table_name} WHERE uuid = ?;"
            data = self.run_thread_query(select_query, (uid,), True)
            if not data:
                raise ValueError(f'Could not locate {field_name} from {table_name} - can\'t proceed')
            return data[0]
        except Exception as e:
            db_error_handler(e, table_name)

    def add_new_file_db(self, uid: bytes, file_name: str, verified: int):
        """Adds a new file to the database for a specific user"""
        try:
            insert_query = 'INSERT OR IGNORE INTO files(uuid, file_name, path_name, verified) VALUES (?, ?, ?, ?);'
            username = self.get_data(constants.CLIENTS_TABLE, uid, constants.USER_NAME_FIELD)
            path = str(self.backup_path/username[:-1])
            self.run_thread_query(insert_query, (uid, file_name, path, verified))
        except Exception as e:
            db_error_handler(e, 'files')

    def find_username(self, username):
        """
            This function finds if a given username is in the database
            If the user is in the database, it will return a list with uuid and REGISTRATION_FAIL code error
            If the user does not exist, it will return a list with empty binary string and INIT_REGISTRATION_SUCC
        """
        search = 'SELECT uuid FROM clients WHERE user_name = ?'
        exists = self.run_thread_query(search, (username,), True)
        if exists is None:
            return [b'', constants.INIT_REGISTRATION_SUCC]
        return [exists[0], constants.REGISTRATION_FAIL]

    def add_new_client_db(self, uid: bytes, _name: str):
        try:
            insert_query = 'INSERT INTO clients (uuid, user_name, public_key, last_seen, aes_key) VALUES (?, ?, ?, ?, ?);'
            self.run_thread_query(insert_query, (uid, _name, b'public_key', self.get_current_timedate(), b'aes_key'))
        except Exception as e:
            db_error_handler(e, 'clients')

    def get_current_timedate(self):
        """return the current time and date"""
        last_seen = datetime.datetime.now()
        return last_seen.strftime("%d-%m-%Y %H:%M:%S")

    def delete_unverified(self, uid, filename):
        """Deletes a file that its CRC could not be verified for three times"""
        try:
            delete_query = 'DELETE FROM files WHERE verified = 0 AND uuid = ? AND file_name = ?'
            deleted = self.run_thread_query(delete_query, (uid, filename))
            if deleted > 0:
                print(f'Server: Successfully deleted corrupted file: {filename}')
        except Exception as e:
            db_error_handler(e)
