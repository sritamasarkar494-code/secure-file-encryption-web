import os
import sqlite3
from dotenv import load_dotenv


# =========================================================
# LOAD ENVIRONMENT VARIABLES
# =========================================================

load_dotenv()


# =========================================================
# DATABASE CONFIGURATION
#
# Local development:
# DATABASE_TYPE=sqlite
#
# MySQL testing / deployment:
# DATABASE_TYPE=mysql
# =========================================================

DATABASE_TYPE = os.getenv(
    "DATABASE_TYPE",
    "sqlite"
).lower()

SQLITE_DATABASE = os.getenv(
    "SQLITE_DATABASE",
    "instance/secure_files.db"
)


# =========================================================
# MYSQL IMPORT
#
# mysql-connector-python is only required when you use
# DATABASE_TYPE=mysql.
# =========================================================

try:

    import mysql.connector
    MYSQL_AVAILABLE = True

except ImportError:

    MYSQL_AVAILABLE = True


# =========================================================
# MYSQL ROW
#
# Allows MySQL rows to behave similarly to sqlite3.Row.
# =========================================================

class MySQLRow(dict):

    def __getitem__(self, key):

        return super().__getitem__(key)


# =========================================================
# MYSQL CURSOR WRAPPER
#
# Gives MySQL cursor behaviour similar to SQLite.
# =========================================================

class MySQLCursorWrapper:

    def __init__(self, cursor):

        self.cursor = cursor

    @property
    def lastrowid(self):

        return self.cursor.lastrowid

    def fetchone(self):

        row = self.cursor.fetchone()

        if row is None:

            return None

        return MySQLRow(row)

    def fetchall(self):

        rows = self.cursor.fetchall()

        return [
            MySQLRow(row)
            for row in rows
        ]


# =========================================================
# MYSQL CONNECTION WRAPPER
#
# Your app.py can continue using:
#
# connection.execute(
#     "SELECT ... WHERE id = ?",
#     (value,)
# )
#
# This wrapper converts SQLite-style syntax to MySQL.
# =========================================================

class MySQLConnectionWrapper:

    def __init__(self, connection):

        self.connection = connection

    def _convert_query(self, query):

        # -------------------------------------------------
        # Convert SQLite INSERT OR IGNORE to MySQL syntax.
        # -------------------------------------------------

        query = query.replace(
            "INSERT OR IGNORE",
            "INSERT IGNORE"
        )

        # -------------------------------------------------
        # Convert SQLite placeholders:
        #
        # SQLite: ?
        # MySQL:  %s
        # -------------------------------------------------

        query = query.replace(
            "?",
            "%s"
        )

        return query

    def execute(
        self,
        query,
        parameters=None
    ):

        converted_query = (
            self._convert_query(query)
        )

        cursor = self.connection.cursor(
            dictionary=True
        )

        if parameters is None:

            cursor.execute(
                converted_query
            )

        else:

            cursor.execute(
                converted_query,
                parameters
            )

        return MySQLCursorWrapper(cursor)

    def cursor(self):

        return self.connection.cursor(
            dictionary=True
        )

    def commit(self):

        self.connection.commit()

    def rollback(self):

        self.connection.rollback()

    def close(self):

        self.connection.close()


# =========================================================
# DATABASE CONNECTION
# =========================================================

def get_connection():

    # =====================================================
    # SQLITE MODE
    # =====================================================

    if DATABASE_TYPE == "sqlite":

        database_directory = os.path.dirname(
            SQLITE_DATABASE
        )

        if database_directory:

            os.makedirs(
                database_directory,
                exist_ok=True
            )

        connection = sqlite3.connect(
            SQLITE_DATABASE
        )

        connection.row_factory = sqlite3.Row

        connection.execute(
            "PRAGMA foreign_keys = ON"
        )

        return connection

    # =====================================================
    # MYSQL MODE
    # =====================================================

    if DATABASE_TYPE == "mysql":

        try:

            import mysql.connector

        except ImportError:

            raise ImportError(
                "MySQL support requires "
                "mysql-connector-python. "
                "Install it using: "
                "pip install mysql-connector-python"
            )

        connection = mysql.connector.connect(

            host=os.getenv(
                "MYSQL_HOST",
                "localhost"
            ),

            port=int(
                os.getenv(
                    "MYSQL_PORT",
                    "3306"
                )
            ),

            user=os.getenv(
                "MYSQL_USER"
            ),

            password=os.getenv(
                "MYSQL_PASSWORD"
            ),

            database=os.getenv(
                "MYSQL_DATABASE"
            ),

            autocommit=False
        )

        return MySQLConnectionWrapper(
            connection
        )

    # =====================================================
    # INVALID DATABASE TYPE
    # =====================================================

    raise ValueError(
        "Invalid DATABASE_TYPE. "
        "Use either 'sqlite' or 'mysql'."
    )


# =========================================================
# SQLITE DATABASE MIGRATION HELPERS
#
# These are used only for your existing SQLite database.
# =========================================================

def sqlite_column_exists(
    connection,
    table_name,
    column_name
):

    columns = connection.execute(
        f"PRAGMA table_info({table_name})"
    ).fetchall()

    return any(
        column["name"] == column_name
        for column in columns
    )


def sqlite_add_column_if_missing(
    connection,
    table_name,
    column_name,
    column_definition
):

    if not sqlite_column_exists(
        connection,
        table_name,
        column_name
    ):

        connection.execute(
            f"""
            ALTER TABLE {table_name}
            ADD COLUMN {column_name}
            {column_definition}
            """
        )


# =========================================================
# MYSQL DATABASE INITIALIZATION
# =========================================================

def initialize_mysql_database():

    connection = get_connection()

    try:

        # =================================================
        # ORGANIZATIONS
        # =================================================

        connection.execute("""
            CREATE TABLE IF NOT EXISTS organizations (

                id INT AUTO_INCREMENT PRIMARY KEY,

                name VARCHAR(255)
                UNIQUE NOT NULL,

                created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # =================================================
        # USERS
        # =================================================

        connection.execute("""
            CREATE TABLE IF NOT EXISTS users (

                id INT AUTO_INCREMENT PRIMARY KEY,

                username VARCHAR(255)
                UNIQUE NOT NULL,

                email VARCHAR(255)
                UNIQUE NOT NULL,

                password_hash TEXT NOT NULL,

                account_type VARCHAR(50)
                NOT NULL,

                role VARCHAR(50)
                NOT NULL,

                organization_id INT NULL,

                public_key LONGBLOB NOT NULL,

                encrypted_private_key LONGBLOB
                NOT NULL,

                failed_login_attempts INT
                NOT NULL DEFAULT 0,

                locked_until VARCHAR(50)
                NULL,

                created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (organization_id)
                REFERENCES organizations(id)
                ON DELETE SET NULL
            )
        """)

        # =================================================
        # ORGANIZATION INVITATIONS
        # =================================================

        connection.execute("""
            CREATE TABLE IF NOT EXISTS invitations (

                id INT AUTO_INCREMENT PRIMARY KEY,

                organization_id INT NOT NULL,

                email VARCHAR(255)
                NOT NULL,

                token VARCHAR(255)
                UNIQUE NOT NULL,

                invited_by INT NOT NULL,

                expires_at VARCHAR(50)
                NOT NULL,

                used_at VARCHAR(50)
                NULL,

                created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (organization_id)
                REFERENCES organizations(id),

                FOREIGN KEY (invited_by)
                REFERENCES users(id)
            )
        """)

        # =================================================
        # EXTERNAL INVITATIONS
        # =================================================

        connection.execute("""
            CREATE TABLE IF NOT EXISTS
            external_invitations (

                id INT AUTO_INCREMENT PRIMARY KEY,

                email VARCHAR(255)
                NOT NULL,

                token VARCHAR(255)
                UNIQUE NOT NULL,

                invited_by INT NOT NULL,

                expires_at VARCHAR(50)
                NOT NULL,

                used_at VARCHAR(50)
                NULL,

                created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (invited_by)
                REFERENCES users(id)
            )
        """)

        # =================================================
        # FILES
        # =================================================

        connection.execute("""
            CREATE TABLE IF NOT EXISTS files (

                id INT AUTO_INCREMENT PRIMARY KEY,

                owner_id INT NOT NULL,

                organization_id INT NULL,

                workspace_type VARCHAR(50)
                NOT NULL DEFAULT 'personal',

                original_filename TEXT NOT NULL,

                stored_filename VARCHAR(255)
                NOT NULL,

                expiry_date VARCHAR(50)
                NULL,

                created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (owner_id)
                REFERENCES users(id),

                FOREIGN KEY (organization_id)
                REFERENCES organizations(id)
            )
        """)

        # =================================================
        # FILE ACCESS
        # =================================================

        connection.execute("""
            CREATE TABLE IF NOT EXISTS file_access (

                id INT AUTO_INCREMENT PRIMARY KEY,

                file_id INT NOT NULL,

                user_id INT NOT NULL,

                encrypted_aes_key LONGBLOB
                NOT NULL,

                FOREIGN KEY (file_id)
                REFERENCES files(id)
                ON DELETE CASCADE,

                FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE CASCADE,

                UNIQUE(file_id, user_id)
            )
        """)

        # =================================================
        # PENDING FILE SHARES
        # =================================================

        connection.execute("""
            CREATE TABLE IF NOT EXISTS
            pending_file_shares (

                id INT AUTO_INCREMENT PRIMARY KEY,

                file_id INT NOT NULL,

                recipient_email VARCHAR(255)
                NOT NULL,

                encrypted_aes_key LONGBLOB
                NOT NULL,

                created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (file_id)
                REFERENCES files(id)
                ON DELETE CASCADE,

                UNIQUE(file_id, recipient_email)
            )
        """)

        # =================================================
        # AUDIT LOGS
        # =================================================

        connection.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (

                id INT AUTO_INCREMENT PRIMARY KEY,

                user_id INT NULL,

                organization_id INT NULL,

                action VARCHAR(100)
                NOT NULL,

                details TEXT,

                created_at TIMESTAMP
                DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE SET NULL,

                FOREIGN KEY (organization_id)
                REFERENCES organizations(id)
                ON DELETE SET NULL
            )
        """)

        connection.commit()

    finally:

        connection.close()


# =========================================================
# SQLITE DATABASE INITIALIZATION
#
# This preserves your existing SQLite structure and data.
# =========================================================

def initialize_sqlite_database():

    connection = get_connection()

    cursor = connection.cursor()

    # =====================================================
    # ORGANIZATIONS
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS organizations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            name TEXT UNIQUE NOT NULL,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # =====================================================
    # USERS
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            username TEXT UNIQUE NOT NULL,

            email TEXT UNIQUE NOT NULL,

            password_hash TEXT NOT NULL,

            account_type TEXT NOT NULL,

            role TEXT NOT NULL,

            organization_id INTEGER,

            public_key BLOB NOT NULL,

            encrypted_private_key BLOB NOT NULL,

            failed_login_attempts INTEGER
            NOT NULL DEFAULT 0,

            locked_until TEXT,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (organization_id)
            REFERENCES organizations(id)
        )
    """)

    # =====================================================
    # ORGANIZATION INVITATIONS
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS invitations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            organization_id INTEGER NOT NULL,

            email TEXT NOT NULL,

            token TEXT UNIQUE NOT NULL,

            invited_by INTEGER NOT NULL,

            expires_at TEXT NOT NULL,

            used_at TEXT,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (organization_id)
            REFERENCES organizations(id),

            FOREIGN KEY (invited_by)
            REFERENCES users(id)
        )
    """)

    # =====================================================
    # EXTERNAL INVITATIONS
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS external_invitations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            email TEXT NOT NULL,

            token TEXT UNIQUE NOT NULL,

            invited_by INTEGER NOT NULL,

            expires_at TEXT NOT NULL,

            used_at TEXT,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (invited_by)
            REFERENCES users(id)
        )
    """)

    # =====================================================
    # FILES
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            owner_id INTEGER NOT NULL,

            organization_id INTEGER,

            workspace_type TEXT
            NOT NULL DEFAULT 'personal',

            original_filename TEXT NOT NULL,

            stored_filename TEXT NOT NULL,

            expiry_date TEXT,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (owner_id)
            REFERENCES users(id),

            FOREIGN KEY (organization_id)
            REFERENCES organizations(id)
        )
    """)

    # Preserve compatibility with an older SQLite database.
    sqlite_add_column_if_missing(
        connection,
        "files",
        "workspace_type",
        "TEXT NOT NULL DEFAULT 'personal'"
    )

    # =====================================================
    # FILE ACCESS
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS file_access (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            file_id INTEGER NOT NULL,

            user_id INTEGER NOT NULL,

            encrypted_aes_key BLOB NOT NULL,

            FOREIGN KEY (file_id)
            REFERENCES files(id),

            FOREIGN KEY (user_id)
            REFERENCES users(id),

            UNIQUE(file_id, user_id)
        )
    """)

    # =====================================================
    # PENDING FILE SHARES
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS pending_file_shares (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            file_id INTEGER NOT NULL,

            recipient_email TEXT NOT NULL,

            encrypted_aes_key BLOB NOT NULL,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (file_id)
            REFERENCES files(id),

            UNIQUE(file_id, recipient_email)
        )
    """)

    # =====================================================
    # AUDIT LOGS
    # =====================================================

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER,

            organization_id INTEGER,

            action TEXT NOT NULL,

            details TEXT,

            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

            FOREIGN KEY (user_id)
            REFERENCES users(id),

            FOREIGN KEY (organization_id)
            REFERENCES organizations(id)
        )
    """)

    # =====================================================
    # UPDATE OLD FILE RECORDS
    # =====================================================

    connection.execute("""
        UPDATE files
        SET workspace_type = 'organization'
        WHERE organization_id IS NOT NULL
        AND (
            workspace_type IS NULL
            OR workspace_type = 'personal'
        )
    """)

    connection.execute("""
        UPDATE files
        SET workspace_type = 'personal'
        WHERE organization_id IS NULL
        AND workspace_type IS NULL
    """)

    connection.commit()

    connection.close()


# =========================================================
# MAIN DATABASE INITIALIZATION
# =========================================================

def initialize_database():

    if DATABASE_TYPE == "sqlite":

        print(
            "Database mode: SQLite"
        )

        initialize_sqlite_database()

        return

    if DATABASE_TYPE == "mysql":

        print(
            "Database mode: MySQL"
        )

        initialize_mysql_database()

        return

    raise ValueError(
        "Invalid DATABASE_TYPE. "
        "Use 'sqlite' or 'mysql'."
    )