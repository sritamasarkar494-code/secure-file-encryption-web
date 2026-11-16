import sqlite3
import os


DATABASE = "instance/secure_files.db"


# =========================================================
# DATABASE CONNECTION
# =========================================================

def get_connection():

    os.makedirs("instance", exist_ok=True)

    connection = sqlite3.connect(DATABASE)

    connection.row_factory = sqlite3.Row

    connection.execute("PRAGMA foreign_keys = ON")

    return connection


# =========================================================
# DATABASE MIGRATION HELPERS
# =========================================================

def column_exists(connection, table_name, column_name):

    columns = connection.execute(
        f"PRAGMA table_info({table_name})"
    ).fetchall()

    return any(
        column["name"] == column_name
        for column in columns
    )


def add_column_if_missing(
    connection,
    table_name,
    column_name,
    column_definition
):

    if not column_exists(
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
# INITIALIZE DATABASE
# =========================================================

def initialize_database():

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
    #
    # An organization employee can use BOTH:
    #
    # - Organization Workspace
    # - Personal Workspace
    #
    # account_type describes how the account was created.
    # It does not restrict personal workspace access.
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
    #
    # Used by organization administrators to invite
    # employees to join their organization.
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
    # PERSONAL / EXTERNAL INVITATIONS
    #
    # Used when someone wants to share a PERSONAL file
    # with a recipient who does not yet have an account.
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
    #
    # workspace_type:
    #
    # organization -> company file
    # personal     -> user's private file
    #
    # IMPORTANT:
    # Personal files always have organization_id = NULL.
    # Therefore organization administrators cannot access
    # or view personal files through organization queries.
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

    # Add workspace_type for older databases
    add_column_if_missing(
        connection,
        "files",
        "workspace_type",
        "TEXT NOT NULL DEFAULT 'personal'"
    )

    # =====================================================
    # FILE ACCESS
    #
    # Stores the encrypted AES key separately for every
    # user who has access to a file.
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
    #
    # This table supports the following flow:
    #
    # 1. User uploads a personal file.
    # 2. Recipient does not have an account.
    # 3. File is encrypted and stored immediately.
    # 4. Recipient receives an invitation.
    # 5. This table remembers which file was intended for
    #    which email address.
    # 6. When the invited person registers with that email,
    #    access to the file is automatically created.
    #
    # The encrypted AES key is stored here because the
    # recipient does not yet have a public key at upload
    # time. After registration, their new public key can
    # be used to encrypt the AES key and create a record
    # in file_access.
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
    #
    # Organization actions:
    # organization_id = organization ID
    #
    # Personal actions:
    # organization_id = NULL
    #
    # Therefore organization administrators only see
    # organization-related activity.
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
    #
    # Existing files with an organization ID are treated
    # as organization files.
    #
    # Existing files without an organization ID are treated
    # as personal files.
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