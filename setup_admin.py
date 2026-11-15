import os

from dotenv import load_dotenv

from werkzeug.security import (
    generate_password_hash
)

from database import (
    get_connection,
    initialize_database
)

from crypto_utils import (
    generate_rsa_key_pair,
    serialize_public_key,
    serialize_private_key,
    encrypt_private_key
)


# =========================================================
# LOAD ENVIRONMENT VARIABLES
# =========================================================

load_dotenv()


# =========================================================
# INITIAL ADMIN CONFIGURATION
#
# IMPORTANT:
# Keep these values in .env locally and in your deployment
# environment variables in production.
#
# Do NOT put real passwords directly in this Python file.
# =========================================================

ORGANIZATION_NAME = os.getenv(
    "ORGANIZATION_NAME"
)

ADMIN_USERNAME = os.getenv(
    "ADMIN_USERNAME"
)

ADMIN_EMAIL = os.getenv(
    "ADMIN_EMAIL"
)

ADMIN_PASSWORD = os.getenv(
    "ADMIN_PASSWORD"
)


# =========================================================
# VALIDATE CONFIGURATION
# =========================================================

def validate_admin_configuration():

    missing_variables = []

    if not ORGANIZATION_NAME:
        missing_variables.append(
            "ORGANIZATION_NAME"
        )

    if not ADMIN_USERNAME:
        missing_variables.append(
            "ADMIN_USERNAME"
        )

    if not ADMIN_EMAIL:
        missing_variables.append(
            "ADMIN_EMAIL"
        )

    if not ADMIN_PASSWORD:
        missing_variables.append(
            "ADMIN_PASSWORD"
        )

    if missing_variables:

        print()

        print(
            "ERROR: Missing environment variables:"
        )

        for variable in missing_variables:

            print(
                f"- {variable}"
            )

        print()

        print(
            "Please configure these values in your .env "
            "file or deployment environment."
        )

        return False

    return True


# =========================================================
# CREATE INITIAL ORGANIZATION AND ADMIN
# =========================================================

def create_initial_admin():

    # -----------------------------------------------------
    # CHECK ENVIRONMENT VARIABLES FIRST
    # -----------------------------------------------------

    if not validate_admin_configuration():

        return

    # -----------------------------------------------------
    # MAKE SURE DATABASE AND TABLES EXIST
    # -----------------------------------------------------

    initialize_database()

    connection = get_connection()

    try:

        # -------------------------------------------------
        # CREATE OR FIND THE ORGANIZATION
        # -------------------------------------------------

        organization = connection.execute(
            """
            SELECT id
            FROM organizations
            WHERE name = ?
            """,
            (ORGANIZATION_NAME,)
        ).fetchone()

        if organization:

            organization_id = organization["id"]

            print(
                "Organization already exists."
            )

        else:

            cursor = connection.execute(
                """
                INSERT INTO organizations (name)
                VALUES (?)
                """,
                (ORGANIZATION_NAME,)
            )

            organization_id = cursor.lastrowid

            print(
                "Organization created successfully."
            )

        # -------------------------------------------------
        # CHECK WHETHER ADMIN ALREADY EXISTS
        # -------------------------------------------------

        existing_admin = connection.execute(
            """
            SELECT id
            FROM users
            WHERE username = ?
            OR email = ?
            """,
            (
                ADMIN_USERNAME,
                ADMIN_EMAIL
            )
        ).fetchone()

        if existing_admin:

            connection.commit()

            print()

            print(
                "An account with this username or email "
                "already exists."
            )

            print(
                "No new admin account was created."
            )

            return

        # -------------------------------------------------
        # GENERATE RSA KEY PAIR
        # -------------------------------------------------

        private_key, public_key = (
            generate_rsa_key_pair()
        )

        # -------------------------------------------------
        # SERIALIZE PUBLIC KEY
        # -------------------------------------------------

        public_key_pem = (
            serialize_public_key(
                public_key
            )
        )

        # -------------------------------------------------
        # SERIALIZE AND ENCRYPT PRIVATE KEY
        # -------------------------------------------------

        private_key_pem = (
            serialize_private_key(
                private_key
            )
        )

        encrypted_private_key = (
            encrypt_private_key(
                private_key_pem,
                ADMIN_PASSWORD
            )
        )

        # -------------------------------------------------
        # HASH ADMIN PASSWORD
        # -------------------------------------------------

        password_hash = (
            generate_password_hash(
                ADMIN_PASSWORD
            )
        )

        # -------------------------------------------------
        # CREATE ADMIN ACCOUNT
        # -------------------------------------------------

        connection.execute(
            """
            INSERT INTO users (
                username,
                email,
                password_hash,
                account_type,
                role,
                organization_id,
                public_key,
                encrypted_private_key
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                ADMIN_USERNAME,
                ADMIN_EMAIL,
                password_hash,
                "organization",
                "admin",
                organization_id,
                public_key_pem,
                encrypted_private_key
            )
        )

        connection.commit()

        # -------------------------------------------------
        # SUCCESS MESSAGE
        # -------------------------------------------------

        print()

        print(
            "========================================"
        )

        print(
            "ADMIN ACCOUNT CREATED SUCCESSFULLY!"
        )

        print(
            "========================================"
        )

        print(
            f"Organization: {ORGANIZATION_NAME}"
        )

        print(
            f"Admin Username: {ADMIN_USERNAME}"
        )

        print(
            f"Admin Email: {ADMIN_EMAIL}"
        )

        print()

        print(
            "Database setup completed successfully."
        )

        print(
            "You can now start SecureShare."
        )

        print(
            "========================================"
        )

    except Exception as error:

        connection.rollback()

        print()

        print(
            "ERROR WHILE CREATING ADMIN:"
        )

        print(error)

    finally:

        connection.close()


# =========================================================
# RUN ADMIN SETUP
# =========================================================

if __name__ == "__main__":

    create_initial_admin()