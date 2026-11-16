
from werkzeug.security import generate_password_hash

from database import get_connection, initialize_database

from crypto_utils import (
    generate_rsa_key_pair,
    serialize_public_key,
    serialize_private_key,
    encrypt_private_key
)
import os
from dotenv import load_dotenv
load_dotenv()

# =========================================================
# INITIAL ADMIN CONFIGURATION
# =========================================================

ORGANIZATION_NAME = os.getenv("ORGANIZATION_NAME")

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME")

# Use the same Gmail address that you configured
# as MAIL_USERNAME and MAIL_DEFAULT_SENDER.
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")

# IMPORTANT:
# Put your SecureShare login password here.
#
# This is NOT your Gmail password.
# It can be a completely different password.
ADMIN_PASSWORD = os.getenv("ADMIN_EMAIL")


# =========================================================
# CREATE INITIAL ORGANIZATION AND ADMIN
# =========================================================

def create_initial_admin():

    # Make sure the database and all tables exist
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

            print()
            print(
                "An account with this username or email "
                "already exists."
            )

            return


        # -------------------------------------------------
        # GENERATE RSA KEY PAIR
        # -------------------------------------------------

        private_key, public_key = (
            generate_rsa_key_pair()
        )


        # -------------------------------------------------
        # SERIALIZE THE PUBLIC KEY
        # -------------------------------------------------

        public_key_pem = (
            serialize_public_key(
                public_key
            )
        )


        # -------------------------------------------------
        # SERIALIZE AND ENCRYPT THE PRIVATE KEY
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
        # HASH THE ADMIN PASSWORD
        # -------------------------------------------------

        password_hash = (
            generate_password_hash(
                ADMIN_PASSWORD
            )
        )


        # -------------------------------------------------
        # CREATE THE ADMIN ACCOUNT
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
            "You can now start SecureShare using:"
        )

        print(
            "python app.py"
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
