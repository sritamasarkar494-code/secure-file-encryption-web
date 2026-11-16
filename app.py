from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    send_file
)

import os
import io
import uuid
import csv
import secrets
import base64
import hashlib
from dotenv import load_dotenv
from datetime import datetime, timedelta

from flask_mail import Mail, Message

from cryptography.fernet import Fernet

from werkzeug.security import (
    generate_password_hash,
    check_password_hash
)

from werkzeug.middleware.proxy_fix import ProxyFix

from database import (
    get_connection,
    initialize_database
)

from crypto_utils import (
    generate_aes_key,
    encrypt_file_data,
    decrypt_file_data,
    generate_rsa_key_pair,
    serialize_public_key,
    serialize_private_key,
    load_public_key,
    load_private_key,
    encrypt_aes_key_for_recipient,
    decrypt_aes_key_for_recipient,
    encrypt_private_key,
    decrypt_private_key
)


# =========================================================
# APPLICATION CONFIGURATION
# =========================================================

app = Flask(__name__)
load_dotenv()
app.secret_key = os.environ.get(
    "SECRET_KEY",
    "development-only-secret-change-this"
)

app.config["MAX_CONTENT_LENGTH"] = (
    10 * 1024 * 1024
)


# =========================================================
# SERVER-SIDE KEY FOR PENDING FILE SHARES
#
# A recipient who does not yet have an account does not have
# a public key. Therefore, the AES key is temporarily encrypted
# here until the recipient registers.
#
# IMPORTANT:
# In production, SECRET_KEY must be a strong environment
# variable and must not be changed while pending shares exist.
# =========================================================

def get_pending_share_cipher():

    secret = app.secret_key.encode("utf-8")

    key = base64.urlsafe_b64encode(
        hashlib.sha256(secret).digest()
    )

    return Fernet(key)


def protect_pending_aes_key(aes_key):

    cipher = get_pending_share_cipher()

    return cipher.encrypt(aes_key)


def recover_pending_aes_key(encrypted_aes_key):

    cipher = get_pending_share_cipher()

    return cipher.decrypt(encrypted_aes_key)


# =========================================================
# EMAIL CONFIGURATION
# =========================================================

app.config["MAIL_SERVER"] = "smtp.gmail.com"
app.config["MAIL_PORT"] = 587
app.config["MAIL_USE_TLS"] = True
app.config["MAIL_USE_SSL"] = False

app.config["MAIL_USERNAME"] = os.environ.get(
    "MAIL_USERNAME"
)

app.config["MAIL_PASSWORD"] = os.environ.get(
    "MAIL_PASSWORD"
)

app.config["MAIL_DEFAULT_SENDER"] = os.environ.get(
    "MAIL_DEFAULT_SENDER",
    app.config["MAIL_USERNAME"]
)

mail = Mail(app)


app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1,
    x_host=1
)


os.makedirs(
    "encrypted_files",
    exist_ok=True
)

initialize_database()


# =========================================================
# SECURITY HEADERS
# =========================================================

@app.after_request
def add_security_headers(response):

    response.headers[
        "X-Content-Type-Options"
    ] = "nosniff"

    response.headers[
        "X-Frame-Options"
    ] = "DENY"

    response.headers[
        "Referrer-Policy"
    ] = "no-referrer"

    return response


# =========================================================
# HELPER FUNCTIONS
# =========================================================

def current_user_id():

    return session.get("user_id")


def current_organization_id():

    return session.get("organization_id")


def login_required():

    if not current_user_id():

        flash("Please log in first.")

        return False

    return True


def admin_required():

    if session.get("role") != "admin":

        flash(
            "Administrator access is required."
        )

        return False

    return True


def get_current_user():

    if not current_user_id():

        return None

    connection = get_connection()

    user = connection.execute(
        """
        SELECT *
        FROM users
        WHERE id = ?
        """,
        (current_user_id(),)
    ).fetchone()

    connection.close()

    return user


def get_user_by_username(username):

    connection = get_connection()

    user = connection.execute(
        """
        SELECT *
        FROM users
        WHERE username = ?
        """,
        (username,)
    ).fetchone()

    connection.close()

    return user


def create_audit_log(
    user_id,
    action,
    details="",
    organization_id=None
):

    connection = get_connection()

    connection.execute(
        """
        INSERT INTO audit_logs (
            user_id,
            organization_id,
            action,
            details
        )
        VALUES (?, ?, ?, ?)
        """,
        (
            user_id,
            organization_id,
            action,
            details
        )
    )

    connection.commit()

    connection.close()


def clear_expired_lock(user):

    if not user["locked_until"]:

        return False

    locked_until = datetime.fromisoformat(
        user["locked_until"]
    )

    if datetime.now() >= locked_until:

        connection = get_connection()

        connection.execute(
            """
            UPDATE users
            SET
                locked_until = NULL,
                failed_login_attempts = 0
            WHERE id = ?
            """,
            (user["id"],)
        )

        connection.commit()

        connection.close()

        return True

    return False


# =========================================================
# GRANT PENDING FILE ACCESS
#
# Called after an invited external recipient creates an account.
#
# The pending AES key is recovered temporarily and encrypted
# using the new user's public RSA key.
# =========================================================

def grant_pending_file_access(
    connection,
    user_id,
    user_email,
    public_key_pem
):

    pending_shares = connection.execute(
        """
        SELECT
            id,
            file_id,
            encrypted_aes_key
        FROM pending_file_shares
        WHERE recipient_email = ?
        """,
        (user_email.lower(),)
    ).fetchall()

    if not pending_shares:

        return 0

    public_key = load_public_key(
        public_key_pem
    )

    granted_count = 0

    for share in pending_shares:

        try:

            aes_key = recover_pending_aes_key(
                share["encrypted_aes_key"]
            )

            encrypted_aes_key = (
                encrypt_aes_key_for_recipient(
                    aes_key,
                    public_key
                )
            )

            connection.execute(
                """
                INSERT OR IGNORE INTO file_access (
                    file_id,
                    user_id,
                    encrypted_aes_key
                )
                VALUES (?, ?, ?)
                """,
                (
                    share["file_id"],
                    user_id,
                    encrypted_aes_key
                )
            )

            connection.execute(
                """
                DELETE FROM pending_file_shares
                WHERE id = ?
                """,
                (share["id"],)
            )

            granted_count += 1

        except Exception as error:

            print(
                "Pending file access error:",
                error
            )

    return granted_count


# =========================================================
# EMAIL FUNCTIONS
# =========================================================

def send_organization_invitation_email(
    recipient_email,
    organization_name,
    invitation_link
):

    message = Message(
        subject=(
            f"Invitation to join "
            f"{organization_name}"
        ),
        recipients=[recipient_email]
    )

    message.body = f"""
Hello,

You have been invited to join:

{organization_name}

Please use the secure link below to create your
organization account:

{invitation_link}

For security reasons, please do not share this
invitation link.

SecureShare
"""

    mail.send(message)


def send_external_invitation_email(
    recipient_email,
    sender_name,
    invitation_link
):

    message = Message(
        subject="You have been invited to SecureShare",
        recipients=[recipient_email]
    )

    message.body = f"""
Hello,

{sender_name} wants to share a secure file with you
through SecureShare.

You do not currently have an account.

Please use the secure link below to create your
independent account using this email address:

{recipient_email}

{invitation_link}

After creating your account, you will automatically
receive access to the file shared with you.

For security reasons, please register using the same
email address to which this invitation was sent.

SecureShare
"""

    mail.send(message)


# =========================================================
# HOME
# =========================================================

@app.route("/")
def home():

    if current_user_id():

        return redirect(
            url_for("dashboard")
        )

    return render_template(
        "home.html"
    )


# =========================================================
# INDEPENDENT REGISTRATION
# =========================================================

@app.route(
    "/register-independent",
    methods=["GET", "POST"]
)
def register_independent():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        if (
            not username
            or not email
            or not password
        ):

            flash(
                "Please complete all fields."
            )

            return redirect(
                url_for(
                    "register_independent"
                )
            )

        if len(password) < 8:

            flash(
                "Password must be at least 8 characters."
            )

            return redirect(
                url_for(
                    "register_independent"
                )
            )

        connection = get_connection()

        existing = connection.execute(
            """
            SELECT id
            FROM users
            WHERE username = ?
            OR email = ?
            """,
            (username, email)
        ).fetchone()

        if existing:

            connection.close()

            flash(
                "Username or email already exists."
            )

            return redirect(
                url_for(
                    "register_independent"
                )
            )

        private_key, public_key = (
            generate_rsa_key_pair()
        )

        public_key_pem = (
            serialize_public_key(public_key)
        )

        private_key_pem = (
            serialize_private_key(private_key)
        )

        encrypted_private_key = (
            encrypt_private_key(
                private_key_pem,
                password
            )
        )

        password_hash = (
            generate_password_hash(password)
        )

        cursor = connection.execute(
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
                username,
                email,
                password_hash,
                "independent",
                "independent",
                None,
                public_key_pem,
                encrypted_private_key
            )
        )

        user_id = cursor.lastrowid

        connection.commit()
        connection.close()

        create_audit_log(
            user_id,
            "INDEPENDENT_ACCOUNT_CREATED",
            "Independent account created",
            None
        )

        flash(
            "Account created successfully. Please log in."
        )

        return redirect(
            url_for("login")
        )

    return render_template(
        "register_independent.html"
    )


# =========================================================
# JOIN ORGANIZATION
# =========================================================

@app.route(
    "/join/<token>",
    methods=["GET", "POST"]
)
def join_organization(token):

    connection = get_connection()

    invitation = connection.execute(
        """
        SELECT
            invitations.*,
            organizations.name AS organization_name
        FROM invitations

        JOIN organizations
        ON invitations.organization_id =
        organizations.id

        WHERE invitations.token = ?
        """,
        (token,)
    ).fetchone()

    if not invitation:

        connection.close()

        flash("This invitation is invalid.")

        return redirect(
            url_for("home")
        )

    if invitation["used_at"]:

        connection.close()

        flash(
            "This invitation has already been used."
        )

        return redirect(
            url_for("login")
        )

    expires_at = datetime.fromisoformat(
        invitation["expires_at"]
    )

    if datetime.now() > expires_at:

        connection.close()

        flash("This invitation has expired.")

        return redirect(
            url_for("home")
        )

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        if not username or not password:

            connection.close()

            flash(
                "Username and password are required."
            )

            return redirect(
                url_for(
                    "join_organization",
                    token=token
                )
            )

        if len(password) < 8:

            connection.close()

            flash(
                "Password must be at least 8 characters."
            )

            return redirect(
                url_for(
                    "join_organization",
                    token=token
                )
            )

        existing = connection.execute(
            """
            SELECT id
            FROM users
            WHERE username = ?
            OR email = ?
            """,
            (
                username,
                invitation["email"]
            )
        ).fetchone()

        if existing:

            connection.close()

            flash(
                "Username or email already has an account."
            )

            return redirect(
                url_for(
                    "join_organization",
                    token=token
                )
            )

        private_key, public_key = (
            generate_rsa_key_pair()
        )

        public_key_pem = (
            serialize_public_key(public_key)
        )

        private_key_pem = (
            serialize_private_key(private_key)
        )

        encrypted_private_key = (
            encrypt_private_key(
                private_key_pem,
                password
            )
        )

        password_hash = (
            generate_password_hash(password)
        )

        cursor = connection.execute(
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
                username,
                invitation["email"],
                password_hash,
                "organization",
                "employee",
                invitation["organization_id"],
                public_key_pem,
                encrypted_private_key
            )
        )

        user_id = cursor.lastrowid

        connection.execute(
            """
            UPDATE invitations
            SET used_at = ?
            WHERE id = ?
            """,
            (
                datetime.now().isoformat(
                    timespec="seconds"
                ),
                invitation["id"]
            )
        )

        connection.commit()
        connection.close()

        create_audit_log(
            user_id,
            "ORGANIZATION_JOINED",
            (
                f"Joined organization: "
                f"{invitation['organization_name']}"
            ),
            invitation["organization_id"]
        )

        flash(
            "Registration successful. Please log in."
        )

        return redirect(
            url_for("login")
        )

    connection.close()

    return render_template(
        "join_organization.html",
        invitation=invitation
    )


# =========================================================
# EXTERNAL INVITATION REGISTRATION
#
# After registration:
# 1. A new RSA key pair is created.
# 2. Pending files for this email are found.
# 3. Their AES keys are re-encrypted using the new public key.
# 4. Access is added to file_access.
# =========================================================

@app.route(
    "/external-register/<token>",
    methods=["GET", "POST"]
)
def external_register(token):

    connection = get_connection()

    invitation = connection.execute(
        """
        SELECT *
        FROM external_invitations
        WHERE token = ?
        """,
        (token,)
    ).fetchone()

    if not invitation:

        connection.close()

        flash("This invitation is invalid.")

        return redirect(
            url_for("home")
        )

    if invitation["used_at"]:

        connection.close()

        flash(
            "This invitation has already been used."
        )

        return redirect(
            url_for("login")
        )

    if datetime.now() > datetime.fromisoformat(
        invitation["expires_at"]
    ):

        connection.close()

        flash(
            "This invitation has expired."
        )

        return redirect(
            url_for("home")
        )

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        if not username or not password:

            flash(
                "Please complete all fields."
            )

            connection.close()

            return redirect(
                url_for(
                    "external_register",
                    token=token
                )
            )

        if len(password) < 8:

            flash(
                "Password must be at least 8 characters."
            )

            connection.close()

            return redirect(
                url_for(
                    "external_register",
                    token=token
                )
            )

        existing = connection.execute(
            """
            SELECT id
            FROM users
            WHERE username = ?
            OR email = ?
            """,
            (
                username,
                invitation["email"]
            )
        ).fetchone()

        if existing:

            connection.close()

            flash(
                "This username or email already has an account."
            )

            return redirect(
                url_for(
                    "external_register",
                    token=token
                )
            )

        private_key, public_key = (
            generate_rsa_key_pair()
        )

        public_key_pem = (
            serialize_public_key(public_key)
        )

        private_key_pem = (
            serialize_private_key(private_key)
        )

        encrypted_private_key = (
            encrypt_private_key(
                private_key_pem,
                password
            )
        )

        password_hash = (
            generate_password_hash(password)
        )

        user_cursor = connection.execute(
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
                username,
                invitation["email"],
                password_hash,
                "independent",
                "independent",
                None,
                public_key_pem,
                encrypted_private_key
            )
        )

        new_user_id = user_cursor.lastrowid

        # Automatically give access to every pending file
        granted_count = grant_pending_file_access(
            connection,
            new_user_id,
            invitation["email"],
            public_key_pem
        )

        connection.execute(
            """
            UPDATE external_invitations
            SET used_at = ?
            WHERE id = ?
            """,
            (
                datetime.now().isoformat(
                    timespec="seconds"
                ),
                invitation["id"]
            )
        )

        connection.commit()
        connection.close()

        create_audit_log(
            new_user_id,
            "EXTERNAL_ACCOUNT_CREATED",
            "Account created through external invitation",
            None
        )

        if granted_count > 0:

            flash(
                "Account created successfully. "
                f"You automatically received access to "
                f"{granted_count} shared file(s). "
                "Please log in."
            )

        else:

            flash(
                "Account created successfully. Please log in."
            )

        return redirect(
            url_for("login")
        )

    connection.close()

    return render_template(
        "external_register.html",
        invited_email=invitation["email"]
    )


# =========================================================
# LOGIN
# =========================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        user = get_user_by_username(
            username
        )

        if user:

            clear_expired_lock(user)

            user = get_user_by_username(
                username
            )

            if user["locked_until"]:

                locked_until = datetime.fromisoformat(
                    user["locked_until"]
                )

                if datetime.now() < locked_until:

                    flash(
                        "This account is temporarily locked until "
                        f"{locked_until.strftime('%d %b %Y, %I:%M %p')}."
                    )

                    return render_template(
                        "login.html"
                    )

            if check_password_hash(
                user["password_hash"],
                password
            ):

                connection = get_connection()

                connection.execute(
                    """
                    UPDATE users
                    SET
                        failed_login_attempts = 0,
                        locked_until = NULL
                    WHERE id = ?
                    """,
                    (user["id"],)
                )

                connection.commit()
                connection.close()

                session.clear()

                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["role"] = user["role"]
                session["account_type"] = user["account_type"]
                session["organization_id"] = (
                    user["organization_id"]
                )

                create_audit_log(
                    user["id"],
                    "LOGIN",
                    "User logged into the system",
                    user["organization_id"]
                )

                return redirect(
                    url_for("dashboard")
                )

            failed_attempts = (
                user["failed_login_attempts"] + 1
            )

            connection = get_connection()

            if failed_attempts >= 5:

                locked_until = (
                    datetime.now()
                    + timedelta(hours=1)
                )

                connection.execute(
                    """
                    UPDATE users
                    SET
                        failed_login_attempts = 0,
                        locked_until = ?
                    WHERE id = ?
                    """,
                    (
                        locked_until.isoformat(
                            timespec="seconds"
                        ),
                        user["id"]
                    )
                )

                connection.commit()
                connection.close()

                create_audit_log(
                    user["id"],
                    "ACCOUNT_LOCKED",
                    "Account locked for one hour after five failed login attempts",
                    user["organization_id"]
                )

                flash(
                    "Too many failed attempts. "
                    "Your account has been locked for one hour."
                )

                return render_template(
                    "login.html"
                )

            connection.execute(
                """
                UPDATE users
                SET failed_login_attempts = ?
                WHERE id = ?
                """,
                (
                    failed_attempts,
                    user["id"]
                )
            )

            connection.commit()
            connection.close()

            create_audit_log(
                user["id"],
                "FAILED_LOGIN",
                "Incorrect login password entered",
                user["organization_id"]
            )

        flash(
            "Invalid username or password."
        )

    return render_template(
        "login.html"
    )


# =========================================================
# LOGOUT
# =========================================================

@app.route("/logout")
def logout():

    user = get_current_user()

    if user:

        create_audit_log(
            user["id"],
            "LOGOUT",
            "User logged out",
            user["organization_id"]
        )

    session.clear()

    return redirect(
        url_for("home")
    )


# =========================================================
# WORKSPACE DASHBOARD
# =========================================================

@app.route("/dashboard")
def dashboard():

    if not login_required():

        return redirect(
            url_for("login")
        )

    user = get_current_user()

    return render_template(
        "dashboard.html",
        user=user
    )


# =========================================================
# ORGANIZATION WORKSPACE
# =========================================================

@app.route("/organization-workspace")
def organization_workspace():

    if not login_required():

        return redirect(
            url_for("login")
        )

    user = get_current_user()

    if not user["organization_id"]:

        flash(
            "You are not a member of an organization."
        )

        return redirect(
            url_for("dashboard")
        )

    connection = get_connection()

    files = connection.execute(
        """
        SELECT DISTINCT
            files.*,
            users.username AS owner_name

        FROM files

        JOIN users
        ON files.owner_id = users.id

        LEFT JOIN file_access
        ON files.id = file_access.file_id

        WHERE files.organization_id = ?
        AND files.workspace_type = 'organization'
        AND (
            files.owner_id = ?
            OR file_access.user_id = ?
        )

        ORDER BY files.created_at DESC
        """,
        (
            user["organization_id"],
            user["id"],
            user["id"]
        )
    ).fetchall()

    connection.close()

    return render_template(
        "workspace_files.html",
        files=files,
        workspace_name="Organization Workspace",
        workspace_type="organization"
    )


# =========================================================
# PERSONAL WORKSPACE
# =========================================================

@app.route("/personal-workspace")
def personal_workspace():

    if not login_required():

        return redirect(
            url_for("login")
        )

    user = get_current_user()

    connection = get_connection()

    files = connection.execute(
        """
        SELECT DISTINCT
            files.*,
            users.username AS owner_name

        FROM files

        JOIN users
        ON files.owner_id = users.id

        LEFT JOIN file_access
        ON files.id = file_access.file_id

        WHERE files.organization_id IS NULL
        AND files.workspace_type = 'personal'
        AND (
            files.owner_id = ?
            OR file_access.user_id = ?
        )

        ORDER BY files.created_at DESC
        """,
        (
            user["id"],
            user["id"]
        )
    ).fetchall()

    connection.close()

    return render_template(
        "workspace_files.html",
        files=files,
        workspace_name="Personal Workspace",
        workspace_type="personal"
    )


# =========================================================
# UPLOAD
#
# Personal files are stored immediately.
#
# Existing users:
#   AES key -> encrypted with their public key -> file_access
#
# New recipients:
#   AES key -> temporarily protected -> pending_file_shares
#   Invitation is sent.
#   After registration, access is automatically granted.
# =========================================================

@app.route(
    "/upload/<workspace_type>",
    methods=["GET", "POST"]
)
def upload(workspace_type):

    if not login_required():

        return redirect(
            url_for("login")
        )

    current_user = get_current_user()

    if workspace_type not in [
        "organization",
        "personal"
    ]:

        flash("Invalid workspace.")

        return redirect(
            url_for("dashboard")
        )

    if (
        workspace_type == "organization"
        and not current_user["organization_id"]
    ):

        flash(
            "You do not have an organization workspace."
        )

        return redirect(
            url_for("dashboard")
        )

    if request.method == "POST":

        uploaded_file = request.files.get(
            "file"
        )

        recipient_emails_text = request.form.get(
            "recipients",
            ""
        )

        expiry_date = request.form.get(
            "expiry_date"
        )

        if (
            not uploaded_file
            or uploaded_file.filename == ""
        ):

            flash("Please select a file.")

            return redirect(
                url_for(
                    "upload",
                    workspace_type=workspace_type
                )
            )

        recipient_emails = list(
            set(
                email.strip().lower()
                for email in recipient_emails_text.split(",")
                if email.strip()
            )
        )

        if not recipient_emails:

            flash(
                "Please provide at least one recipient email."
            )

            return redirect(
                url_for(
                    "upload",
                    workspace_type=workspace_type
                )
            )

        connection = get_connection()

        recipients = []
        pending_recipient_emails = []

        for email in recipient_emails:

            recipient = connection.execute(
                """
                SELECT *
                FROM users
                WHERE email = ?
                """,
                (email,)
            ).fetchone()

            # =============================================
            # ORGANIZATION SHARING
            # =============================================

            if workspace_type == "organization":

                if not recipient:

                    connection.close()

                    flash(
                        f"{email} is not registered in your organization."
                    )

                    return redirect(
                        url_for(
                            "upload",
                            workspace_type=workspace_type
                        )
                    )

                if (
                    recipient["organization_id"]
                    != current_user["organization_id"]
                ):

                    connection.close()

                    flash(
                        f"{email} is not a member of your organization."
                    )

                    return redirect(
                        url_for(
                            "upload",
                            workspace_type=workspace_type
                        )
                    )

                recipients.append(recipient)

            # =============================================
            # PERSONAL SHARING
            # =============================================

            else:

                if recipient:

                    recipients.append(recipient)

                else:

                    # Remember this email so access can be
                    # granted automatically after registration.
                    pending_recipient_emails.append(
                        email
                    )

                    # Create an invitation only when there is
                    # no active invitation already.
                    existing_invitation = (
                        connection.execute(
                            """
                            SELECT id
                            FROM external_invitations
                            WHERE email = ?
                            AND used_at IS NULL
                            AND expires_at > ?
                            """,
                            (
                                email,
                                datetime.now().isoformat(
                                    timespec="seconds"
                                )
                            )
                        ).fetchone()
                    )

                    if not existing_invitation:

                        token = secrets.token_urlsafe(32)

                        expires_at = (
                            datetime.now()
                            + timedelta(days=7)
                        )

                        connection.execute(
                            """
                            INSERT INTO external_invitations (
                                email,
                                token,
                                invited_by,
                                expires_at
                            )
                            VALUES (?, ?, ?, ?)
                            """,
                            (
                                email,
                                token,
                                current_user["id"],
                                expires_at.isoformat(
                                    timespec="seconds"
                                )
                            )
                        )

                        invitation_link = url_for(
                            "external_register",
                            token=token,
                            _external=True
                        )

                        try:

                            send_external_invitation_email(
                                email,
                                current_user["username"],
                                invitation_link
                            )

                        except Exception as error:

                            print(
                                "Email sending error:",
                                error
                            )

        # =============================================
        # OWNER ALWAYS HAS ACCESS
        # =============================================

        owner = connection.execute(
            """
            SELECT *
            FROM users
            WHERE id = ?
            """,
            (current_user["id"],)
        ).fetchone()

        authorized_users = {
            recipient["id"]: recipient
            for recipient in recipients
        }

        authorized_users[
            owner["id"]
        ] = owner

        # =============================================
        # GENERATE AES KEY AND ENCRYPT FILE
        # =============================================

        aes_key = generate_aes_key()

        file_data = uploaded_file.read()

        encrypted_file_data = (
            encrypt_file_data(
                file_data,
                aes_key
            )
        )

        stored_filename = (
            f"{uuid.uuid4().hex}.encrypted"
        )

        file_path = os.path.join(
            "encrypted_files",
            stored_filename
        )

        with open(
            file_path,
            "wb"
        ) as encrypted_file:

            encrypted_file.write(
                encrypted_file_data
            )

        # =============================================
        # DETERMINE WORKSPACE OWNERSHIP
        # =============================================

        if workspace_type == "organization":

            file_organization_id = (
                current_user["organization_id"]
            )

        else:

            file_organization_id = None

        # =============================================
        # CREATE FILE RECORD IMMEDIATELY
        # =============================================

        cursor = connection.execute(
            """
            INSERT INTO files (
                owner_id,
                organization_id,
                workspace_type,
                original_filename,
                stored_filename,
                expiry_date
            )
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                current_user["id"],
                file_organization_id,
                workspace_type,
                uploaded_file.filename,
                stored_filename,
                expiry_date or None
            )
        )

        file_id = cursor.lastrowid

        # =============================================
        # GIVE EXISTING USERS ACCESS
        # =============================================

        for user in authorized_users.values():

            recipient_public_key = (
                load_public_key(
                    user["public_key"]
                )
            )

            encrypted_aes_key = (
                encrypt_aes_key_for_recipient(
                    aes_key,
                    recipient_public_key
                )
            )

            connection.execute(
                """
                INSERT INTO file_access (
                    file_id,
                    user_id,
                    encrypted_aes_key
                )
                VALUES (?, ?, ?)
                """,
                (
                    file_id,
                    user["id"],
                    encrypted_aes_key
                )
            )

        # =============================================
        # SAVE PENDING PERSONAL RECIPIENTS
        #
        # The encrypted file already exists.
        # The recipient's temporary AES key is stored securely
        # until they create an account.
        # =============================================

        if (
            workspace_type == "personal"
            and pending_recipient_emails
        ):

            protected_aes_key = (
                protect_pending_aes_key(
                    aes_key
                )
            )

            for email in pending_recipient_emails:

                connection.execute(
                    """
                    INSERT INTO pending_file_shares (
                        file_id,
                        recipient_email,
                        encrypted_aes_key
                    )
                    VALUES (?, ?, ?)
                    """,
                    (
                        file_id,
                        email,
                        protected_aes_key
                    )
                )

        connection.commit()
        connection.close()

        # =============================================
        # AUDIT LOG
        # =============================================

        if workspace_type == "organization":

            log_organization_id = (
                current_user["organization_id"]
            )

        else:

            log_organization_id = None

        create_audit_log(
            current_user["id"],
            "FILE_UPLOADED",
            (
                f"Uploaded file in {workspace_type} workspace"
            ),
            log_organization_id
        )

        if pending_recipient_emails:

            flash(
                "File encrypted and stored successfully. "
                "Invitation(s) were sent to new recipient(s), "
                "who will automatically receive access after "
                "registering with the invited email address."
            )

        else:

            flash(
                "File encrypted and shared successfully."
            )

        if workspace_type == "organization":

            return redirect(
                url_for(
                    "organization_workspace"
                )
            )

        return redirect(
            url_for("personal_workspace")
        )

    return render_template(
        "upload.html",
        workspace_type=workspace_type
    )


# =========================================================
# DOWNLOAD
# =========================================================

@app.route(
    "/download/<int:file_id>",
    methods=["GET", "POST"]
)
def download(file_id):

    if not login_required():

        return redirect(
            url_for("login")
        )

    current_user = get_current_user()

    connection = get_connection()

    file_record = connection.execute(
        """
        SELECT *
        FROM files
        WHERE id = ?
        """,
        (file_id,)
    ).fetchone()

    if not file_record:

        connection.close()

        flash("File not found.")

        return redirect(
            url_for("dashboard")
        )

    # Organization file isolation
    if (
        file_record["workspace_type"]
        == "organization"
    ):

        if (
            current_user["organization_id"]
            != file_record["organization_id"]
        ):

            connection.close()

            flash(
                "You are not authorized to access this file."
            )

            return redirect(
                url_for("dashboard")
            )

    # Check exact file permission
    access = connection.execute(
        """
        SELECT encrypted_aes_key
        FROM file_access
        WHERE file_id = ?
        AND user_id = ?
        """,
        (
            file_id,
            current_user["id"]
        )
    ).fetchone()

    if not access:

        connection.close()

        flash(
            "You are not authorized to access this file."
        )

        return redirect(
            url_for("dashboard")
        )

    # Check expiry
    if file_record["expiry_date"]:

        expiry = datetime.fromisoformat(
            file_record["expiry_date"]
        )

        if datetime.now() > expiry:

            connection.close()

            if (
                file_record["workspace_type"]
                == "organization"
            ):

                log_org = (
                    current_user["organization_id"]
                )

            else:

                log_org = None

            create_audit_log(
                current_user["id"],
                "ACCESS_DENIED",
                "Attempted to access an expired file",
                log_org
            )

            flash("This file has expired.")

            return redirect(
                url_for("dashboard")
            )

    if request.method == "POST":

        account_password = request.form.get(
            "password",
            ""
        )

        if not check_password_hash(
            current_user["password_hash"],
            account_password
        ):

            connection.close()

            flash("Incorrect password.")

            return redirect(
                url_for(
                    "download",
                    file_id=file_id
                )
            )

        try:

            private_key_pem = (
                decrypt_private_key(
                    current_user[
                        "encrypted_private_key"
                    ],
                    account_password
                )
            )

            private_key = load_private_key(
                private_key_pem
            )

            aes_key = (
                decrypt_aes_key_for_recipient(
                    access["encrypted_aes_key"],
                    private_key
                )
            )

            file_path = os.path.join(
                "encrypted_files",
                file_record["stored_filename"]
            )

            with open(
                file_path,
                "rb"
            ) as encrypted_file:

                encrypted_data = (
                    encrypted_file.read()
                )

            decrypted_data = (
                decrypt_file_data(
                    encrypted_data,
                    aes_key
                )
            )

            connection.close()

            if (
                file_record["workspace_type"]
                == "organization"
            ):

                log_org = (
                    current_user["organization_id"]
                )

            else:

                log_org = None

            create_audit_log(
                current_user["id"],
                "FILE_DECRYPTED",
                (
                    f"Decrypted: "
                    f"{file_record['original_filename']}"
                ),
                log_org
            )

            return send_file(
                io.BytesIO(decrypted_data),
                as_attachment=True,
                download_name=(
                    file_record[
                        "original_filename"
                    ]
                ),
                mimetype="application/octet-stream"
            )

        except Exception as error:

            print(
                "Decryption error:",
                error
            )

            connection.close()

            flash(
                "Unable to decrypt the file."
            )

            return redirect(
                url_for(
                    "download",
                    file_id=file_id
                )
            )

    connection.close()

    return render_template(
        "download.html",
        file=file_record
    )


# =========================================================
# ADMIN PANEL
#
# Only organization data is selected.
# Personal files never appear here.
# =========================================================

@app.route("/admin")
def admin_panel():

    if not login_required():

        return redirect(
            url_for("login")
        )

    if not admin_required():

        return redirect(
            url_for("dashboard")
        )

    organization_id = current_organization_id()

    connection = get_connection()

    connection.execute(
        """
        UPDATE users
        SET
            locked_until = NULL,
            failed_login_attempts = 0
        WHERE organization_id = ?
        AND locked_until IS NOT NULL
        AND locked_until <= ?
        """,
        (
            organization_id,
            datetime.now().isoformat(
                timespec="seconds"
            )
        )
    )

    connection.commit()

    users = connection.execute(
        """
        SELECT
            id,
            username,
            email,
            role,
            failed_login_attempts,
            locked_until,
            created_at
        FROM users
        WHERE organization_id = ?
        ORDER BY created_at DESC
        """,
        (organization_id,)
    ).fetchall()

    files = connection.execute(
        """
        SELECT
            files.*,
            users.username AS owner_name
        FROM files

        JOIN users
        ON files.owner_id = users.id

        WHERE files.organization_id = ?
        AND files.workspace_type = 'organization'

        ORDER BY files.created_at DESC
        """,
        (organization_id,)
    ).fetchall()

    user_count = connection.execute(
        """
        SELECT COUNT(*) AS total
        FROM users
        WHERE organization_id = ?
        """,
        (organization_id,)
    ).fetchone()["total"]

    file_count = connection.execute(
        """
        SELECT COUNT(*) AS total
        FROM files
        WHERE organization_id = ?
        AND workspace_type = 'organization'
        """,
        (organization_id,)
    ).fetchone()["total"]

    log_count = connection.execute(
        """
        SELECT COUNT(*) AS total
        FROM audit_logs
        WHERE organization_id = ?
        """,
        (organization_id,)
    ).fetchone()["total"]

    organization = connection.execute(
        """
        SELECT name
        FROM organizations
        WHERE id = ?
        """,
        (organization_id,)
    ).fetchone()

    connection.close()

    return render_template(
        "admin.html",
        users=users,
        files=files,
        user_count=user_count,
        file_count=file_count,
        log_count=log_count,
        organization=organization
    )


# =========================================================
# ADMIN INVITATIONS
# =========================================================

@app.route(
    "/admin/invite",
    methods=["GET", "POST"]
)
def invite_users():

    if not login_required():

        return redirect(
            url_for("login")
        )

    if not admin_required():

        flash(
            "Administrator access is required."
        )

        return redirect(
            url_for("dashboard")
        )

    if request.method == "POST":

        emails = []

        email_text = request.form.get(
            "emails",
            ""
        )

        for email in email_text.split(","):

            email = email.strip().lower()

            if email and "@" in email:

                emails.append(email)

        csv_file = request.files.get(
            "email_file"
        )

        if (
            csv_file
            and csv_file.filename != ""
        ):

            try:

                content = (
                    csv_file.read()
                    .decode("utf-8")
                    .splitlines()
                )

                reader = csv.reader(content)

                for row in reader:

                    if row:

                        email = (
                            row[0]
                            .strip()
                            .lower()
                        )

                        if (
                            email
                            and "@" in email
                        ):

                            emails.append(email)

            except Exception:

                flash(
                    "Unable to read the CSV file."
                )

                return redirect(
                    url_for("invite_users")
                )

        emails = list(set(emails))

        if not emails:

            flash(
                "Please enter at least one valid email "
                "or upload a CSV file."
            )

            return redirect(
                url_for("invite_users")
            )

        connection = get_connection()

        organization = connection.execute(
            """
            SELECT name
            FROM organizations
            WHERE id = ?
            """,
            (current_organization_id(),)
        ).fetchone()

        sent_count = 0

        for email in emails:

            existing_user = connection.execute(
                """
                SELECT id
                FROM users
                WHERE email = ?
                """,
                (email,)
            ).fetchone()

            if existing_user:

                continue

            token = secrets.token_urlsafe(32)

            expires_at = (
                datetime.now()
                + timedelta(days=7)
            )

            connection.execute(
                """
                INSERT INTO invitations (
                    organization_id,
                    email,
                    token,
                    invited_by,
                    expires_at
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    current_organization_id(),
                    email,
                    token,
                    current_user_id(),
                    expires_at.isoformat(
                        timespec="seconds"
                    )
                )
            )

            invitation_link = url_for(
                "join_organization",
                token=token,
                _external=True
            )

            try:

                send_organization_invitation_email(
                    email,
                    organization["name"],
                    invitation_link
                )

                sent_count += 1

            except Exception as error:

                print(
                    "Email sending error:",
                    error
                )

        connection.commit()
        connection.close()

        create_audit_log(
            current_user_id(),
            "INVITATIONS_CREATED",
            (
                f"Created {len(emails)} "
                "organization invitation(s)"
            ),
            current_organization_id()
        )

        flash(
            f"{sent_count} invitation email(s) sent successfully."
        )

        return redirect(
            url_for("admin_panel")
        )

    return render_template(
        "invite_users.html"
    )


# =========================================================
# ORGANIZATION AUDIT LOGS
#
# Personal logs have organization_id = NULL and therefore
# NEVER appear here.
# =========================================================

@app.route("/audit-logs")
def audit_logs():

    if not login_required():

        return redirect(
            url_for("login")
        )

    if not admin_required():

        return redirect(
            url_for("dashboard")
        )

    connection = get_connection()

    logs = connection.execute(
        """
        SELECT
            audit_logs.*,
            users.username

        FROM audit_logs

        LEFT JOIN users
        ON audit_logs.user_id = users.id

        WHERE audit_logs.organization_id = ?

        ORDER BY audit_logs.created_at DESC
        """,
        (current_organization_id(),)
    ).fetchall()

    connection.close()

    return render_template(
        "audit_logs.html",
        logs=logs
    )


# =========================================================
# APPLICATION START
# =========================================================

if __name__ == "__main__":

    app.run(
        debug=True
    )