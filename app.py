from flask import Flask, render_template, request, send_file, flash
import io
import os
from crypto_utils import encrypt_data, decrypt_data
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)

# 🔐 Use environment variable for secret key (production standard)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(32))

# 🔐 Limit file upload size (10MB)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

# 🔐 Fix for deployment behind proxy (Railway / Nginx)
app.wsgi_app = ProxyFix(app.wsgi_app)


# 🛡 Security Headers
@app.after_request
def add_security_headers(response):
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; script-src 'self'"
    return response


def validate_input(file, password, template):
    if not file or file.filename == "":
        flash("Please select a file.")
        return render_template(template)

    if not password:
        flash("Password is required.")
        return render_template(template)

    if len(password) < 8:
        flash("Password must be at least 8 characters long.")
        return render_template(template)

    return None


@app.route("/", methods=["GET", "POST"])
def encrypt():
    if request.method == "POST":
        file = request.files.get("file")
        password = request.form.get("password", "").strip()

        validation = validate_input(file, password, "index.html")
        if validation:
            return validation

        try:
            encrypted = encrypt_data(file.read(), password.encode())

            return send_file(
                io.BytesIO(encrypted),
                as_attachment=True,
                download_name="encrypted.sfe",
                mimetype="application/octet-stream"
            )

        except Exception:
            flash("Encryption failed.")
            return render_template("index.html")

    return render_template("index.html")


@app.route("/decrypt", methods=["GET", "POST"])
def decrypt():
    if request.method == "POST":
        file = request.files.get("file")
        password = request.form.get("password", "").strip()

        validation = validate_input(file, password, "decrypt.html")
        if validation:
            return validation

        try:
            decrypted = decrypt_data(file.read(), password.encode())

            return send_file(
                io.BytesIO(decrypted),
                as_attachment=True,
                download_name="decrypted_file",
                mimetype="application/octet-stream"
            )

        except Exception:
            flash("Wrong password, corrupted file, or invalid format.")
            return render_template("decrypt.html")

    return render_template("decrypt.html")
if __name__ == "__main__":
    app.run()


