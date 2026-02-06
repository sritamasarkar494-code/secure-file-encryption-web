from flask import Flask, render_template, request, send_file, flash
import io
from crypto_utils import encrypt_data, decrypt_data

app = Flask(__name__)
app.secret_key = "temporary-session-key"

@app.route("/", methods=["GET", "POST"])
def encrypt():
    if request.method == "POST":
        file = request.files.get("file")
        password = request.form.get("password", "").strip()


        if not file or not password:
            flash("File and password are required")
            return render_template("index.html")

        encrypted = encrypt_data(file.read(), password.encode())

        return send_file(
            io.BytesIO(encrypted),
            as_attachment=True,
            download_name="encrypted.bin",
            mimetype="application/octet-stream"
        )

    return render_template("index.html")

@app.route("/decrypt", methods=["GET", "POST"])
def decrypt():
    if request.method == "POST":
        file = request.files.get("file")
        password = request.form.get("password", "").strip()


        if not file or not password:
            flash("File and password are required")
            return render_template("decrypt.html")

        try:
            decrypted = decrypt_data(file.read(), password.encode())
        except Exception:
            flash("Wrong password or corrupted file")
            return render_template("decrypt.html")

        return send_file(
            io.BytesIO(decrypted),
            as_attachment=True,
            download_name="decrypted_file",
            mimetype="application/octet-stream"

        )

    return render_template("decrypt.html")

if __name__ == "__main__":
    app.run(debug=True)