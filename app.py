import os
import secrets
from pathlib import Path
from flask import Flask, render_template, request, send_file, flash, redirect, url_for
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25 MB
app.config["UPLOAD_FOLDER"] = Path("instance") / "uploads"
app.config["UPLOAD_FOLDER"].mkdir(parents=True, exist_ok=True)

MAGIC = b"SFE1"
SALT_LEN = 16
NONCE_LEN = 12
KEY_LEN = 32  # 32 bytes = 256 bits
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from the user's password using scrypt."""
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))

def encrypt_bytes(data: bytes, password: str) -> bytes:
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    key = derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, data, MAGIC)
    return MAGIC + salt + nonce + ciphertext

def decrypt_bytes(blob: bytes, password: str) -> bytes:
    minimum = len(MAGIC) + SALT_LEN + NONCE_LEN + 16
    if len(blob) < minimum or not blob.startswith(MAGIC):
        raise ValueError("This does not appear to be a valid SFE encrypted file.")
    offset = len(MAGIC)
    salt = blob[offset:offset + SALT_LEN]
    offset += SALT_LEN
    nonce = blob[offset:offset + NONCE_LEN]
    ciphertext = blob[offset + NONCE_LEN:]
    key = derive_key(password, salt)
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, MAGIC)
    except Exception as exc:
        raise ValueError("Incorrect password or the encrypted file has been modified.") from exc

@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")

@app.route("/encrypt", methods=["POST"])
def encrypt():
    uploaded = request.files.get("file")
    password = request.form.get("password", "")
    if not uploaded or not uploaded.filename:
        flash("Please choose a file to encrypt.", "error")
        return redirect(url_for("index"))
    if len(password) < 8:
        flash("Use a password with at least 8 characters.", "error")
        return redirect(url_for("index"))
    original_name = secure_filename(uploaded.filename) or "file"
    data = uploaded.read()
    encrypted = encrypt_bytes(data, password)
    out_path = app.config["UPLOAD_FOLDER"] / f"{secrets.token_hex(12)}.sfe"
    out_path.write_bytes(encrypted)
    return send_file(out_path, as_attachment=True, download_name=original_name + ".sfe",
                     mimetype="application/octet-stream")

@app.route("/decrypt", methods=["POST"])
def decrypt():
    uploaded = request.files.get("file")
    password = request.form.get("password", "")
    if not uploaded or not uploaded.filename:
        flash("Please choose an encrypted .sfe file.", "error")
        return redirect(url_for("index"))
    if not password:
        flash("Enter the password used during encryption.", "error")
        return redirect(url_for("index"))
    encrypted_name = secure_filename(uploaded.filename) or "encrypted.sfe"
    try:
        recovered = decrypt_bytes(uploaded.read(), password)
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("index"))
    original_name = encrypted_name[:-4] if encrypted_name.lower().endswith(".sfe") else "decrypted_file"
    original_name = secure_filename(original_name) or "decrypted_file"
    out_path = app.config["UPLOAD_FOLDER"] / f"{secrets.token_hex(12)}_{original_name}"
    out_path.write_bytes(recovered)
    return send_file(out_path, as_attachment=True, download_name=original_name,
                     mimetype="application/octet-stream")

@app.errorhandler(413)
def too_large(_error):
    flash("File is too large. The maximum supported size is 25 MB.", "error")
    return redirect(url_for("index"))

if __name__ == "__main__":
    # Local development only. For deployment, use a production WSGI server and HTTPS.
    app.run(host="127.0.0.1", port=5000, debug=False)