from flask import Flask, render_template, request, jsonify, session
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os, base64, uuid

app = Flask(__name__)
app.secret_key = "supersecret123"  # ⚠️ Replace in production

# ---------------- Demo user ----------------
VALID_USERNAME = "admin"
VALID_PASSWORD = "password"

nodes_data = {}

# ------------------ Helpers ----------------
def get_aes_key(secret: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"ecc-demo").derive(secret)

def encrypt_bytes(data: bytes, key: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(data) + encryptor.finalize()
    return iv + ct

def decrypt_bytes(enc: bytes, key: bytes) -> bytes:
    iv, ct = enc[:16], enc[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()

# ------------------ Routes ----------------
@app.route("/")
def index():
    return render_template("index.html")

# ---------- Login ----------
@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(force=True)
    if data.get("username") == VALID_USERNAME and data.get("password") == VALID_PASSWORD:
        session_id = str(uuid.uuid4())
        session["user"] = data["username"]
        session["session_id"] = session_id
        nodes_data[session_id] = {}
        return jsonify({"success": True})
    return jsonify({"success": False, "message": "Invalid credentials"}), 401

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"success": True, "message": "Logged out"})

# ---------- ECC ----------
@app.route("/generate-keys", methods=["POST"])
def generate_keys():
    sid = session.get("session_id")
    if not sid:
        return jsonify({"success": False}), 401

    privA = ec.generate_private_key(ec.SECP256R1())
    privB = ec.generate_private_key(ec.SECP256R1())
    nodes_data[sid]["privA"], nodes_data[sid]["privB"] = privA, privB

    pubA = privA.public_key().public_bytes(serialization.Encoding.PEM,
                                           serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    pubB = privB.public_key().public_bytes(serialization.Encoding.PEM,
                                           serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return jsonify({"success": True, "node_A_public": pubA, "node_B_public": pubB})

@app.route("/establish-secret", methods=["POST"])
def establish_secret():
    sid = session.get("session_id")
    if not sid or "privA" not in nodes_data[sid]:
        return jsonify({"success": False}), 400

    privA, privB = nodes_data[sid]["privA"], nodes_data[sid]["privB"]
    sharedA = privA.exchange(ec.ECDH(), privB.public_key())
    sharedB = privB.exchange(ec.ECDH(), privA.public_key())
    keyA = get_aes_key(sharedA)
    keyB = get_aes_key(sharedB)
    nodes_data[sid]["key"] = keyA
    return jsonify({"success": True, "keys_match": keyA==keyB, "symmetric_key_length": len(keyA)})

# ---------- Text Encryption ----------
@app.route("/encrypt-text", methods=["POST"])
def encrypt_text():
    sid = session.get("session_id")
    if not sid or "key" not in nodes_data[sid]:
        return jsonify({"success": False}), 400
    msg = request.get_json(force=True).get("message", "").encode()
    key = nodes_data[sid]["key"]
    enc = encrypt_bytes(msg, key)
    return jsonify({"success": True, "encrypted_hex": enc.hex(), "encrypted_b64": base64.b64encode(enc).decode()})

@app.route("/decrypt-text", methods=["POST"])
def decrypt_text():
    sid = session.get("session_id")
    if not sid or "key" not in nodes_data[sid]:
        return jsonify({"success": False}), 400
    enc_hex = request.get_json(force=True).get("encrypted_hex")
    if not enc_hex:
        return jsonify({"success": False, "message": "No input"}), 400
    enc = bytes.fromhex(enc_hex)
    key = nodes_data[sid]["key"]
    pt = decrypt_bytes(enc, key)
    return jsonify({"success": True, "decrypted_text": pt.decode(errors="ignore")})

# ---------- Image Encryption ----------
@app.route("/encrypt-image", methods=["POST"])
def encrypt_image():
    sid = session.get("session_id")
    if not sid or "key" not in nodes_data[sid]:
        return jsonify({"success": False}), 400
    if "file" not in request.files:
        return jsonify({"success": False, "message": "No file uploaded"}), 400
    file = request.files["file"]
    data = file.read()
    key = nodes_data[sid]["key"]
    enc = encrypt_bytes(data, key)
    enc_b64 = base64.b64encode(enc).decode()
    return jsonify({"success": True, "encrypted_base64": enc_b64})

@app.route("/decrypt-image", methods=["POST"])
def decrypt_image():
    sid = session.get("session_id")
    if not sid or "key" not in nodes_data[sid]:
        return jsonify({"success": False}), 400
    enc_b64 = request.form.get("encrypted_base64") or request.get_json(force=True).get("encrypted_base64")
    if not enc_b64:
        return jsonify({"success": False, "message": "No encrypted data"}), 400
    enc = base64.b64decode(enc_b64)
    key = nodes_data[sid]["key"]
    pt = decrypt_bytes(enc, key)
    pt_b64 = base64.b64encode(pt).decode()
    return jsonify({"success": True, "decrypted_base64": pt_b64})

if __name__ == "__main__":
    app.run(debug=True)
