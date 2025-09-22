import os
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# ---------- ECC Functions ----------
def generate_keys():
    global node_A_private, node_B_private, node_A_public, node_B_public
    node_A_private = ec.generate_private_key(ec.SECP256R1())
    node_B_private = ec.generate_private_key(ec.SECP256R1())

    node_A_public = node_A_private.public_key()
    node_B_public = node_B_private.public_key()
    print("[+] ECC Keys for Node A & B generated successfully.")


def derive_key(shared_key):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'wsn secure communication'
    ).derive(shared_key)


def establish_shared_secret():
    global symmetric_key_A, symmetric_key_B
    shared_A = node_A_private.exchange(ec.ECDH(), node_B_public)
    shared_B = node_B_private.exchange(ec.ECDH(), node_A_public)

    symmetric_key_A = derive_key(shared_A)
    symmetric_key_B = derive_key(shared_B)

    print("[+] Shared secret established successfully.")


# ---------- Helper: File Hash ----------
def compute_hash(file_path: str) -> str:
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            sha256.update(chunk)
    return sha256.hexdigest()


# ---------- Text Encryption ----------
def encrypt_message(plaintext: str) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key_A), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
    return iv + ciphertext


def decrypt_message(ciphertext: bytes) -> str:
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(symmetric_key_B), modes.CFB(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return plaintext.decode()


# ---------- Image Encryption ----------
def encrypt_image(input_path: str, output_path: str):
    with open(input_path, "rb") as f:
        img_data = f.read()

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(symmetric_key_A), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(img_data) + encryptor.finalize()

    with open(output_path, "wb") as f:
        f.write(iv + encrypted_data)

    print(f"[+] Image encrypted and saved as {output_path}")


def decrypt_image(input_path: str, output_path: str, original_path: str = None):
    with open(input_path, "rb") as f:
        encrypted_data = f.read()

    iv = encrypted_data[:16]
    cipher = Cipher(algorithms.AES(symmetric_key_B), modes.CFB(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data[16:]) + decryptor.finalize()

    with open(output_path, "wb") as f:
        f.write(decrypted_data)

    print(f"[+] Image decrypted and saved as {output_path}")

    if original_path:  # Integrity check
        orig_hash = compute_hash(original_path)
        new_hash = compute_hash(output_path)

        if orig_hash == new_hash:
            print("[✔] Integrity Verified: Decrypted image matches the original.")
        else:
            print("[✘] Integrity Failed: Decrypted image is corrupted or altered!")


# ---------- Menu Interface ----------
def menu():
    generate_keys()
    establish_shared_secret()

    encrypted_text = None
    encrypted_img_file = None

    while True:
        print("\n===== ECC Secure Communication =====")
        print("1. Encrypt Text")
        print("2. Decrypt Text")
        print("3. Encrypt Image")
        print("4. Decrypt Image (with integrity check)")
        print("5. Exit")
        choice = input("Enter choice: ").strip()

        if choice == "1":
            message = input("Enter message: ")
            encrypted_text = encrypt_message(message)
            print(f"[+] Encrypted (hex): {encrypted_text.hex()}")

        elif choice == "2":
            if encrypted_text:
                decrypted_text = decrypt_message(encrypted_text)
                print(f"[+] Decrypted: {decrypted_text}")
            else:
                print("[!] No text has been encrypted yet.")

        elif choice == "3":
            path = input("Enter image file path: ").strip()
            if os.path.exists(path):
                encrypted_img_file = "encrypted_image.bin"
                encrypt_image(path, encrypted_img_file)
            else:
                print("[!] File not found.")

        elif choice == "4":
            if encrypted_img_file:
                output_file = "decrypted_image.jpg"
                original_file = input("Enter original image path for integrity check: ").strip()
                if os.path.exists(original_file):
                    decrypt_image(encrypted_img_file, output_file, original_file)
                else:
                    print("[!] Original file not found. Skipping integrity check.")
                    decrypt_image(encrypted_img_file, output_file)
            else:
                print("[!] No image has been encrypted yet.")

        elif choice == "5":
            print("Exiting...")
            break
        else:
            print("[!] Invalid choice. Try again.")


if __name__ == "__main__":
    menu()
