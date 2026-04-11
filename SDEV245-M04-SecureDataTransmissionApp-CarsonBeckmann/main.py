import os
from auth import login
from crypto_utils import get_key, sha256_hash, encrypt_aes, decrypt_aes, verify_integrity

def read_input():
    choice = input("Do you want to enter a message (m) or a file path (f)? ").lower()
    if choice == 'm':
        data = input("Enter your message: ").encode('utf-8')
        return data, "message"
    elif choice == 'f':
        path = input("Enter file path: ").strip()
        if not os.path.exists(path):
            print("File not found")
            return None, None
        with open(path, "rb") as f:
            data = f.read()
        return data, path
    else:
        print("Invalid choice")
        return None, None

def main():
    print("=== Secure Application ===")
    username, role = login()
    if not username:
        return

    key = get_key()

    while True:
        print("\nOptions:")
        print("1. Encrypt & hash input (admin only)")
        print("2. Decrypt & verify integrity (admin only)")
        print("3. Compute SHA-256 hash of input (any role)")
        print("4. Exit")
        choice = input("Select: ")

        if choice == '1':
            if role != 'admin':
                print("Access denied: only admin can encrypt.")
                continue
            data, src = read_input()
            if data is None:
                continue
            orig_hash = sha256_hash(data)
            print(f"Original SHA-256: {orig_hash}")
            encrypt = encrypt_aes(data, key)
            print(f"Encrypt (hex): {encrypt.hex()[:64]}...")
            with open("ciphertext.bin", "wb") as f:
                f.write(encrypt)
            print("Ciphertext saved to ciphertext.bin")
            with open("original_hash.txt", "w") as f:
                f.write(orig_hash)
            print("Original hash saved to original_hash.txt")
        elif choice == '2':
            if role != 'admin':
                print("Access denied: only admin can decrypt.")
                continue
            if not os.path.exists("ciphertext.bin") or not os.path.exists("original_hash.txt"):
                print("No ciphertext or hash found. Run option 1 first.")
                continue
            try:
                with open("ciphertext.bin", "rb") as f:
                    ciphertext = f.read()
                with open("original_hash.txt", "r") as f:
                    expected_hash = f.read().strip()
                decrypted_data = decrypt_aes(ciphertext, key)
            except Exception as e:
                print(f"Decryption failed: {e}")
                continue
            decrypted_hash = sha256_hash(decrypted_data)
            print(f"Decrypted hash: {decrypted_hash}")
            if decrypted_hash == expected_hash:
                print("Integrity verified: hashes match.")
                try:
                    print("Decrypted content (as text):", decrypted_data.decode('utf-8'))
                except:
                    print("Decrypted content (binary):", decrypted_data[:100])
            else:
                print("INTEGRITY FAILURE: hashes do not match.")

        elif choice == '3':
            data, src = read_input()
            if data is None:
                continue
            print(f"SHA-256 hash: {sha256_hash(data)}")

        elif choice == '4':
            print("Goodbye.")
            break
        else:
            print("Invalid option")

if __name__ == "__main__":
    main()