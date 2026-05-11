# Sender sends encrypted messages to the receiver
# Encryption is done using AES-256-CBC mode
# Input: file.txt, receiver_public.pem
# Output: trabnsmitted_data.json

import json
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Hash import HMAC, SHA256

# Default demo values for testing
SENDER = "Alice"
RECEIVER = "Bob"
PLAINTEXT_FILE = "file.txt"
RECEIVER_PUBLIC_KEY_FILE = f"../{RECEIVER}_public.pem"
TRANSMITTED_DATA_FILE = "Transmitted_Data.json"


def encrypt_message_with_aes(plaintext):
    """
    Encrypts plaintext using AES-256-CBC mode.
    Returns:
    - aes_key: The randomly generated AES key
    - iv: The initialization vector used for encryption
    - ciphertext: The encrypted message
    """
    aes_key = get_random_bytes(32)  # 32 bytes = 256-bit key
    iv = get_random_bytes(16)  # AES block size is 16 bytes
    
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)     # Create AES-256 cipher that uses CBC mode and starts with this IV

    # Pad the plaintext to be a multiple of the block size and encrypt
    padded_plaintext = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)

    return aes_key, iv, ciphertext

def encrypt_aes_key_with_rsa(aes_key, receiver_public_key_file):
    """
    Encrypts the AES key using the receiver's RSA public key.
    Returns:
    - encrypted AES key.
    """
    with open(receiver_public_key_file, "rb") as key_file:
        receiver_public_key = RSA.import_key(key_file.read())
    
    cipher_rsa = PKCS1_OAEP.new(receiver_public_key)  # Create a new PKCS1_OAEP cipher object using the receiver's public key
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)   # Encrypt the AES key with the RSA public key

    return encrypted_aes_key

def generate_hmac(mac_key, encrypted_aes_key, iv, ciphertext):
    """
    Generate HMAC-SHA256 
    """
    h = HMAC.new(mac_key, digestmod=SHA256)
    h.update(encrypted_aes_key + iv + ciphertext)
    return h.digest()


def main():
    # Read the plaintext message from the file
    with open(PLAINTEXT_FILE, "r") as file:
        plaintext = file.read()

    # Encrypt the plaintext message using AES-256-CBC
    aes_key, iv, ciphertext = encrypt_message_with_aes(plaintext)

    # Encrypt the AES key using the receiver's RSA public key
    encrypted_aes_key = encrypt_aes_key_with_rsa(aes_key, RECEIVER_PUBLIC_KEY_FILE)

    # Use AES key for mac key for simplicity
    mac = generate_hmac(aes_key, encrypted_aes_key, iv, ciphertext)

    # Prepare the data to be transmitted
    transmitted_data = {
        "sender": SENDER,
        "receiver": RECEIVER,
        "encrypted_aes_key": base64.b64encode(encrypted_aes_key).decode(),  # Encode to base64 for JSON serialization
        "iv": base64.b64encode(iv).decode(),  # Encode IV to base64 for JSON serialization
        "ciphertext": base64.b64encode(ciphertext).decode(),  # Encode ciphertext to base64 for JSON serialization
        "hmac": base64.b64encode(mac).decode() # Encode HMAC to base64 for JSON serialization
    }

    # Save the transmitted data to a JSON file
    with open(TRANSMITTED_DATA_FILE, "w") as json_file:
        json.dump(transmitted_data, json_file, indent=4)
    print(f"Message encrypted and saved to {TRANSMITTED_DATA_FILE}")

if __name__ == "__main__":
    main()