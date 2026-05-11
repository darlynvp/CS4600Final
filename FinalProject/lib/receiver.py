# Receiver retrieves transmitted data from the channel and decodes it back to the original message.\
# Input: Transmitted_Data.json
# Output: Decrypted message printed to the console.
# ^ temporary; can change to writing to a file if needed

import json
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Util.Padding import unpad

# Default demo values for testing
RECEIVER = "Bob"
TRANSMITTED_DATA_FILE = "Transmitted_Data.json"
RECEIVER_PRIVATE_KEY_FILE = f"../{RECEIVER}_private.pem"


def decrypt_aes_key_with_rsa(encrypted_aes_key, receiver_private_key_file):
    """
    Decrypts the AES key using the receiver's RSA private key.
    Returns:
    - decrypted AES key.
    """
    with open(receiver_private_key_file, "rb") as key_file:
        receiver_private_key = RSA.import_key(key_file.read())
    
    cipher_rsa = PKCS1_OAEP.new(receiver_private_key)  # Create a new PKCS1_OAEP cipher object using the receiver's private key
    aes_key = cipher_rsa.decrypt(encrypted_aes_key)     # Decrypt the AES key with the RSA private key

    return aes_key

def decrypt_message_with_aes(ciphertext, aes_key, iv):
    """
    Decrypts the ciphertext using AES-256-CBC mode.
    Returns:
    - decrypted plaintext message.
    """
    cipher = AES.new(aes_key, AES.MODE_CBC, iv)  # Create AES-256 cipher that uses CBC mode and starts with the same IV
    padded_plaintext = cipher.decrypt(ciphertext)  # Decrypt the ciphertext
    plaintext = unpad(padded_plaintext, AES.block_size).decode()  # Unpad and decode the plaintext

    return plaintext

def main():
    # Read the transmitted data from the JSON file
    with open(TRANSMITTED_DATA_FILE, "r") as file:
        transmitted_data = json.load(file)

    # Decode the base64-encoded values
    encrypted_aes_key = base64.b64decode(transmitted_data["encrypted_aes_key"])
    iv = base64.b64decode(transmitted_data["iv"])
    ciphertext = base64.b64decode(transmitted_data["ciphertext"])

    # Decrypt the AES key using the receiver's RSA private key
    aes_key = decrypt_aes_key_with_rsa(encrypted_aes_key, RECEIVER_PRIVATE_KEY_FILE)

    # Decrypt the message using the decrypted AES key and IV
    decrypted_message = decrypt_message_with_aes(ciphertext, aes_key, iv)

    # Print the decrypted message to the console
    print("Decrypted message:")
    print(decrypted_message)

if __name__ == "__main__":
    main()