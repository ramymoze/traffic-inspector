from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

key = b"dfa9009d1bda63e85d1a7ee9bbb1ece4"
# will be changed later and put into an env file


def encrypt(plaintext):
    iv = get_random_bytes(16)
    cipher = AES.new(key, 2, iv)
    padded_plaintext = pad(plaintext, AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return iv + ciphertext


def decrypt(ciphertext):
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    cipher_dec = AES.new(key, 2, iv)
    padded_plaintext = cipher_dec.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, AES.block_size)
    return plaintext
