from hashlib import sha256
from base64 import b64decode, b64encode
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from . import ModArithmetic as mod_op

########################################################################################
########################### Phase 2: AES Cryptosystem ##################################
########################################################################################


class Cryptosystem (object):

    def __init__(self, key, bs, opponent):
        key_len = mod_op.getBytesLen(key)
        self.key = sha256(key.to_bytes(key_len, 'little')).digest()
        self.bs = bs
        self.opponent = opponent

    def generate_initialization_vector(self):
        self.iv = get_random_bytes(self.bs)

    def set_initialization_vector(self, iv):
        self.iv = iv
        print("--------------------------------------------------------------------")
        print("  The IV value received from {}: {}" .format(
            self.opponent, self.iv.hex()))
        print("--------------------------------------------------------------------")

    # The Encryption Method {IV is one of the parameters of the method}
    def encryption(self, plaintext):
        cipher = AES.new(self.key, AES.MODE_CBC, iv=self.iv)
        padded_text = pad(plaintext.encode('utf-8'), self.bs)
        ciphertext = self.iv + cipher.encrypt(padded_text)
        print("--------------------------------------------------------------------")
        print("  The encrypted value sent to {}: {}" .format(
            self.opponent, ciphertext[self.bs:].hex()))
        print("--------------------------------------------------------------------")
        ciphertext = b64encode(ciphertext)
        return ciphertext

    # The Decryption Method {IV will be sent from the received ciphertext}
    def decryption(self, ciphertext):
        ciphertext = b64decode(ciphertext)
        iv = ciphertext[:self.bs]
        cipher = AES.new(self.key, AES.MODE_CBC, iv=iv)
        padded_text = cipher.decrypt(ciphertext[self.bs:])
        plaintext = unpad(padded_text, self.bs)
        return plaintext

    # Method for printing the hashed key
    def print_key(self):
        print("--------------------------------------------------------------------")
        print("  The key used for this cryptosystem is {} " .format(self.key.hex()))
        print("--------------------------------------------------------------------")

    # This method is to "destroy" the key at the end of a session
    def destroy_key(self):
        self.key = 0
