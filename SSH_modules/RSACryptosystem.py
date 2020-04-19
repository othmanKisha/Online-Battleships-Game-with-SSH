from base64 import b64encode, b64decode
from . import ModArithmetic as mod_op
########################################################################################
########################### Phase 3: RSA Cryptosystem ##################################
########################################################################################


class Cryptosystem (object):

    def __init__(self, p, q, e):
        self.p = p
        self.q = q
        self.e = e
        self.d = mod_op.multiplicative_inverse(
            a=self.e, m=(self.p - 1) * (self.q - 1))
        self.N = self.p * self.q

    # The encryption method {C = (plaintext ^ e) mod N} ==> C = {plaintext}Bob
    def encryption(self, plaintext, e, N):
        # e and N here are the public key of the other party
        ciphertext = mod_op.repeated_squaring(
            div=plaintext, modulus=N, power=e)
        ciphertext = b64encode(ciphertext)
        return ciphertext

    # The decryption method {plaintext = (C ^ d) mod N} ==> plaintext = [C]Alice
    def decryption(self, ciphertext):
        ciphertext = b64decode(ciphertext)
        plaintext = mod_op.repeated_squaring(
            div=ciphertext, modulus=self.N, power=self.d)
        return plaintext

    # Digital signing method {signature = (plaintext ^ d) mod N} ==> signature = [plaintext]Alice
    def digital_sign(self, plaintext):
        digital_signature = mod_op.repeated_squaring(
            div=plaintext, modulus=self.N, power=self.d)
        return digital_signature

    # This method is for signature verification using the other party's public key ==> plaintext = {signature}other party
    def verify_signature(self, N, e, S, ip, H):
        verify = mod_op.repeated_squaring(div=S, modulus=N, power=e)
        ip_bytes = bytes(ip.encode())
        test = int.from_bytes((ip_bytes + H), 'little')
        if verify == test:
            return True
        return False

    # This method to get the public key without asking for N and e
    def get_public_key(self):
        return (self.N, self.e)
