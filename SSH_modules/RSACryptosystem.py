from . import ModArithmetic as mod_op
########################################################################################
########################### Phase 3: RSA Cryptosystem ##################################
########################################################################################


class Cryptosystem (object):

    def __init__(self, p, q, e):
        self.p = p
        self.q = q
        self.e = e
        self.d = mod_op.multiplicative_inverse(self.e, (self.p-1)*(self.q-1))
        self.N = self.p * self.q

    # The encryption method {C = (plaintext ^ e) mod N} ==> C = {plaintext}Bob
    def encryption(self, plaintext, e, N):
        # e and N here are the public key of the other party
        ciphertext = mod_op.repeated_squaring(plaintext, N, e)
        return ciphertext

    # The decryption method {plaintext = (C ^ d) mod N} ==> plaintext = [C]Alice
    def decryption(self, ciphertext):
        plaintext = mod_op.repeated_squaring(ciphertext, self.N, self.d)
        return plaintext

    # Digital signing method {signature = (plaintext ^ d) mod N} ==> signature = [plaintext]Alice
    def digital_sign(self, plaintext):
        digital_signature = mod_op.repeated_squaring(plaintext, self.N, self.d)
        return digital_signature

    # This method is for signature verification using the other party's public key ==> plaintext = {signature}other party
    def verify_signature(self, N, e, S, unique_id, H):
        verify = mod_op.repeated_squaring(S, N, e)
        test = int.from_bytes((bytes(unique_id.encode()) + H), 'little')
        if verify == test:
            return True
        return False

    # This method to get the public key without asking for N and e
    def get_public_key(self):
        return (self.N, self.e)

    # This method is not for implementing the protocol or RSA, but it will be used for testing only
    def manipulate_private_key(self, d):
        self.d = d
