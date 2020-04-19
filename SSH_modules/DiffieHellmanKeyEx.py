from . import ModArithmetic as mod_op
from hashlib import sha256

###################################################################################################
########################### Phase 3: Diffie-Hellman Key Exchange ##################################
###################################################################################################


class KeyExchange (object):

    def __init__(self, g, m):
        self.g = g
        self.m = m

    # At the end of each key exchange, this method should be called to "destroy" exponent
    def destroy_exponent(self):
        print("  >Destroying the exponent . . .")
        self.exp = 0

    # At the beginning of each key exchange, this method should be called
    # The secret exponent for either Alice or Bob
    def set_new_secret_exponent(self, exp):
        print("  >Setting the new exponent . . .")
        self.exp = exp

    def get_public_value(self):
        public_value = mod_op.repeated_squaring(
            div=self.g, modulus=self.m, power=self.exp)
        return public_value

    # exp_recv is g^(the other's exponent) mod m
    def get_secret_key(self, exp_recv):
        secret_key = mod_op.repeated_squaring(
            div=exp_recv, modulus=self.m, power=self.exp)
        return secret_key

    def generate_H(self, id_1, id_2, R_1, R_2, pub_v1, pub_v2, secret):
        R1_bytes = R_1.to_bytes(mod_op.getBytesLen(R_1), 'little')
        R2_bytes = R_2.to_bytes(mod_op.getBytesLen(R_2), 'little')
        pub_v1_bytes = pub_v1.to_bytes(mod_op.getBytesLen(pub_v1), 'little')
        pub_v2_bytes = pub_v2.to_bytes(mod_op.getBytesLen(pub_v2), 'little')
        secret_bytes = secret.to_bytes(mod_op.getBytesLen(secret), 'little')
        H = sha256(bytes(id_1.encode()) + bytes(id_2.encode()) + R1_bytes + R2_bytes +
                   pub_v1_bytes + pub_v2_bytes + secret_bytes).digest()
        return H
