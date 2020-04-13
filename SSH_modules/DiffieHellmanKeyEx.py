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
        self.exp = 0

    # At the beginning of each key exchange, this method should be called
    # The secret exponent for either Alice or Bob
    def set_new_secret_exponent(self, exp):
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
        # Should be modified later
        H = sha256((id_1, id_2, R_1, R_2, pub_v1, pub_v2, secret))
        return H
