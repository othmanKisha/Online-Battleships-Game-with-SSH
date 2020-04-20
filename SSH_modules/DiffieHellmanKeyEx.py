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
        public_value = mod_op.repeated_squaring(self.g, self.m, self.exp)
        return public_value

    # exp_recv is g^(the other's exponent) mod m
    def get_secret_key(self, exp_recv):
        secret_key = mod_op.repeated_squaring(exp_recv, self.m, self.exp)
        return secret_key

    def generate_H(self, id1, id2, Ra, Rb, ga, gb, gab):
        id1_B = bytes(id1.encode())
        id2_B = bytes(id2.encode())
        Ra_B = Ra.to_bytes(mod_op.getBytesLen(Ra), 'little')
        Rb_B = Rb.to_bytes(mod_op.getBytesLen(Rb), 'little')
        ga_B = ga.to_bytes(mod_op.getBytesLen(ga), 'little')
        gb_B = gb.to_bytes(mod_op.getBytesLen(gb), 'little')
        gab_B = gab.to_bytes(mod_op.getBytesLen(gab), 'little')
        H = sha256(id1_B + id2_B + Ra_B + Rb_B + ga_B + gb_B + gab_B).digest()
        return H
