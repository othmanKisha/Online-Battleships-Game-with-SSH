import math

#########################################################################################################
########################### Phase 3: Modular Arithmetic Helper Methods ##################################
#########################################################################################################

# Used the method here for performing repeated squaring: https://stackoverflow.com/questions/16421311/python-implementing-pow-for-exponentiation-by-squaring-for-very-large-integers


def repeated_squaring(div, modulus, power):
    x = 1
    bits = "{0:b}".format(power)
    for _, bit in enumerate(bits):
        if bit == '1':
            x = ((x**2) * div) % modulus
        elif bit == '0':
            x = (x**2) % modulus
    return x % modulus


def getBytesLen(bytes_num):
    return math.ceil(bytes_num.bit_length() / 8)


# Used the python code from the link attached in the document: https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python


def multiplicative_inverse(a, m):
    g, x, _ = xgcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m


# Used from a comment from the link attached in the document for pdf at page two: http://anh.cs.luc.edu/331/notes/xgcd.pdf


def xgcd(a, b):
    prevx, x = 1, 0
    prevy, y = 0, 1
    while b:
        q = a // b
        x, prevx = prevx - q*x, x
        y, prevy = prevy - q*y, y
        a, b = b, a % b
    return a, prevx, prevy
