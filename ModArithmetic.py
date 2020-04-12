#########################################################################################################
########################### Phase 3: Modular Arithmetic Helper Methods ##################################
#########################################################################################################


def repeated_squaring(div, modulus, power):
    if power == 0:
        return 1
    elif power == 1:
        return Mod(div, modulus)
    elif Mod(power, 2) != 0:
        return Mod(div * repeated_squaring(div*div, modulus, (power - 1) / 2), modulus)
    else:
        return Mod(repeated_squaring(div * div, modulus, power / 2), modulus)


def Mod(div, modulus):
    return div % modulus

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
        q = a/b
        x, prevx = prevx - q*x, x
        y, prevy = prevy - q*y, y
        a, b = b, Mod(a, b)
    return a, prevx, prevy
