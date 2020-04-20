import socket
from Crypto.Cipher import AES as SymCrypto
from Crypto.Util.Padding import pad
from base64 import b64encode, b64decode
from Crypto.Random import get_random_bytes
from . import AESCryptosystem as AES
from . import RSACryptosystem as RSA
from . import DiffieHellmanKeyEx as DiffieHellman
from . import ModArithmetic as mod_op

###########################################################################################
########################### Phase 3: SSH Protocol Client ##################################
###########################################################################################


class Client (object):

    def __init__(self, port, opponent, username, p, q, e, m, g):
        self.port = port
        self.opponent = opponent
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ip = socket.gethostbyname(socket.gethostname())
        self.username = username
        self.set_key_exchange(g, m)
        self.set_public_key_crypto(p, q, e)
        # This line is for testing the case when trudy tries to communicate as alice
        # self.rsa.manipulate_private_key(1234)

    def connect(self):
        # This is to wait untill connected to player 2(server)
        while True:
            try:
                self.socket.connect((self.ip, self.port))
                break
            except Exception as _:
                pass
        print("  Congartulations: you are connect, now you can start the game. ")
        print("  IP address of {}: {}" .format(self.opponent, self.ip))

    def disconnect(self):
        # This is just for waiting and displaying the last messeges
        _ = input("\n  Press any key to close . . .")
        self.socket.close()

    def send(self, message):
        message_length = len(message).to_bytes(3, 'little')
        self.socket.send(message_length)
        #print("  message length: ", len(message))
        self.socket.send(message)
        #print("  message: ", message)

    def secure_send(self, message):
        ciphertext = self.aes.encryption(message)
        self.send(ciphertext)

    def receive(self):
        message_length = int.from_bytes(self.socket.recv(3), 'little')
        #print("  message length: ", message_length)
        message = self.socket.recv(message_length)
        #print("  message: ", message)
        return message

    def secure_receive(self):
        ciphertext = self.receive()
        message = self.aes.decryption(ciphertext)
        return message

    def start_session(self):
        ############## Preparations #################
        ### Sending and receiving the public keys ###
        print("  -------------------- SSH --------------------")
        print("  >Exchanging publice values . . .")
        N, e = self.rsa.get_public_key()
        self.send(str(N).encode('utf-8'))
        print("  >Sending your N . . .")
        self.send(str(e).encode('utf-8'))
        print("  >Sending your e . . .")
        print("  >Your public key has been sent.")
        N_bob = int(self.receive().decode('utf-8'))
        print("  >Receiving N of {} . . .".format(self.opponent))
        e_bob = int(self.receive().decode('utf-8'))
        print("  >Receiving e of {} . . .".format(self.opponent))
        print("  >{}'s public key has been received.".format(self.opponent))
        alice = self.username
        self.send(alice.encode('utf-8'))
        print("  >Sending your username . . .")
        bob = self.receive().decode('utf-8')
        print("  >Receiving {}'s username . . .".format(self.opponent))
        print("  >Public values have been received.")
        #############################################
        a = int.from_bytes(get_random_bytes(256), 'little')
        print("\n  >Your a is equal to: {}\n".format(a))
        self.diffie_hellman.set_new_secret_exponent(a)
        Ra = int.from_bytes(get_random_bytes(32), 'little')
        ga = self.diffie_hellman.get_public_value()
        self.perform_step1(Ra, ga)
        K, H, bob_auth = self.perform_step2(alice, bob, Ra, ga, N_bob, e_bob)
        self.diffie_hellman.destroy_exponent()
        Sa = self.generate_signature(H, alice)
        print("  >Authenticating . . .")
        if bob_auth:
            print("  >Congratulations: {} is authenticated successfully." .format(
                self.opponent))
            print("  >Now it is your time, authenticating . . .")
            alice_auth = self.perform_step3(K, Sa, bytes(alice.encode()))
            print(alice_auth)
            if alice_auth:
                print("  >Congratulations: You are now authenticated.")
                print("  >Now you can start communicating with {} securely.\n" .format(
                    self.opponent))
                self.aes.print_key()
                return True
            print("  >Unfortunately, you failed to be authenticated successfully.")
            return False
        print("  >Unfortunately, {} failed to be authenticated successfully." .format(
            self.opponent))
        return False

    def end_session(self):
        self.aes.destroy_key()
        while True:
            new_exchange_alice = input(
                "  >Do you want to play again (y/n)? . . .")
            alice_conf = new_exchange_alice == "y" or new_exchange_alice == "Y"
            alice_rej = new_exchange_alice == "n" or new_exchange_alice == "N"
            if not (alice_conf) and not(alice_rej):
                print("  >Please only enter either (Y/y) or (N/n) . . .")
            else:
                self.send(new_exchange_alice.encode('utf-8'))
                new_exchange_bob = self.receive().decode('utf-8')
                bob_rej = new_exchange_bob == "n" or new_exchange_bob == "N"
                if alice_rej:
                    self.disconnect()
                    return True
                else:
                    if bob_rej:
                        print("  >Unfortunately, {} does not want to play." .format(
                            self.opponent))
                        self.disconnect()
                        return True
                    else:
                        print("  >Starting new session . . .")
                        return False

    ##############################################
    ################## Step (1) ##################
    def perform_step1(self, Ra, ga):
        self.send(str(Ra).encode('utf-8'))
        self.send(str(ga).encode('utf-8'))

    ##############################################
    ################## Step (2) ##################
    def perform_step2(self, alice, bob, Ra, ga, N_bob, e_bob):
        Rb = int(self.receive().decode('utf-8'))
        gb = int(self.receive().decode('utf-8'))
        Sb = int(self.receive().decode('utf-8'))
        K = self.diffie_hellman.get_secret_key(gb)
        H = self.diffie_hellman.generate_H(alice, bob, Ra, Rb, ga, gb, K)
        auth = self.rsa.verify_signature(N_bob, e_bob, Sb, bob, H)
        if auth:
            self.send(str(auth).encode('utf-8'))
        else:
            self.send("".encode('utf-8'))
        return (K, H, auth)

    ##############################################
    ################## Step (3) ##################
    def perform_step3(self, K, Sa, alice_bytes):
        encryptedtext = self.pack_and_encrypt(K, Sa, alice_bytes)
        self.send(b64encode(encryptedtext))
        auth = bool(self.receive().decode('utf-8'))
        return auth

    def set_symmetric_crypto(self, K, bs, Opponent):
        self.aes = AES.Cryptosystem(K, bs, Opponent)

    def set_public_key_crypto(self, p, q, e):
        self.rsa = RSA.Cryptosystem(p, q, e)

    def set_key_exchange(self, g, m):
        self.diffie_hellman = DiffieHellman.KeyExchange(g, m)

    def generate_signature(self, H, user):
        ########## Signing ==> S = [H, user] ############
        M = int.from_bytes((bytes(user.encode()) + H), 'little')
        S = self.rsa.digital_sign(M)
        return S

    def pack_and_encrypt(self, K, Sa, alice):
        self.set_symmetric_crypto(K, 16, self.opponent)
        self.aes.generate_initialization_vector()
        Sa_bytes = Sa.to_bytes(mod_op.getBytesLen(Sa), 'little')
        plaintext = (alice + Sa_bytes)
        cipher = SymCrypto.new(self.aes.key, SymCrypto.MODE_CBC, self.aes.iv)
        ciphertext = self.aes.iv + cipher.encrypt(pad(plaintext, 16))
        return ciphertext
