import socket
from Crypto.Cipher import AES as SymCrypto
from Crypto.Util.Padding import unpad
from base64 import b64encode, b64decode
from Crypto.Random import get_random_bytes
from . import AESCryptosystem as AES
from . import RSACryptosystem as RSA
from . import DiffieHellmanKeyEx as DiffieHellman
from . import ModArithmetic as mod_op

###########################################################################################
########################### Phase 3: SSH Protocol Server ##################################
###########################################################################################


class Server (object):

    def __init__(self, port, opponent, username, p, q, e, m, g):
        self.port = port
        self.opponent = opponent
        self.conn_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ip = socket.gethostbyname(socket.gethostname())
        self.username = username
        self.set_key_exchange(g, m)
        self.set_public_key_crypto(p, q, e)
        # This line is for testing the case when trudy tries to communicate as alice
        # self.rsa.manipulate_private_key(1234)

    def bind(self):
        try:
            self.conn_socket.bind(("", self.port))
            # waiting to connect to the client(player 1)
            self.conn_socket.listen(5)
            # accepting the connection, self.alice is unique id for alice
            self.socket, self.alice = self.conn_socket.accept()
        except Exception as e:
            print("  error: ", e)
        print("  Congartulations: you are connect, now you can start the game. ")
        print("  IP address of {}: {}" .format(self.opponent, self.alice[0]))

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
        N_alice = int(self.receive().decode('utf-8'))
        print("  >Receiving N of {} . . .".format(self.opponent))
        e_alice = int(self.receive().decode('utf-8'))
        print("  >Receiving e of {} . . .".format(self.opponent))
        print("  >{}'s public key has been received.".format(self.opponent))
        self.send(str(N).encode('utf-8'))
        print("  >Sending your N . . .")
        self.send(str(e).encode('utf-8'))
        print("  >Sending your e . . .")
        print("  >Your public key has been sent.")
        bob = self.username
        alice = self.receive().decode('utf-8')
        print("  >Receiving {}'s username . . .".format(self.opponent))
        self.send(bob.encode('utf-8'))
        print("  >Sending your username . . .")
        print("  >Public values have been received.")
        #############################################
        b = int.from_bytes(get_random_bytes(256), 'little')
        print("\n  >Your b is equal to: {}\n".format(b))
        self.diffie_hellman.set_new_secret_exponent(b)
        Rb = int.from_bytes(get_random_bytes(32), 'little')
        gb = self.diffie_hellman.get_public_value()
        Ra, ga = self.perform_step1()
        K = self.diffie_hellman.get_secret_key(ga)
        H = self.diffie_hellman.generate_H(alice, bob, Ra, Rb, ga, gb, K)
        Sb = self.generate_signature(H, bob)
        print("  >Authenticating . . .")
        bob_auth = self.perform_step2(Sb, Rb, gb)
        self.diffie_hellman.destroy_exponent()
        if bob_auth:
            print("  >Congratulations: you are now authenticated successfully.")
            print("  >Now it is {}'s time, authenticating . . ." .format(self.opponent))
            alice_auth = self.perform_step3(K, N_alice, e_alice, alice, H)
            if alice_auth:
                print("  >Congratulations: {} is authenticated successfully." .format(
                    self.opponent))
                print("  >Now you can start communicating with {} securely.\n" .format(
                    self.opponent))
                self.aes.print_key()
                return True
            print("  >Unfortunately, {} failed to be authenticated successfully." .format(
                self.opponent))
            return False
        print("  >Unfortunately, you failed to be authenticated successfully.")
        return False

    def end_session(self):
        self.aes.destroy_key()
        while True:
            new_exchange_bob = input(
                "  >Do you want to play again (y/n)? . . .")
            bob_conf = new_exchange_bob == "y" or new_exchange_bob == "Y"
            bob_rej = new_exchange_bob == "n" or new_exchange_bob == "N"
            if not (bob_conf) and not(bob_rej):
                print("  >Please only enter either (Y/y) or (N/n) . . .")
            else:
                new_exchange_alice = self.receive().decode('utf-8')
                self.send(new_exchange_bob.encode('utf-8'))
                alice_rej = new_exchange_alice == "n" or new_exchange_alice == "N"
                if bob_rej:
                    self.disconnect()
                    return True
                else:
                    if alice_rej:
                        print("  >Unfortunately, {} does not want to play." .format(
                            self.opponent))
                        self.disconnect()
                        return True
                    else:
                        print("  >Starting new session . . .")
                        return False

    ##############################################
    ################## Step (1) ##################
    def perform_step1(self):
        Ra = int(self.receive().decode('utf-8'))
        ga = int(self.receive().decode('utf-8'))
        return (Ra, ga)

    ##############################################
    ################## Step (2) ##################
    def perform_step2(self, Sb, Rb, gb):
        ### Sending Sb, Rb, and public value of Bob ####
        self.send(str(Rb).encode('utf-8'))
        self.send(str(gb).encode('utf-8'))
        self.send(str(Sb).encode('utf-8'))
        auth = bool(self.receive().decode('utf-8'))
        return auth

    ##############################################
    ################## Step (3) ##################
    def perform_step3(self, K, N_alice, e_alice, alice, H):
        encryptedtext = b64decode(self.receive())
        Sa = self.decrypt_and_extract(K, encryptedtext, alice)
        auth = self.rsa.verify_signature(N_alice, e_alice, Sa, alice, H)
        if auth:
            self.send(str(auth).encode('utf-8'))
        else:
            self.send("".encode('utf-8'))
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

    def decrypt_and_extract(self, K, ciphertext, alice):
        iv = ciphertext[:16]
        self.set_symmetric_crypto(K, 16, self.opponent)
        self.aes.set_initialization_vector(iv)
        cipher = SymCrypto.new(self.aes.key, SymCrypto.MODE_CBC, iv)
        M = unpad(cipher.decrypt(ciphertext[self.aes.bs:]), self.aes.bs)
        a_len = len(bytes(alice.encode()))
        S_bytes = M[a_len:]
        S = int.from_bytes(S_bytes, 'little')
        return S
