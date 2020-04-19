import socket
from base64 import b64decode
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

    def bind(self):
        self.conn_socket.bind(("", self.port))
        # waiting to connect to the client(player 1)
        self.conn_socket.listen(5)
        # accepting the connection, self.alice is unique id for alice
        self.socket, self.alice = self.conn_socket.accept()

        print("  Congartulations: you are connect, now you can start the game. ")
        print("  IP address of {}: {}" .format(self.opponent, self.alice))

    def disconnect(self):
        # This is just for waiting and displaying the last messeges
        _ = input("\n  Press any key to close . . .")
        self.socket.close()

    def send(self, message):
        self.socket.send(message)

    def secure_send(self, message):
        ciphertext = self.aes.encryption(message)
        self.send(ciphertext)

    def receive(self, size):
        received_msg = self.socket.recv(size)
        return received_msg

    def secure_receive(self, size):
        ciphertext = self.receive(size)
        received_msg = self.aes.decryption(ciphertext)
        return received_msg

    def set_symmetric_crypto(self, K, bs, Opponent, iv):
        self.aes = AES.Cryptosystem(K, bs, Opponent)
        self.aes.set_initialization_vector(iv)
        self.aes.print_key()

    def set_public_key_crypto(self, p, q, e):
        self.rsa = RSA.Cryptosystem(p, q, e)

    def set_key_exchange(self, g, m):
        self.diffie_hellman = DiffieHellman.KeyExchange(g, m)

    def start_session(self):
        ### Sending and receiving the public keys ###
        N, e = self.rsa.get_public_key()
        N_alice = self.receive(4096)
        e_alice = self.receive(128)
        self.send(N)
        self.send(e)
        alice = self.receive(128).decode()
        bob = self.username
        self.send(bob.encode())
        Ra, public_a, Rb, public_b = self.perform_step1()
        K, H = self.perform_step2(
            alice, bob, Ra, Rb, public_a, public_b)
        # To make sure for Bob that he is authenticated
        bob_auth = self.receive(128)
        if bob_auth:
            print("  Congratulations: you are now authenticated successfully.")
            print("  Now it is {}'s time, authenticating . . ." .format(self.opponent))
            alice_auth = self.perform_step3(self.alice, H, K, N_alice, e_alice)
            if alice_auth:
                return True
            print("  Unfortunately, {} failed to be authenticated successfully." .format(
                self.opponent))
            return False
        print("  Unfortunately, you failed to be authenticated successfully.")
        return False

    def end_session(self):
        self.aes.destroy_key()
        while True:
            new_exchange_bob = input(
                "  Do you want to play again (y/n)? . . .")
            bob_conf = new_exchange_bob == "y" or new_exchange_bob == "Y"
            bob_rej = new_exchange_bob == "n" or new_exchange_bob == "N"
            if not (bob_conf) and not(bob_rej):
                print("  Please only enter either (Y/y) or (N/n) . . .")
            else:
                new_exchange_alice = self.receive(128)
                self.send(new_exchange_bob)
                alice_rej = new_exchange_alice == "n" or new_exchange_alice == "N"
                if bob_rej:
                    self.disconnect()
                    return True
                else:
                    if alice_rej:
                        print("  Unfortunately, {} does not want to play." .format(
                            self.opponent))
                        self.disconnect()
                        return True
                    else:
                        print("  Starting new session . . .")
                        return False

    ##############################################
    ################## Step (1) ##################
    def perform_step1(self):
        Ra = self.receive(256)
        public_a = self.receive(2048)
        Rb = get_random_bytes(32)
        b = get_random_bytes(256)
        print("  Your b is equal to: {}".format(b))
        self.diffie_hellman.set_new_secret_exponent(b)
        public_b = self.diffie_hellman.get_public_value()
        return Ra, public_a, Rb, public_b

    ##############################################
    ################## Step (2) ##################
    def perform_step2(self, alice, bob, Ra, Rb, public_a, public_b):
        K = self.diffie_hellman.get_secret_key(public_a)
        H = self.diffie_hellman.generate_H(
            alice, bob, Ra, Rb, public_a, public_b, K)
        M = bytes(bob.encode()) + H
        Sb = self.rsa.digital_sign(int.from_bytes(M, 'little'))
        self.send(Rb)
        self.send(public_b)
        self.send(Sb)
        print("  Authenticating . . .")
        self.diffie_hellman.destroy_exponent()
        return K, H

    ##############################################
    ################## Step (3) ##################
    def perform_step3(self, alice, H, K, N_alice, e_alice):
        M = self.receive(128)
        c = b64decode(M)
        iv = c[:16]
        self.set_symmetric_crypto(K, 16, self.opponent, iv)
        M = self.aes.decryption(M)
        alice_len = len(bytes(alice.encode()))
        Sa_bytes = M.to_bytes(mod_op.getBytesLen(M), 'little')[alice_len:]
        Sa = int.from_bytes(Sa_bytes, 'little')
        authenticated = self.rsa.verify_signature(
            N_alice, e_alice, Sa, alice, H)
        if authenticated:
            print("  Congratulations: {} is authenticated successfully." .format(
                self.opponent))
            print("  Now you can start communicating with {} securely." .format(
                self.opponent))
        self.send(authenticated)
        return authenticated
