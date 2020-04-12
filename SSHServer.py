import socket
from base64 import b64decode
from Crypto.Random import get_random_bytes
from AESCryptosystem import Cryptosystem as AESCrypto
from RSACryptosystem import Cryptosystem as RSACrypto
from DiffieHellmanKeyEx import KeyExchange as DiffieHellman

###########################################################################################
########################### Phase 3: SSH Protocol Server ##################################
###########################################################################################


class SSHServer (object):

    def __init__(self, port, opponent):
        self.port = port
        self.opponent = opponent
        self.conn_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ip = socket.gethostbyname(socket.gethostname())   # Bob's id
        # Should be modified later
        self.set_key_exchange(0, 0)
        # Should be modified later
        self.set_public_key_crypto(0, 0, 0)

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
        self.aes = AESCrypto(K, bs, Opponent)
        self.aes.set_initialization_vector(iv)
        self.aes.print_key()

    def set_public_key_crypto(self, p, q, e):
        self.rsa = RSACrypto(p, q, e)

    def set_key_exchange(self, g, m):
        self.diffie_hellman = DiffieHellman(g, m)

    def start_session(self):
        ### Sending and receiving the public keys ###
        N, e = self.rsa.get_public_key()
        self.send(N)
        self.send(e)
        # Should be modified later
        N_alice = self.receive(0)
        # Should be modified later
        e_alice = self.receive(0)
        Ra, public_a, Rb, public_b = self.perform_step1()
        K, H = self.perform_step2(
            self.alice, self.ip, Ra, Rb, public_a, public_b)
        # Should be modified later
        # To make sure for Bob that he is authenticated
        bob_auth = self.receive(0)
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
                # Should be modified later
                new_exchange_alice = self.receive(0)
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
        # Should be modified later
        Ra = self.receive(0)
        # Should be modified later
        public_a = self.receive(0)
        Rb = get_random_bytes(32)
        self.diffie_hellman.set_new_secret_exponent(get_random_bytes(256))
        public_b = self.diffie_hellman.get_public_value()
        return Ra, public_a, Rb, public_b

    ##############################################
    ################## Step (2) ##################
    def perform_step2(self, alice, bob, Ra, Rb, public_a, public_b):
        K = self.diffie_hellman.get_secret_key(public_a)
        H = self.diffie_hellman.generate_H(
            alice, bob, Ra, Rb, public_a, public_b, K)
        # Should be modified later
        Sb = self.rsa.digital_sign((H, bob))
        self.send(Rb)
        self.send(public_b)
        self.send(Sb)
        print("  Authenticating . . .")
        self.diffie_hellman.destroy_exponent()
        return K, H

    ##############################################
    ################## Step (3) ##################
    def perform_step3(self, alice, H, K, N_alice, e_alice):
        # Should be modified later
        M = self.receive(0)
        c = b64decode(M)
        iv = c[:16]
        self.set_symmetric_crypto(K, 16, self.opponent, iv)
        M = self.aes.decryption(M)
        # Should be modified later
        Sa = (M - alice)
        authenticated = self.rsa.verify_signature(
            N_alice, e_alice, Sa, alice, H)
        if authenticated:
            print("  Congratulations: {} is authenticated successfully." .format(
                self.opponent))
            print("  Now you can start communicating with {} securely." .format(
                self.opponent))
        self.send(authenticated)
        return authenticated
