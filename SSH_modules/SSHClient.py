import socket
from Crypto.Random import get_random_bytes
from AESCryptosystem import Cryptosystem as AESCrypto
from RSACryptosystem import Cryptosystem as RSACrypto
from DiffieHellmanKeyEx import KeyExchange as DiffieHellman

###########################################################################################
########################### Phase 3: SSH Protocol Client ##################################
###########################################################################################


class Client (object):

    def __init__(self, port, opponent, p, q, e, m, g):
        self.port = port
        self.opponent = opponent
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.ip = socket.gethostbyname(socket.gethostname())    # Unique id
        self.set_key_exchange(g, m)
        self.set_public_key_crypto(p, q, e)

    def connect(self):
        connect = False
        # This is to wait untill connected to player 2(server)
        while not connect:
            try:
                # Here because we are connecting to the same machine, both will have the same ip
                self.socket.connect((self.ip, self.port))
                connect = True
            except Exception as _:
                pass
        print("  Congartulations: you are connect, now you can start the game. ")
        print("  IP address of {}: {}" .format(self.opponent, self.ip))

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

    def set_symmetric_crypto(self, K, bs, Opponent):
        self.aes = AESCrypto(K, bs, Opponent)
        self.aes.generate_initialization_vector()
        self.aes.print_key()

    def set_public_key_crypto(self, p, q, e):
        self.rsa = RSACrypto(p, q, e)

    def set_key_exchange(self, g, m):
        self.diffie_hellman = DiffieHellman(g, m)

    def start_session(self):
        # Sending and receiving the public keys ###
        N_bob = self.receive(4096)
        e_bob = self.receive(128)
        N, e = self.rsa.get_public_key()
        self.send(N)
        self.send(e)
        alice = self.ip                             # Unique id for Alice
        bob = self.ip                               # Unique id for Bob
        Ra, public_a = self.perform_step1()
        K, H, bob_auth = self.perform_step2(
            alice, bob, Ra, public_a, N_bob, e_bob)
        # To make sure for Bob that he is authenticated
        self.send(bob_auth)
        if bob_auth:
            self.diffie_hellman.destroy_exponent()
            alice_auth = self.perform_step3(alice, H, K)
            if alice_auth:
                return True
            print("  Unfortunately, you failed to be authenticated successfully.")
            return False
        print("  Unfortunately, {} failed to be authenticated successfully." .format(
            self.opponent))
        return False

    def end_session(self):
        self.aes.destroy_key()
        while True:
            new_exchange_alice = input(
                "  Do you want to play again (y/n)? . . .")
            alice_conf = new_exchange_alice == "y" or new_exchange_alice == "Y"
            alice_rej = new_exchange_alice == "n" or new_exchange_alice == "N"
            if not (alice_conf) and not(alice_rej):
                print("  Please only enter either (Y/y) or (N/n) . . .")
            else:
                self.send(new_exchange_alice)
                new_exchange_bob = self.receive(128)
                bob_rej = new_exchange_bob == "n" or new_exchange_bob == "N"
                if alice_rej:
                    self.disconnect()
                    return True
                else:
                    if bob_rej:
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
        Ra = get_random_bytes(32)
        self.diffie_hellman.set_new_secret_exponent(get_random_bytes(256))
        public_a = self.diffie_hellman.get_public_value()
        self.send(Ra)
        self.send(public_a)
        return Ra, public_a

    ##############################################
    ################## Step (2) ##################
    def perform_step2(self, alice, bob, Ra, public_a, N_bob, e_bob):
        Rb = self.receive(256)
        public_b = self.receive(2048)
        Sb = self.receive(4096)
        K = self.diffie_hellman.get_secret_key(public_b)
        H = self.diffie_hellman.generate_H(
            alice, bob, Ra, Rb, public_a, public_b, K)
        print("  Authenticating . . .")
        authenticated = self.rsa.verify_signature(N_bob, e_bob, Sb, bob, H)
        if authenticated:
            print("  Congratulation: {} is authenticated successfully." .format(
                self.opponent))
            print("  Now it is your time, authenticating . . .")
        return K, H, authenticated

    ##############################################
    ################## Step (3) ##################
    def perform_step3(self, alice, H, K):
        # Should be modified later
        Sa = self.rsa.digital_sign((H, alice))
        self.set_symmetric_crypto(K, 16, self.opponent)
        # Should be modified later
        self.secure_send((alice, Sa))
        authenticated = self.receive(128)
        if authenticated:
            print("  Congratulations: You are now authenticated.")
            print("  Now you can start communicating with {} securely." .format(
                self.opponent))
        return authenticated
