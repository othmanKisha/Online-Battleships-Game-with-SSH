import socket
from Crypto.Cipher import AES as Symmetric
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
        self.aes = AES.Cryptosystem(K, bs, Opponent)
        self.aes.generate_initialization_vector()
        self.aes.print_key()

    def set_public_key_crypto(self, p, q, e):
        self.rsa = RSA.Cryptosystem(p, q, e)

    def set_key_exchange(self, g, m):
        self.diffie_hellman = DiffieHellman.KeyExchange(g, m)

    def start_session(self):
        # Sending and receiving the public keys ###
        N, e = self.rsa.get_public_key()
        self.send(str(N).encode())
        self.send(str(e).encode())
        N_bob = int(self.receive(4096).decode())
        e_bob = int(self.receive(128).decode())
        alice = self.username
        self.send(alice.encode())
        bob = self.receive(1024).decode()
        Ra, public_a = self.perform_step1()
        K, H, bob_auth = self.perform_step2(
            alice, bob, Ra, public_a, N_bob, e_bob)
        self.send(str(bob_auth).encode())
        if bob_auth:
            self.diffie_hellman.destroy_exponent()
            alice_auth = self.perform_step3(alice, H, K)
            if alice_auth:
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
                self.send(new_exchange_alice.encode())
                new_exchange_bob = self.receive(1024).decode()
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
    def perform_step1(self):
        Ra = int.from_bytes(get_random_bytes(32), 'little')
        a = int.from_bytes(get_random_bytes(256), 'little')
        print("\n  >Your a is equal to: {}\n".format(a))
        self.diffie_hellman.set_new_secret_exponent(a)
        public_a = self.diffie_hellman.get_public_value()
        self.send(str(Ra).encode())
        self.send(str(public_a).encode())
        return (Ra, public_a)

    ##############################################
    ################## Step (2) ##################
    def perform_step2(self, alice, bob, Ra, public_a, N_bob, e_bob):
        Rb = int(self.receive(256).decode())
        public_b = int(self.receive(2048).decode())
        Sb = int(self.receive(4096).decode())
        K = self.diffie_hellman.get_secret_key(public_b)
        H = self.diffie_hellman.generate_H(
            alice, bob, Ra, Rb, public_a, public_b, K)
        print("  >Authenticating . . .")
        authenticated = self.rsa.verify_signature(N_bob, e_bob, Sb, bob, H)
        if authenticated:
            print("  >Congratulation: {} is authenticated successfully." .format(
                self.opponent))
            print("  >Now it is your time, authenticating . . .")
        return (K, H, authenticated)

    ##############################################
    ################## Step (3) ##################
    def perform_step3(self, alice, H, K):
        self.set_symmetric_crypto(K, 16, self.opponent)
        M = bytes(alice.encode()) + H
        Sa = self.rsa.digital_sign(int.from_bytes(M, 'little'))
        Sa_len = mod_op.getBytesLen(Sa)
        cipher = Symmetric.new(self.aes.key, Symmetric.MODE_CBC, self.aes.iv)
        C = self.aes.iv + \
            cipher.encrypt(pad(bytes(alice.encode()) +
                               (Sa.to_bytes(Sa_len, 'little')), 16))
        self.send(b64encode(C))
        authenticated = bool(self.receive(1024).decode())
        if authenticated:
            print("  >Congratulations: You are now authenticated.")
            print("  >Now you can start communicating with {} securely." .format(
                self.opponent))
        return authenticated
