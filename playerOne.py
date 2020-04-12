import socket
from Board import Board
from SSHClient import SSHClient
from AESCryptosystem import Cryptosystem as AESCrypto
from RSACryptosystem import Cryptosystem as RSACrypto
from DiffieHellmanKeyEx import KeyExchange as DiffieHellman
#from DiffieHellmanKeyEx import repeated_squaring, Mod

def main():

    aes = AESCrypto("201675760", 16, "Bob")
    aes.print_key()                                             #Printing the hashed key
    aes.generate_initialization_vector()                        #Securely random number generated for the IV
    turn = "Alice"                                              #If turn = alice, alice play, if it is bob then bob play
    game_board = Board("Alice")                                 #This will contain the board displayed for both players
    game_board.initialize_board()

    print("  Welcome To Online battleships game designed by Othman Kisha")
    print("----------------------------- Hello Alice ------------------------------")
    print("  First Enter the number of your ships and then place them in the game board, ")
    print("  After that you will be connected with player 2 and start the game.")
    print("  PLease Note that the board is 6x6 matrix, enter the index from 0 to 5 only. \n")
    
    shipsNum = input("  Please enter the number of ships: ")
    print("  Please place your ships (Your ships must be of one unit only) by inserting the index. ")
    game_board.insert_ship(shipsNum)
    game_board.print_board("  This is how your ships are placed: ") 

    print("  Connecting to player 2 . . . . .")
    playerOneSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    hostIP = socket.gethostbyname(socket.gethostname())         #because the test will be using the same pc, i used the localhost ip
    port = 6594
    connect = False

    #This is to wait untill connected to player 2(server)
    while not connect:
        try:
            playerOneSocket.connect((hostIP, port))
            connect = True
        except Exception as _:
            pass  

    print("  Congartulations: you are connect, now you can start the game. ")
    print("  IP address of your opponent: {}" .format(hostIP))
    game_board.print_board("  Your current view of the field:  ")

    EshipsNum = aes.encryption(shipsNum)    
    playerOneSocket.send(EshipsNum)                             #Sending the encrypted number of ships to the opponent
    DoppoShips = playerOneSocket.recv(128)                      #Receiving the encrypted (128-bits) number of ships of the oponent
    oppoShips = aes.decryption(DoppoShips)                      #Decrypting the encrypted number of ships of the opponent
    print("  Your opponent have {} ships placed in the battle." .format(oppoShips.decode('utf-8')))

    while True:
        if turn != "Alice":
            print("--------- Bob's turn -------")
            Drow = playerOneSocket.recv(128)                        #The (decrypted 128-bits) guessed row by bob
            row = aes.decryption(Drow)                              #Decrypting the row number
            Dcol = playerOneSocket.recv(128)                        #The (decrypted 128-bits) guessed column by bob
            col = aes.decryption(Dcol)                              #Decrypting the column number

            res = game_board.guess_receive(row, col)  
            Eres = aes.encryption(res)                              #Encrypting the response
            playerOneSocket.send(Eres)                              #The (Encrypted) response will be sent to the opponent   
            turn = "Alice"                                          #Turn is changed to you

        else:
            print("--------- Your turn -------")
            while True:
                row = input("  Enter your row guess: ")             #The guessed row by you    
                col = input("  Enter your column guess: ")          #The guessed column by you
                if game_board.is_guess_valid(row, col):
                    break     
                
            Erow = aes.encryption(row)
            playerOneSocket.send(Erow)
            Ecol = aes.encryption(col)
            playerOneSocket.send(Ecol)
            Dres = playerOneSocket.recv(128)                        #The (Encrypted) response received from the opponent
            res = aes.decryption(Dres).decode('utf-8')
            
            game_board.guess_place(res, row, col)
            turn = "Bob"                                            #Turn is changed to player 2
        
        if game_board.check_score(shipsNum, oppoShips, turn):
            break

        game_board.print_board("  The current view of the game: ")

    #This is just for waiting and displaying the last messeges
    _ = input("\n  Press any key to close . . .")
    playerOneSocket.close()                                     #End the game

if __name__ == '__main__':
    main()
