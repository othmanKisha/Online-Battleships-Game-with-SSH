import socket
from Board import Board
from base64 import b64decode
from SSHServer import SSHServer
from AESCryptosystem import Cryptosystem as AESCrypto
from RSACryptosystem import Cryptosystem as RSACrypto
from DiffieHellmanKeyEx import KeyExchange as DiffieHellman
#from DiffieHellmanKeyEx import repeated_squaring, Mod

def main():
    
    #IV is going to be received from the client always
    aes = AESCrypto("201675760", 16, "Alice")
    aes.print_key()                                             #Printing the hashed key
    turn = "Alice"                                              #If turn = 1, player 1 play, if it is 2 then player 2 play
    game_board = Board("Bob")
    game_board.initialize_board()

    print("  Welcome To Online battleships game designed by Othman Kisha")
    print("----------------------------- Hello Bob ------------------------------")
    print("  First Enter the number of your ships and then place them in the game board, ")
    print("  After that you will be connected with player 1 and start the game.")
    print("  PLease Note that the board is 6x6 matrix, enter the index from 0 to 5 only. \n")
    
    shipsNum = input("  Please enter the number of ships: ")
    print("  Please place your ships (Your ships must be of one unit only) by inserting the index. ")
    game_board.insert_ship(shipsNum)
    game_board.print_board("  This is how your ships are placed: ") 

    print("  Connecting to player 1 . . . . .")
    playerTwoSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    port = 6594
    
    playerTwoSocket.bind(("", port))
    playerTwoSocket.listen(5)                                   #waiting to connect to the client(player 1)
    playerOneSocket, _ = playerTwoSocket.accept()               #accepting the connection
    clientIP = playerOneSocket.getsockname()[0]                 #This will contain the ip address of the client(here it is the same because the programs run on the same pc)
    
    print("  Congartulations: you are connect, now you can start the game. ")
    print("  IP address of your opponent: {}" .format(clientIP))
    game_board.print_board("  Your current view of the field:  ") 

    DoppoShips = playerOneSocket.recv(128)                      #Receiving the number of ships of the oponent 
    aes.set_initialization_vector(b64decode(DoppoShips)[:16] )  #iv is the first 16 bytes

    oppoShips = aes.decryption(DoppoShips)
    EshipsNum = aes.encryption(shipsNum)
    playerOneSocket.send(EshipsNum)                             #Sending the number of ships to the opponent
    print("  Your opponent have {} ships placed in the battle." .format(oppoShips.decode('utf-8')))

    while True:
        if turn == "Bob":
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
            turn = "Alice"                                            #Turn is changed to player 2
        
        else:
            print("--------- Alice's turn -------")
            Drow = playerOneSocket.recv(128)                        #The (decrypted 128-bits) guessed row by bob
            row = aes.decryption(Drow)                              #Decrypting the row number
            Dcol = playerOneSocket.recv(128)                        #The (decrypted 128-bits) guessed column by bob
            col = aes.decryption(Dcol)                              #Decrypting the column number

            res = game_board.guess_receive(row, col)        
            Eres = aes.encryption(res)                              #Encrypting the response
            playerOneSocket.send(Eres)                              #The (Encrypted) response will be sent to the opponent   
            turn = "Bob"                                            #Turn is changed to you

        if game_board.check_score(shipsNum, oppoShips, turn):
            break

        game_board.print_board("  The current view of the game: ")          

    #This is just for waiting and displaying the last messeges
    _ = input("\n  Press any key to close . . .")
    playerOneSocket.close()                                     #End the game 

if __name__ == '__main__':
    main()    
    