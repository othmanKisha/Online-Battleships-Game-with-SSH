from Board import Board as game
from SSH_modules import SSHClient as SSH
import math


def main():

    # |HARDCODED| two 355 digits primes for p and q, 2048-bits prime for m and generator 2
    p = 7891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891234567891
    q = 2357111317192329313741434753596167717379838997101103107109113127131137139149151157163167173179181191193197199211223227229233239241251257263269271277281283293307311313317331337347349353359367373379383389397401409419421431433439443449457461463467479487491499503509521523541547557563569571577587593599601607613617619631641643647653659661673677683691701709719
    m = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    e = 91
    g = 2
    name = input("  Please enter your name: ")
    username = input("  Please enter your username: ")
    opponent = input("  please enter your opponent's name: ")
    turn = name
    client = SSH.Client(4321, opponent, username, p, q, e, m, g)
    game_board = game.Board(name)
    game_board.initialize_board()
    game_board.print_welcome_message()
    print("  Connecting to {} . . .".format(opponent))
    client.connect()

    while True:
        if not client.start_session():
            break
        print("  ------------ Secured Connection ------------")
        ships_num = game_board.set_ships_number()
        game_board.insert_ship()
        game_board.print_board("  This is how your ships are placed: ")
        client.secure_send(ships_num)
        oppo_ships = client.secure_receive()
        print("  {} has {} ships placed in the battle." .format(
            opponent, oppo_ships))

        while True:
            if turn != name:
                print("  --------- {}'s turn -------".format(opponent))
                row = client.secure_receive()
                col = client.secure_receive()
                res = game_board.guess_receive(row, col)
                client.secure_send(res)
                turn = name
            else:
                print("  --------- Your turn -------")
                while True:
                    row = input("  Enter your row guess: ")
                    col = input("  Enter your column guess: ")
                    if game_board.is_guess_valid(row, col):
                        break
                client.secure_send(row)
                client.secure_send(col)
                res = client.secure_receive()
                game_board.guess_place(res, row, col)
                turn = opponent

            if game_board.check_score(oppo_ships, turn):
                break
            game_board.print_board("  The current view of the game: ")

        if client.end_session():
            break


if __name__ == '__main__':
    main()
