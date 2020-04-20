from Board import Board as game
from SSH_modules import SSHServer as SSH
import math


def main():

    turn = "Alice"
    # |HARDCODED| two 370 digits primes for p and q, 2048-bits prime for m and generator 2
    p = 2455909081919070671056560522967800006666849057058423323928051220835074218066504353672673338146773787416578529354512733449164913935665750853408322014625220816720173609185638647418282634104183956379916028789643301746208389463575127027767809505105089977924522503431696858493692537999611406559310284962669871090920211165881116217037908164705886278634169486222360237657432361
    q = 3357919051293446684817338475525336738410860683671992917156014373893439459981205349461903840857391256114552436727030705242812636090289386090253261128312388690032525006703900566545832881453504420702454161952515801782756924440723510485553617697701860843302292487377415029400870876382968571950877132931544109243793366659520676094343242287408182490885436245732490266782865577
    m = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    e = 51
    g = 2
    #username = input("  Please enter your username: ")
    server = SSH.Server(4321, "Alice", "username", p, q, e, m, g)
    game_board = game.Board("Bob")
    game_board.initialize_board()
    game_board.print_welcome_message()
    print("  Connecting to Alice . . .")
    server.bind()

    while True:
        if not server.start_session():
            break
        print("  ------------ Secured Connection ------------")
        ships_num = game_board.set_ships_number()
        game_board.insert_ship()
        game_board.print_board("  This is how your ships are placed: ")
        oppo_ships = server.secure_receive()
        server.secure_send(ships_num)
        print("  Your opponent have {} ships placed in the battle." .format(oppo_ships))

        while True:
            if turn == "Bob":
                print("--------- Your turn -------")
                while True:
                    row = input("  Enter your row guess: ")
                    col = input("  Enter your column guess: ")
                    if game_board.is_guess_valid(row, col):
                        break
                server.secure_send(row)
                server.secure_send(col)
                res = server.secure_receive().decode('utf-8')
                game_board.guess_place(res, row, col)
                turn = "Alice"
            else:
                print("--------- Alice's turn -------")
                row = server.secure_receive()
                col = server.secure_receive()
                res = game_board.guess_receive(row, col)
                server.secure_send(res)
                turn = "Bob"

            if game_board.check_score(oppo_ships, turn):
                break
            game_board.print_board("  The current view of the game: ")

        if server.end_session():
            break


if __name__ == '__main__':
    main()
