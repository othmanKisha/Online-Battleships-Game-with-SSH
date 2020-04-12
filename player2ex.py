from Board import Board
from SSHServer import SSHServer


def main():

    turn = "Alice"
    server = SSHServer(4321, "Alice")
    game_board = Board("Bob")
    game_board.initialize_board()
    game_board.print_welcome_message()
    print("  Connecting to Alice . . .")
    server.bind()

    while True:
        if not(server.start_session()):
            break
        ships_num = game_board.set_ships_number()
        game_board.insert_ship()
        game_board.print_board("  This is how your ships are placed: ")
        oppo_ships = server.secure_receive(128)
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
                res = server.secure_receive(128).decode('utf-8')
                game_board.guess_place(res, row, col)
                turn = "Alice"
            else:
                print("--------- Alice's turn -------")
                row = server.secure_receive(128)
                col = server.secure_receive(128)
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
