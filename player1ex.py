from Board import Board
from SSHClient import SSHClient


def main():

    turn = "Alice"
    client = SSHClient(4321, "Bob")
    game_board = Board("Alice")
    game_board.initialize_board()
    game_board.print_welcome_message()
    print("  Connecting to Bob . . .")
    client.connect()

    while True:
        if not(client.start_session()):
            break
        ships_num = game_board.set_ships_number()
        game_board.insert_ship()
        game_board.print_board("  This is how your ships are placed: ")
        client.secure_send(ships_num)
        oppo_ships = client.secure_receive(128)
        print("  Bob have {} ships placed in the battle." .format(oppo_ships))

        while True:
            if turn != "Alice":
                print("--------- Bob's turn -------")
                row = client.secure_receive(128)
                col = client.secure_receive(128)
                res = game_board.guess_receive(row, col)
                client.secure_send(res)
                turn = "Alice"
            else:
                print("--------- Your turn -------")
                while True:
                    row = input("  Enter your row guess: ")
                    col = input("  Enter your column guess: ")
                    if game_board.is_guess_valid(row, col):
                        break
                client.secure_send(row)
                client.secure_send(col)
                res = client.secure_receive(128)
                game_board.guess_place(res, row, col)
                turn = "Bob"

            if game_board.check_score(oppo_ships, turn):
                break
            game_board.print_board("  The current view of the game: ")

        if client.end_session():
            break


if __name__ == '__main__':
    main()
