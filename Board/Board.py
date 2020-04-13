########################################################################################
########################### Phase 1: BattleShips Game ##################################
########################################################################################


class Board (object):

    def __init__(self, player):
        self.player = player
        self.board = []
        self.result = {
            'boomed': 0,
            'hit': 0,
            'remaining': 4,
            'response': "",
            'status': True
        }

    # initializing the board
    def initialize_board(self):
        for _ in range(6):
            self.board.append([" "] * 6)

    def print_welcome_message(self):
        print("  Welcome To Online battleships game designed by Othman Kisha")
        print("----------------------------- Hello {} ------------------------------" .format(self.player))
        print("  First you will have a SSH connection with Bob, authenticated and then start the game, ")
        print("  After that enter the number of your ships and then place them in the game board.")
        print("  PLease Note that the board is 6x6 matrix, enter the index from 0 to 5 only. \n")

    def set_ships_number(self):
        while True:
            self.ships_num = input("  Please enter the number of ships: ")
            if int(self.ships_num) <= 0:
                print("  Wrong number of ships, please insert a proper number of ships.")
                pass
            break
        return self.ships_num

    def get_cell(self, row, col):
        Row = int(row)
        Col = int(col)
        return self.board[Row][Col]

    # The player will place his ships in the game board
    def insert_ship(self):
        print("  Please place your ships (Your ships must be of one unit only) by inserting the index. ")
        for _ in range(int(self.ships_num)):
            while True:
                row = input("  Please enter the row number: ")
                if int(row) >= 6 or int(row) < 0:
                    print("  Please re-enter the row number, it should be between 0-5.")
                    pass
                col = input("  Please enter the column number: ")
                if int(col) >= 6 or int(col) < 0:
                    print(
                        "  Please re-enter the column number, it should be between 0-5.")
                    pass

                if self.board[int(row)][int(col)] == "S":
                    print("  You have already placed a ship here, please try again.")
                    self.result['status'] = False
                else:
                    self.board[int(row)][int(col)] = "S"
                    print("  Ship has been successfully placed. ")
                    self.result['status'] = True

                if self.result['status']:
                    break

    def is_guess_valid(self, row, col):
        Row = int(row)
        Col = int(col)

        if self.board[Row][Col] == "S":
            print(
                "  You have already placed your ship here, please re-enter a suitable guess. \n")
            return False
        elif self.board[Row][Col] == "X" or self.board[Row][Col] == "L" or self.board[Row][Col] == "V":
            print("  This place is already attacked, please re-enter a valid guess. \n")
            return False
        else:
            return True

    def guess_place(self, res, row, col):
        Row = int(row)
        Col = int(col)

        if res == "Hit":  # If the response is that the guess is correct
            self.board[Row][Col] = "V"
            print("  Yes!!! one ship has been successfully attacked. ")
            self.result['hit'] += 1
        else:  # If the response is that the guess is wrong
            self.board[Row][Col] = "X"
            self.result['remaining'] -= 1  # Decrement the remaining chances
            print("  Wrong guess, you missed the ships.\n  You have {} chances remaining."  .format(
                str(self.result['remaining'])))

    def guess_receive(self, row, col):
        Row = int(row)
        Col = int(col)
        cell = self.board[Row][Col]

        if cell == "S":  # If the guess is correct
            self.board[Row][Col] = "L"
            self.result['boomed'] += 1
            print("  OPS!! One Ship has been attacked. ")
            self.result['response'] = "Hit"
        else:  # If it is a new index and it is wrong
            self.board[Row][Col] = "X"
            print("  Fortunately, your ships are safe. ")
            self.result['response'] = "Miss"

        return self.result['response']

    # This method is for printing the board
    def print_board(self, message):
        print(message)
        print("    __ __ __ __ __ __")
        for row in self.board:
            print("  ", (" |").join(row), "|")
            print("    __ __ __ __ __ __")
        print("")

    def check_score(self, oppo_ships, turn):
        # You will lose if all of your ships are boomed
        if self.result['boomed'] == int(self.ships_num):
            print("  You lost.")
            self.result['status'] = True
        # You will win if all of your opponent's ships are hit
        elif self.result['hit'] == int(oppo_ships):
            print("  Congratulations, You Won.")
            self.result['status'] = True
        # You have only 4 chances of missing ships
        elif self.result['remaining'] == 0 and turn == self.player:
            print("  You have reached the maximum number of trials, Game Over . . . .")
            self.result['status'] = True
        else:
            self.result['status'] = False

        return self.result['status']
