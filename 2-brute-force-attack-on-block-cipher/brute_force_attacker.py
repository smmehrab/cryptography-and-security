
# ************************************************
# username  :   smmehrab
# fullname  :   s.m.mehrabul islam
# email     :   smmehrabul-2017614964@cs.du.ac.bd
# institute :   university of dhaka, bangladesh
# reg       :   2017614964
# ************************************************

import sys
from key_checker import KeyChecker

########################################

# CHARNUM_BRUTE_FORCE_ITERATIONS = 1153
# CHARNUM_BRUTE_FORCE_FIRST_LETTER = 18
# CHARNUM_BRUTE_FORCE_SECOND_LETTER = 19

# ASCII_BRUTE_FORCE_ITERATIONS = 14836
# ASCII_BRUTE_FORCE_FIRST_LETTER = 115
# ASCII_BRUTE_FORCE_SECOND_LETTER = 116

# NAIVE_BRUTE_FORCE_ITERATION = 29556

CHARNUM_BRUTE_FORCE_ITERATION_START = 1008
CHARNUM_BRUTE_FORCE_FIRST_LETTER = 16
CHARNUM_BRUTE_FORCE_SECOND_LETTER = 0

ASCII_BRUTE_FORCE_ITERATION_START = 14592
ASCII_BRUTE_FORCE_FIRST_LETTER = 114
ASCII_BRUTE_FORCE_SECOND_LETTER = 0

NAIVE_BRUTE_FORCE_ITERATION_START = 28500

########################################

class BruteForceAttacker():

    def __init__(self, BLOCK_SIZE=16) -> None:
        self._BLOCK_SIZE = BLOCK_SIZE

    def _to_code(self, character):
        if character == " ":
            return 62
        elif character>="0" and character<="9":
            return ord(character)-ord('0')+52
        elif character>="A" and character<="Z":
            return ord(character)-ord('A')+26
        return ord(character)-ord('a')

    def _to_character(self, code):
        if code == 62:
            return " "
        elif code >= 52:
            return chr(ord('0')+code-52)
        elif code >= 26:
            return chr(ord('A')+code-26)
        return chr(ord('a')+code)

    def _show_input_details(self, ciphertext, passphrase, hint):
        print("____________________________________________")
        print("                                            ")
        print("Input Details")
        print("--------------------------------------------")
        print(f"Block Size      :     {self._BLOCK_SIZE}")
        print("--------------------------------------------")
        print("Ciphertext:")
        print(ciphertext)
        print("--------------------------------------------")
        print("Passphrase:")
        print(passphrase)
        print("--------------------------------------------")
        print("Hint:")
        print(hint)
        print("____________________________________________")
        print("                                            ")

    def _show_attack_report(self, status, key, plaintext):
        if status:
            print("--------------------------------------------")
            print("[Successful Attack]")
            print("--------------------------------------------")
            print("Key:")
            print(key)
            print("--------------------------------------------")
            print("Plaintext:")
            print(plaintext)
            print("____________________________________________")
            print("                                            ")
        else:
            print("--------------------------------------------")
            print("[Unsuccessful Attack]")
            print("____________________________________________")
            print("                                            ")

    # characters, numbers and space only (26 + 26 + 10 = 62)
    # only applicable for 16 bit block size
    def _charnum_brute_force(self, key_checker):
        print("CHARNUM BRUTE FORCE")
        print("--------------------------------------------")

        key = -1
        plaintext = ""
        status = False
        iteration = CHARNUM_BRUTE_FORCE_ITERATION_START
        for first_letter_code in range(CHARNUM_BRUTE_FORCE_FIRST_LETTER, 63):
            for second_letter_code in range(CHARNUM_BRUTE_FORCE_SECOND_LETTER, 63):
                print(f"\r[{iteration}]", end="")
                first_letter = self._to_character(first_letter_code)
                second_letter = self._to_character(second_letter_code)
                # ascii encoding for 2 characters
                candidate_key = (ord(first_letter) << 8) + ord(second_letter)
                valid = key_checker.check(candidate_key)
                if valid:
                    key = candidate_key
                    status = True
                    break
                iteration += 1
            if status:
                break
        print("")

        if status:
            key, plaintext = key_checker.decrypt(key)
        return status, key, plaintext

    # ascii characters only (128)
    # only applicable for 16 bit block size
    def _ascii_brute_force(self, key_checker):
        print("ASCII BRUTE FORCE")
        print("--------------------------------------------")

        key = -1
        plaintext = ""
        status = False
        iteration = ASCII_BRUTE_FORCE_ITERATION_START
        for first_letter_ascii in range(ASCII_BRUTE_FORCE_FIRST_LETTER, 128):
            for second_letter_ascii in range(ASCII_BRUTE_FORCE_SECOND_LETTER, 128):
                print(f"\r[{iteration}]", end="")
                # ascii encoding for 2 characters
                candidate_key = (first_letter_ascii << 8) + second_letter_ascii
                valid = key_checker.check(candidate_key)
                if valid:
                    key = candidate_key
                    status = True
                    break
                iteration += 1
            if status:
                break
        print("")

        if status:
            key, plaintext = key_checker.decrypt(key)
        return status, key, plaintext

    # naive (2^16)
    def _naive_brute_force(self, key_checker):
        print("NAIVE BRUTE FORCE")
        print("--------------------------------------------")

        key = -1
        plaintext = ""
        status = False
        key_range = range(NAIVE_BRUTE_FORCE_ITERATION_START, 2**(self._BLOCK_SIZE))
        for candidate_key in key_range:
            print(f"\r[{candidate_key}]", end="")
            valid = key_checker.check(candidate_key)
            if valid:
                key = candidate_key
                status = True
                break
        print("")

        if status:
            key, plaintext = key_checker.decrypt(key)
        return status, key, plaintext

    def attack(self, ciphertext, passphrase, hint):

        self._show_input_details(ciphertext, passphrase, hint)

        key_checker = KeyChecker(ciphertext, passphrase, hint, self._BLOCK_SIZE)

        # charnum brute-force
        status, key, plaintext = self._charnum_brute_force(key_checker)
        self._show_attack_report(status, key, plaintext)

        # ascii brute-force
        status, key, plaintext = self._ascii_brute_force(key_checker)
        self._show_attack_report(status, key, plaintext)

        # ascii brute-force
        status, key, plaintext = self._naive_brute_force(key_checker)
        self._show_attack_report(status, key, plaintext)

        return status, plaintext


if __name__ == '__main__':

    # input
    if len(sys.argv) != 4:
        print("EXACTLY 3 ARGUMENTS NEEDED IN ORDER: ciphertext_file_path cipher_info_file_path output_file_path")
        sys.exit()
    else:
        ciphertext_file_path = sys.argv[1]
        cipher_info_file_path = sys.argv[2]
        output_file_path = sys.argv[3]

    # file reads
    with open(ciphertext_file_path, 'r') as file:
        ciphertext = file.read()
    with open(cipher_info_file_path, 'r') as file:
        cipher_info_lines = file.readlines()
        blocksize = int(cipher_info_lines[0].split(":")[1])
        passphrase = cipher_info_lines[1].split(":")[1][:-1]
        hint = cipher_info_lines[2].split(":")[1]

    ### ATTACK ###
    attacker = BruteForceAttacker(blocksize)
    status, plaintext = attacker.attack(ciphertext, passphrase, hint)

    # output
    with open(output_file_path, 'w') as file:
        file.write(plaintext)
