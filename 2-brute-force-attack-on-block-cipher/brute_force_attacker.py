
# ************************************************
# username  :   smmehrab
# fullname  :   s.m.mehrabul islam
# email     :   smmehrabul-2017614964@cs.du.ac.bd
# institute :   university of dhaka, bangladesh
# reg       :   2017614964
# ************************************************

import sys
from key_checker import KeyChecker

DEBUG = True

class BruteForceAttacker():

    def __init__(self, BLOCK_SIZE=16) -> None:
        self._BLOCK_SIZE = BLOCK_SIZE
        self._key_range = range(0, 2**(self._BLOCK_SIZE))

        if DEBUG:
            print("--------------------------------------------")
            print(f"Block Size:     {self._BLOCK_SIZE}")
            print(f"Key Range :     {self._key_range}")

    def attack(self, ciphertext, passphrase, hint):

        if DEBUG:
            print("--------------------------------------------")
            print("Ciphertext:")
            print(ciphertext)
            print("--------------------------------------------")
            print("Passphrase:")
            print(passphrase)
            print("--------------------------------------------")
            print("Hint:")
            print(hint)

        status = False
        key = None
        plainttext = ""

        # brute-force
        key_checker = KeyChecker(ciphertext, passphrase, hint)
        for candidate_key in self._key_range:
            valid = key_checker.check(candidate_key)
            if valid:
                key = candidate_key
                status = True
                break

        # output
        if status:
            plainttext = key_checker.decrypt(key)
            print("[Successful Attack]")
            if DEBUG:
                print("--------------------------------------------")
                print("Plaintext:")
                print(plainttext)
        else:
            print("[Unsuccessful Attack]")

        return status, plainttext


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
