#!/usr/bin/env python3

# ************************************************
# username  :   smmehrab
# fullname  :   s.m.mehrabul islam
# email     :   smmehrabul-2017614964@cs.du.ac.bd
# institute :   university of dhaka, bangladesh
# reg       :   2017614964
# ************************************************


import sys
from des import DES

# MESSAGE_FILE_PATH     =       "./data/message.txt"
# KEY_FILE_PATH         =       "./data/key.txt"
# ENCRYPTED_FILE_PATH   =       "./data/encrypted.txt"
# DECRYPTED_FILE_PATH   =       "./data/decrypted.txt"

DEBUG = True
HLINE = "___________________________________________\n"

if __name__ == '__main__':

    # Invalid Arguments
    if len(sys.argv) != 5:
        print("EXACTLY 4 ARGUMENTS NEEDED IN ORDER: \"ENCRYPT or DECRYPT\" input_file_path key_file_path output_file_path")
        sys.exit()

    # Encryption or Decryption
    op_mode = (sys.argv[1] == "ENCRYPT")

    # Input
    input_file_path = sys.argv[2]
    with open(input_file_path, 'r') as input_file:
        input_text = input_file.read()

    # Key
    key_file_path = sys.argv[3]
    with open(key_file_path, 'r') as key_file:
        key = key_file.read()

    # DES
    des = DES()
    output = des.apply(input_text, key, op_mode)

    if DEBUG:
        print(HLINE)
        if op_mode:
            print("[ENCRYPTION]")
            print(HLINE)
            print("Key              : " + key)
            print("Plaintext        : " + input_text)
            print("Ciphertext       : " + output)
            print(HLINE)
        else:
            print("[DECRYPTION]")
            print(HLINE)
            print("Key              : " + key)
            print("Ciphertext       : " + input_text)
            print("Plaintext        : " + output)
            print(HLINE)

    # Output
    output_file_path = sys.argv[4]
    with open(output_file_path, 'w') as output_file:
        output_file.write(output)

