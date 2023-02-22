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

# IMG_FILE_PATH     =       "./img/image.ppm"
# KEY_FILE_PATH         =       "./data/key.txt"
# ENCRYPTED_IMG_PATH   =       "./img/image_enc.ppm"
# DECRYPTED_IMG_PATH   =       "./data/decrypted.txt"

# ./DES_image.py "ENCRYPT" img/image.ppm data/key.txt img/image_enc.ppm 

if __name__ == '__main__':

    # Invalid Arguments
    if len(sys.argv) != 5:
        print("EXACTLY 4 ARGUMENTS NEEDED IN ORDER: \"ENCRYPT or DECRYPT\" input_img_path key_file_path output_img_path")
        sys.exit()

    op_mode = (sys.argv[1] == "ENCRYPT")
    input_img_path = sys.argv[2]
    key_file_path = sys.argv[3]
    output_img_path = sys.argv[4]


    # Key
    with open(key_file_path, 'r') as key_file:
        key = key_file.read()

    # DES
    des = DES()
    des.apply_on_image(input_img_path, key, output_img_path, op_mode)
