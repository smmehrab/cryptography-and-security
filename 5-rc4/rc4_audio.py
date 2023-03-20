#!/usr/bin/env python3

# ************************************************
# username  :   smmehrab
# fullname  :   s.m.mehrabul islam
# email     :   smmehrabul-2017614964@cs.du.ac.bd
# institute :   university of dhaka, bangladesh
# reg       :   2017614964
# ************************************************

import sys
from rc4 import RC4

"""
README
(Make rc4_audio.py executable)

./rc4_audio.py data/audio.wav output/audio_enc.wav
./rc4_audio.py output/audio_enc.wav output/audio_dec.wav
./rc4_audio.py data/audio_long.wav output/audio_long_enc.wav
./rc4_audio.py output/audio_long_enc.wav output/audio_long_dec.wav
"""

DEBUG = True
HLINE = "___________________________________________\n"

if __name__ == '__main__':

    # Invalid Arguments
    if len(sys.argv) != 3:
        print("EXACTLY 2 ARGUMENTS NEEDED IN ORDER: input_file_path output_file_path")
        sys.exit()

    # Input
    input_file_path = sys.argv[1]
    output_file_path = sys.argv[2]

    # Key Prompt
    # key = "polymathpolymath"
    print(HLINE)
    key = input("Enter ASCII Key: (16 Chars)\n")
    if len(key) != 16:
        error = ValueError("Key length must be 16 characters long.")
        raise error
    
    if DEBUG:
        print(HLINE)
        print("Key: " + key)
        print(HLINE)

    # RC4
    rc4 = RC4()
    rc4.apply(input_file_path, output_file_path, key)

