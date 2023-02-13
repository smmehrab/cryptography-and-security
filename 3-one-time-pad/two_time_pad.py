
# ************************************************
# username  :   smmehrab
# fullname  :   s.m.mehrabul islam
# email     :   smmehrabul-2017614964@cs.du.ac.bd
# institute :   university of dhaka, bangladesh
# reg       :   2017614964
# ************************************************

import sys
import re

REGEX_STRIP = '\s+'
CIPHERTEXT_FILE_PATH = "./data/ttp/two_ciphertexts.txt"

class TwoTimePad():

    def __init__(self) -> None:
        pass

    def _get_ciphertexts(self, ciphertext_file_path):
        with open(ciphertext_file_path, 'r') as fhead:
            lines = fhead.readlines()
        return re.sub(REGEX_STRIP, '', lines[0]), re.sub(REGEX_STRIP, '', lines[1])

    def _get_words(self, file_path):
        with open(file_path, 'r') as fhead:
            lines = fhead.readlines()
        return re.sub(REGEX_STRIP, '', lines[0]), re.sub(REGEX_STRIP, '', lines[1])

    def attack(self, ciphertext_file_path=CIPHERTEXT_FILE_PATH):
        ciphertext1, ciphertext2 = self._get_ciphertexts(ciphertext_file_path)

        print(ciphertext1)
        print(ciphertext2)
        pass

if __name__ == '__main__':

    two_time_pad = TwoTimePad()
    two_time_pad.attack()
