# ************************************************
# username  :   smmehrab
# fullname  :   s.m.mehrabul islam
# email     :   smmehrabul-2017614964@cs.du.ac.bd
# institute :   university of dhaka, bangladesh
# reg       :   2017614964
# ************************************************


# P(2 letter same) = index_of_coincidence = 0.066 monoalphabetic cipher
# P(2 letter same) = index_of_coincidence = 0.038 polyalphabetic cipher


import re

REGEX = "[^A-Za-z]"
CIPHERTEXT_FILE_PATH = "./data/output.txt"
POSSIBLE_KEYS_FILE_PATH = "./data/possible_keys.txt"

class Kasiski:

    def __init__(self, frequency_table_file_path) -> None:
        pass

    def _read(self, file_path):
        with open(file_path) as fhead:
            contents = fhead.read()
        return contents

    def _write(self, file_path, text):
        with open(file_path) as fhead:
             fhead.write(text)

    def _clean(self, text):
        return re.sub(REGEX, '', text)

    def _index_of_coincidence(self):
        pass

    def _frequency_analysis(self):
        pass

    def _find_keyword_length(self):
        pass

    def attack(self, ciphertext_file_path):
        pass


if __name__ == '__main__':
    kasiski = Kasiski()
    kasiski.attack(CIPHERTEXT_FILE_PATH)