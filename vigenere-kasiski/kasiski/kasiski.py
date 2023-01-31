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
FREQUENCY_TABLE_FILE_PATH = "./data/frequency_table.txt"
CIPHERTEXT_FILE_PATH = "./data/ciphertext.txt"
POSSIBLE_KEYS_FILE_PATH = "./output/possible_keys.txt"

class Kasiski:

    def __init__(self, frequency_table_file_path):
        self._frequency_table = {}
        self._read_frequency_table(frequency_table_file_path)
        print(self._frequency_table)

    def _read_frequency_table(self, file_path):
        with open(file_path, 'r') as fhead:
            lines = fhead.readlines()
            for line in lines:
                line = line[:-1]
                letter, count = line.split(" ")
                if letter:
                    self._frequency_table[letter] = count

    def _read(self, file_path):
        with open(file_path, 'r') as fhead:
            contents = fhead.read()
        return contents

    def _write(self, file_path, text):
        with open(file_path, 'w') as fhead:
             fhead.write(text)

    def _clean(self, text):
        return re.sub(REGEX, '', text)

    def _index_of_coincidence(self, text):
        n = len(text)
        ioc_numerator = 0.0
        ioc_denumerator = float(n*(n-1))
        for letter in self._alphabet:
            f = text.count(letter)
            ioc_numerator += f * (f-1)
        # ioc = SUM OF ALL (f/n)*((f-1)/(n-1))
        ioc = float(ioc_numerator/ioc_denumerator)
        return ioc

    def _frequency_analysis(self):
        pass

    def _find_keyword_length(self):
        pass

    def _find_keyword(self):
        pass

    def attack(self, ciphertext_file_path):
        ciphertext = self._read(ciphertext_file_path)
        ciphertext = self._clean(ciphertext)

        keyword_length = self._find_keyword_length(ciphertext)
        keyword = self._find_keyword(ciphertext, keyword_length)
        print(keyword)
        return

if __name__ == '__main__':
    kasiski = Kasiski(FREQUENCY_TABLE_FILE_PATH)
    # kasiski.attack(CIPHERTEXT_FILE_PATH)