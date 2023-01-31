# ************************************************
# username  :   smmehrab
# fullname  :   s.m.mehrabul islam
# email     :   smmehrabul-2017614964@cs.du.ac.bd
# institute :   university of dhaka, bangladesh
# reg       :   2017614964
# ************************************************

import re

REGEX = "[^A-Za-z]"
INPUT_FILE_PATH = "./data/input.txt"
OUTPUT_FILE_PATH = "./output.txt"

class FTGenerator:

    def __init__(self) -> None:
        self._frequency = [0]*52

    def _read(self, file_path):
        with open(file_path, 'r') as fhead:
            contents = fhead.read()
        return contents

    def _write(self, file_path):
        with open(file_path, 'w') as fhead:
            base_lower = ord('a')
            base_upper = ord('A')
            for i, f in enumerate(self._frequency):
                letter = chr(base_upper+i)
                if i>=26:
                    letter = chr(base_lower+i-26)
                line = letter + " " + str(f) + "\n"
                fhead.write(line)

    def _clean(self, text):
        return re.sub(REGEX, '', text)

    def generate(self, input_file_path):
        self._frequency = [0]*52
        input = self._read(input_file_path)
        input = self._clean(input)
        n = len(input)
        base_lower = ord('a')
        base_upper = ord('A')
        for i in range(52):
            letter = chr(base_upper+i)
            if i>=26:
                letter = chr(base_lower+i-26)
            f = input.count(letter)
            self._frequency[i] = float(f/n)

        self._write(OUTPUT_FILE_PATH)

if __name__ == '__main__':

    ftgenerator = FTGenerator()
    ftgenerator.generate(INPUT_FILE_PATH)