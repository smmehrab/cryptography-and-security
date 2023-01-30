# ************************************************
# username  :   smmehrab
# fullname  :   s.m.mehrabul islam
# email     :   smmehrabul-2017614964@cs.du.ac.bd
# institute :   university of dhaka, bangladesh
# reg       :   2017614964
# ************************************************

import re

REGEX = "[^A-Za-z]"
KEY_FILE_PATH = "./data/key.txt"
PLAINTTEXT_FILE_PATH = "./data/plaintext.txt"
CIPHERTEXT_FILE_PATH = "./data/ciphertext.txt"
WORD_SIZE = 5

class Vigenere:

    def __init__(self, key_file_path) -> None:
        self._keys = self._read(key_file_path)

    def _read(self, file_path):
        with open(file_path) as fhead:
            contents = fhead.read()
        return contents

    def _write(self, file_path, text):
        with open(file_path) as fhead:
             fhead.write(text)

    def _clean(self, text):
        return re.sub(REGEX, '', text)

    def _format(self, text):
        n = len(text)
        words = [text[i:i+WORD_SIZE] for i in range(0, n, WORD_SIZE)]
        return " ".join(words)

    def encrypt(self, plaintext_file_path):
        plaintext = self._read(plaintext_file_path)
        plaintext = self._clean(plaintext)

        # @Encryption


        ciphertext = self._format(ciphertext)
        self._write(CIPHERTEXT_FILE_PATH, ciphertext)
        return

    def decrypt(self, ciphertext_file_path):
        ciphertext = self._read(ciphertext_file_path)
        ciphertext = self._clean(ciphertext)

        # @Decryption


        plaintext = self._format(plaintext)
        self._write(PLAINTTEXT_FILE_PATH, plaintext)
        return

if __name__ == '__main__':

    vigenere = Vigenere(KEY_FILE_PATH)
    vigenere.encrypt(PLAINTTEXT_FILE_PATH)