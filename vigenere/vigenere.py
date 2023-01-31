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
        with open(file_path, 'r') as fhead:
            contents = fhead.read()
        return contents

    def _write(self, file_path, text):
        with open(file_path, 'w') as fhead:
             fhead.write(text)

    def _clean(self, text):
        return re.sub(REGEX, '', text)

    def _test_alphabet(self, text):
        cleaned_text = re.sub(REGEX, '', text)
        return len(text) == len(cleaned_text)

    def _format(self, text):
        n = len(text)
        words = [text[i:i+WORD_SIZE] for i in range(0, n, WORD_SIZE)]
        lines = []
        line = ""
        for i, word in enumerate(words):
            if i!= 0 and i%19==0:
                line += "\n"
                lines.append(line)
                line = ""
            else:
                line += " "
            line += word
        lines.append(line)
        return " ".join(lines)

    def encrypt(self, plaintext_file_path):
        # preprocessing
        plaintext = self._read(plaintext_file_path)
        plaintext = self._clean(plaintext)
        plaintext_len = len(plaintext)
        key_len = len(self._keys[0])
        alphabet_len = ord('z')-ord('a')
        # text to codes
        plaincodes = [ord(letter) for letter in plaintext]
        keycodes = [ord(letter) for letter in self._keys[0]]
        ciphercodes = []
        # encryption mechanism
        for i in range(plaintext_len):
            basecode = ord('A') if plaincodes[i]>=ord('A') and plaincodes[i]<=ord('Z') else ord('a')
            ciphercode = (plaincodes[i]-basecode)
            ciphercode += (keycodes[i%key_len]-basecode)
            if ciphercode>alphabet_len-1:
                ciphercode -= alphabet_len
            ciphercode += basecode
            ciphercodes.append(ciphercode)
        # codes to text
        ciphertext = ''.join(chr(code) for code in ciphercodes)
        # postprocessing
        ciphertext = self._format(ciphertext)
        self._write(CIPHERTEXT_FILE_PATH, ciphertext)
        if self._test_alphabet(ciphertext):
            print("[Successful Encryption]")
        else:
            print("[Faulty Encryption]")
        return

    def decrypt(self, ciphertext_file_path):
        ciphertext = self._read(ciphertext_file_path)
        ciphertext = self._clean(ciphertext)
        ciphertext_len = len(ciphertext)
        key_len = len(self._keys[0])
        alphabet_len = ord('z')-ord('a')
        # text to codes
        ciphercodes = [ord(letter) for letter in ciphertext]
        keycodes = [ord(letter) for letter in self._keys[0]]
        plaincodes = []
        # decryption mechanism
        for i in range(ciphertext_len):
            basecode = ord('A') if ciphercodes[i]>=ord('A') and ciphercodes[i]<=ord('Z') else ord('a')
            plaincode = (ciphercodes[i]-basecode)
            plaincode -= (keycodes[i%key_len]-basecode)
            if plaincode>alphabet_len-1:
                plaincode -= alphabet_len
            plaincode += basecode
            plaincodes.append(plaincode)
        # codes to text
        plaintext = ''.join(chr(code) for code in plaincodes)
        # postprocessing
        plaintext = self._format(plaintext)
        self._write(PLAINTTEXT_FILE_PATH, plaintext)
        if self._test_alphabet(plaintext):
            print("[Successful Decryption]")
        else:
            print("[Faulty Decryption]")
        return

if __name__ == '__main__':

    vigenere = Vigenere(KEY_FILE_PATH)
    vigenere.encrypt(PLAINTTEXT_FILE_PATH)