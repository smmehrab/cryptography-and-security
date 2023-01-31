# ************************************************
# username  :   smmehrab
# fullname  :   s.m.mehrabul islam
# email     :   smmehrabul-2017614964@cs.du.ac.bd
# institute :   university of dhaka, bangladesh
# reg       :   2017614964
# ************************************************

import re

REGEX = "[^A-Za-z]"
REGEX_FOR_TEST = "[^A-Za-z\n ]"

# ALPHABET_FILE_PATH = "./data/alphabet.txt"
KEY_FILE_PATH = "./data/key.txt"

PLAINTTEXT_FILE_PATH = "./data/plaintext.txt"
CIPHERTEXT_FILE_PATH = "./output/ciphertext.txt"

WORD_SIZE = 5
WORDS_PER_LINE = 19

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
        cleaned_text = re.sub(REGEX_FOR_TEST, '', text)
        # print(text)
        # print(cleaned_text)
        return len(text) == len(cleaned_text)

    def _format(self, text):
        text_len = len(text)
        words = [text[i:i+WORD_SIZE] for i in range(0, text_len, WORD_SIZE)]
        lines = []
        line = ""
        for i, word in enumerate(words):
            if i!=0 and i%WORDS_PER_LINE==0:
                line += "\n"
                lines.append(line)
                line = ""
            else:
                line += " "
            line += word
        lines.append(line)
        return " ".join(lines)

    def _to_code(self, character):
        if character>="A" and character<="Z":
            return ord(character)-ord('A')+26
        return ord(character)-ord('a')

    def _to_character(self, code):
        if code >= 26:
            return chr(ord('A')+code-26)
        return chr(ord('a')+code)
 
    def encrypt(self, plaintext_file_path):
        # preprocessing
        plaintext = self._read(plaintext_file_path)
        plaintext = self._clean(plaintext)
        plaintext_len = len(plaintext)
        key_len = len(self._keys[0])
        # text to codes
        plaincodes = [self._to_code(letter) for letter in plaintext]
        keycodes = [self._to_code(letter) for letter in self._keys[0]]
        # encryption mechanism
        ciphertext = ""
        key_index = 0
        for i in range(plaintext_len):
            # key index
            if key_index==key_len:
                key_index = 0
            # C = (P+K)%N
            ciphercode = (plaincodes[i]+keycodes[key_index])%52
            key_index += 1
            ciphertext += self._to_character(ciphercode)
        # postprocessing
        ciphertext = self._format(ciphertext)
        self._write(CIPHERTEXT_FILE_PATH, ciphertext)
        # test
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
        # text to codes
        ciphercodes = [self._to_code(letter) for letter in ciphertext]
        keycodes = [self._to_code(letter) for letter in self._keys[0]]
        # decryption mechanism
        plaintext = ""
        key_index = 0
        for i in range(ciphertext_len):
            # key index
            if key_index == key_len:
                key_index = 0
            # P = (C-K)%N
            plaincode = (ciphercodes[i]-keycodes[key_index])%52
            key_index += 1
            plaintext += self._to_character(plaincode)
        # postprocessing
        plaintext = self._format(plaintext)
        self._write(PLAINTTEXT_FILE_PATH, plaintext)
        # test
        if self._test_alphabet(plaintext):
            print("[Successful Decryption]")
        else:
            print("[Faulty Decryption]")
        return

if __name__ == '__main__':

    vigenere = Vigenere(KEY_FILE_PATH)
    vigenere.encrypt(PLAINTTEXT_FILE_PATH)
    vigenere.decrypt(CIPHERTEXT_FILE_PATH)