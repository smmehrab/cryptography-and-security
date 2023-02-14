
# ************************************************
# username  :   smmehrab
# fullname  :   s.m.mehrabul islam
# email     :   smmehrabul-2017614964@cs.du.ac.bd
# institute :   university of dhaka, bangladesh
# reg       :   2017614964
# ************************************************

import re

ALPHABET_FILE_PATH = "./data/mtp/alphabet.txt"
DICTIONARY_FILE_PATH = "/usr/share/dict/words"

REGEX_STRIP = '\s+'
CIPHERTEXT_FILE_PATH = "./data/ttp/two_ciphertexts.txt"
OUTPUT_FILE_PATH = "./output/ttp.txt"

class TwoTimePad():

    def __init__(self, alphabet_file_path=ALPHABET_FILE_PATH, dictionary_file_path=DICTIONARY_FILE_PATH, output_file_path=OUTPUT_FILE_PATH) -> None:
        self._output_file_path = output_file_path
        # read alphabets available
        with open(alphabet_file_path, 'r') as file:
            self._alphabet = file.read().rstrip()
            self._alphabet_bytes = []
            for c in self._alphabet:
                self._alphabet_bytes.append(ord(c))

        # read dictionary of words
        with open(dictionary_file_path, 'r') as fhead:
            self._words = set([word for word in fhead.read().split()])

    def _hex_to_bytes(self, h):
        n = len(h)
        hexbytes = []
        for i in range(0, n, 2):
            two_letter = h[i:i+2]
            hexbytes.append(int(two_letter, 16))
        return hexbytes

    def _text_to_bytes(self, text):
        text_bytes = []
        for letter in text:
            text_bytes.append(ord(letter))
        return text_bytes

    def _get_ciphertexts(self, ciphertext_file_path):
        with open(ciphertext_file_path, 'r') as fhead:
            lines = fhead.readlines()
            c1 = re.sub(REGEX_STRIP, '', lines[0])
            c2 = re.sub(REGEX_STRIP, '', lines[1])
            return self._hex_to_bytes(c1), self._hex_to_bytes(c2)

    def attack(self, ciphertext_file_path=CIPHERTEXT_FILE_PATH):
        ciphertext1, ciphertext2 = self._get_ciphertexts(ciphertext_file_path)

        # ciphertext1 ^ ciphertext2 = plaintext1 ^ plaintext2
        number_of_characters = len(ciphertext1)
        combined_plaintext_bytes = []
        for i in range(number_of_characters):
            ciphertext1_byte = ciphertext1[i]
            ciphertext2_byte = ciphertext2[i]
            combined_plaintext_bytes.append(ciphertext1_byte^ciphertext2_byte)

        # restrict dictionary
        restricted_dictionary = []
        for word in self._words:
            if len(word) == number_of_characters:
                valid = True
                for letter in word:
                    if letter not in self._alphabet:
                        valid = False
                        break
                if valid:
                    restricted_dictionary.append(word)

        # brute force
        iteration = 0
        plaintext1 = ""
        plaintext2 = ""
        for word in restricted_dictionary:

            plaintext1 = word
            plaintext1_bytes = self._text_to_bytes(plaintext1)

            plaintext2 = ""
            plaintext2_bytes = []
            for i in range(number_of_characters):
                plaintext2_byte = plaintext1_bytes[i]^combined_plaintext_bytes[i]
                plaintext2 += chr(plaintext2_byte)
                plaintext2_bytes.append(plaintext2_byte)

            if plaintext2 in restricted_dictionary:
                print("[FOUND]")
                break

            iteration += 1

        # find key bytes
        key_bytes1 = []
        for i in range(number_of_characters):
            key_bytes1.append(plaintext1_bytes[i]^ciphertext1[i])

        key_bytes2 = []
        for i in range(number_of_characters):
            key_bytes2.append(plaintext1_bytes[i]^ciphertext2[i])

        # Output
        ## Console
        print(f"Iterations      :       {iteration}")
        print(f"Plaintext 1     :       {plaintext1}")
        print(f"Plaintext 2     :       {plaintext2}")
        print(f"Key Bytes 1     :       {key_bytes1}")
        print(f"Key Bytes 2     :       {key_bytes2}")
        ## File
        with open(self._output_file_path, 'w') as fhead:
            print(f"Iterations      :       {iteration}", file = fhead)
            print(f"Plaintext 1     :       {plaintext1}", file = fhead)
            print(f"Plaintext 2     :       {plaintext2}", file = fhead)
            print(f"Key Bytes 1     :       {key_bytes1}", file = fhead)
            print(f"Key Bytes 2     :       {key_bytes2}", file = fhead)
        return plaintext1, plaintext2, key_bytes1, key_bytes2

if __name__ == '__main__':

    two_time_pad = TwoTimePad(ALPHABET_FILE_PATH, DICTIONARY_FILE_PATH, OUTPUT_FILE_PATH)
    two_time_pad.attack()
