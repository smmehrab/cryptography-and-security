# ************************************************
# username  :   smmehrab
# fullname  :   s.m.mehrabul islam
# email     :   smmehrabul-2017614964@cs.du.ac.bd
# institute :   university of dhaka, bangladesh
# reg       :   2017614964
# ************************************************

import re, time
from difflib import SequenceMatcher

REGEX = '[^A-Za-z]'

KEY_FILE_PATH = "./data/key.txt"
PLAINTTEXT_FILE_PATH = "./data/plaintext.txt"
CIPHERTEXT_FILE_PATH = "./data/ciphertext.txt"

ENCRYPTED_CIPHERTEXT_FILE_PATH = "./output/encrypted_ciphertext.txt"
DECRYPTED_PLAINTTEXT_FILE_PATH = "./output/decrypted_plaintext.txt"

WORD_SIZE = 5
WORDS_PER_LINE = 19

class Vigenere:

    def __init__(self) -> None:
        pass

    def _get_text(self, path):
        with open(path, 'r') as file:
            data = file.read().rstrip()
        return re.sub(REGEX, '',  data)

    def _get_key(self, path):
        with open(path, 'r') as file:
            key = file.read().rstrip()
            return key

    def _to_code(self, character):
        if ord(character) < 91:
            return ord(character)-ord('A')+26
        return ord(character)-ord('a')

    def _to_character(self, code):
        code %= 52
        if code >= 26:
            return chr(code+ord('A')-26)
        return chr(code+ord('a'))

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

    def _encryption_report(self, plaintext, key, ciphertext, formatted_ciphertext, execution_time):
        print("------------------------------------------------")
        print("[Encryption]")
        print(f"Keyword                 :   {key}")
        print(f"Plaintext Length        :   {len(plaintext)}")
        print(f"Ciphertext Length       :   {len(ciphertext)}")
        print(f"Ciphertext Length (f)   :   {len(formatted_ciphertext)}")
        print(f"Execution Time          :   {execution_time}s")
        print()
        print(f"[OUTPUT]")
        print(f"Ciphertext Path         :   {ENCRYPTED_CIPHERTEXT_FILE_PATH}")
        print()
        print(f"[INPUT]")
        print(f"Plaintext Path          :   {PLAINTTEXT_FILE_PATH}")
        print(f"Keyword Path            :   {KEY_FILE_PATH}")

    def _decryption_report(self, plaintext, key, ciphertext, execution_time):
        print("------------------------------------------------")
        print("[Decryption]")
        print(f"Keyword                 :   {key}")
        print(f"Ciphertext Length       :   {len(ciphertext)}")
        print(f"Plaintext Length        :   {len(plaintext)}")
        print(f"Execution Time          :   {execution_time}s")
        print()
        print(f"[OUTPUT]")
        print(f"Plaintext Path          :   {DECRYPTED_PLAINTTEXT_FILE_PATH}")
        print()
        print(f"[INPUT]")
        print(f"Ciphertext Path         :   {ENCRYPTED_CIPHERTEXT_FILE_PATH}")
        print(f"Keyword Path            :   {KEY_FILE_PATH}")

    def get_plaintext_accuracy(self, predicted_plaintext_file_path, plaintext_file_path=PLAINTTEXT_FILE_PATH):
        predicted_plaintext = self._get_text(predicted_plaintext_file_path)
        plaintext = self._get_text(plaintext_file_path)
        return 100*SequenceMatcher(None, predicted_plaintext, plaintext).ratio()

    def get_key_accuracy(self, predicted_key_file_path, key_file_path=KEY_FILE_PATH):
        predicted_key = self._get_key(predicted_key_file_path)
        key = self._get_key(key_file_path)
        return 100*SequenceMatcher(None, predicted_key, key).ratio()

    def encrypt(self, plaintext_file_path, key_file_path, output_file_path=ENCRYPTED_CIPHERTEXT_FILE_PATH, report=True):
        start_time = time.time()

        # preprocess
        plaintext = self._get_text(plaintext_file_path)
        key = self._get_key(key_file_path)
        # mechanism
        ciphertext = ""
        key_len = len(key)
        for i, letter in enumerate(plaintext):
            ciphercode = self._to_code(letter) + self._to_code(key[i%key_len])
            cipherletter = self._to_character(ciphercode)
            ciphertext += cipherletter
        # format
        formatted_ciphertext = self._format(ciphertext)
        # save
        with open(ENCRYPTED_CIPHERTEXT_FILE_PATH, "w") as fhead:
            fhead.write(formatted_ciphertext)
        with open(CIPHERTEXT_FILE_PATH, "w") as fhead:
            fhead.write(ciphertext)

        end_time = time.time()
        execution_time = round(float(end_time - start_time), 4)

        if report:
            self._encryption_report(plaintext, key, ciphertext, formatted_ciphertext, execution_time)
        return ciphertext

    def decrypt(self, encrypted_ciphertext_file_path, key_file_path, output_file_path=DECRYPTED_PLAINTTEXT_FILE_PATH, report=True):
        start_time = time.time()
        # preprocess
        formatted_ciphertext = self._get_text(encrypted_ciphertext_file_path)
        ciphertext = formatted_ciphertext.replace(" ", "")
        key = self._get_key(key_file_path)
        # mechanism
        plaintext = ""
        key_len = len(key)
        for i, letter in enumerate(ciphertext):
            plaincode = self._to_code(letter) - self._to_code(key[i%key_len])
            plainletter = self._to_character(plaincode)
            plaintext += plainletter
        # save
        with open(output_file_path, "w") as fhead:
            fhead.write(plaintext)

        end_time = time.time()
        execution_time = round(float(end_time - start_time), 4)

        if report:
            self._decryption_report(plaintext, key, ciphertext, execution_time)
        return plaintext

if __name__ == '__main__':

    vigenere = Vigenere()
    ciphertext = vigenere.encrypt(PLAINTTEXT_FILE_PATH, KEY_FILE_PATH)
    plainttext = vigenere.decrypt(ENCRYPTED_CIPHERTEXT_FILE_PATH, KEY_FILE_PATH)
