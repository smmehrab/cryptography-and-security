
# ************************************************
# username  :   smmehrab
# fullname  :   s.m.mehrabul islam
# email     :   smmehrabul-2017614964@cs.du.ac.bd
# institute :   university of dhaka, bangladesh
# reg       :   2017614964
# ************************************************

import re

DEBUG = True
REGEX_PLAINTEXT = '[^A-Za-z\s,.?!-().]'
REGEX_CIPHERTEXT_BYTES = '[^0-9,]'

REGEX_STRIP = '\s+'
PLAINTEXT_FILE_PATH = "./data/mtp/plaintext.txt"
KEY_FILE_PATH = "./data/mtp/key.txt"
CIPHERTEXT_FILE_PATH = "./data/mtp/ciphertext.txt"
LIST_OF_CIPHERTEXTS_FILE_PATH = "./data/mtp/list_of_ciphertexts.txt"
OUTPUT_FILE_PATH = "./output/mtp.txt"

class ManyTimePad():

    def __init__(self) -> None:
        pass

    def _read_plaintext(self, path):
        with open(path, 'r') as file:
            data = file.read().rstrip()
        return re.sub(REGEX_PLAINTEXT, '',  data)

    def _read_ciphertext_bytes(self, path, reading_list=False):
        with open(path, 'r') as file:
            lines = file.readlines()
        list_of_ciphertext_bytes = []
        for line in lines:
            strnums = re.sub(REGEX_CIPHERTEXT_BYTES, '',  line)
            strnums = strnums.split(",")
            ciphertext_bytes = []
            for strnum in strnums:
                ciphertext_bytes.append(int(strnum))
            list_of_ciphertext_bytes.append(ciphertext_bytes)
        if reading_list:
            return list_of_ciphertext_bytes
        return list_of_ciphertext_bytes[0]

    def _read_key(self, path):
        with open(path, 'r') as file:
            key = file.read().rstrip()
            return key

    def _write_ciphertext_bytes(self, ciphertext_bytes, path):
        with open(path, "w") as fhead:
            fhead.write("[")
            n = len(ciphertext_bytes)
            for i, ciphertext_byte in enumerate(ciphertext_bytes):
                fhead.write(str(ciphertext_byte))
                if i!=n-1:
                    fhead.write(", ")
            fhead.write("]")
            fhead.write("\n")

    def _write_plaintext(self, plaintext, path):
        with open(path, "w") as fhead:
            fhead.write(plaintext)

    def _PRF(self, text_byte, key_byte, previous_cipher_byte):
        return text_byte ^ ((key_byte+previous_cipher_byte)%256)

    def _get_key_bytes(self, ciphertext_bytes, plaintext, previous_cipher_byte=0):

        if len(ciphertext_bytes) != len(plaintext):
            raise Exception("[GET KEY] plaintext length must be equal to the ciphertext bytes count")

        n = len(plaintext)
        key_bytes = []
        for i in range(n):
            ciphertext_byte = ciphertext_bytes[i]
            plaintext_byte = ord(plaintext[i])
            key_byte = ((ciphertext_byte ^ plaintext_byte) - previous_cipher_byte) % 256
            key_bytes.append(key_byte)
            previous_cipher_byte = ciphertext_byte

        return key_bytes

    def encrypt(self, plaintext_file_path=PLAINTEXT_FILE_PATH, key_file_path=KEY_FILE_PATH, output_file_path=CIPHERTEXT_FILE_PATH):
        plaintext = self._read_plaintext(plaintext_file_path)
        key = self._read_key(key_file_path)

        if len(key) != len(plaintext):
            raise Exception("[ENCRYPTION] key must be as long as the plaintext")
        
        n = len(plaintext)
        ciphertext_bytes = []
        previous_cipher_byte = 0
        for i in range(n):
            plaintext_byte = ord(plaintext[i])
            key_byte = ord(key[i])
            previous_cipher_byte = self._PRF(plaintext_byte, key_byte, previous_cipher_byte)
            ciphertext_bytes.append(previous_cipher_byte)

        if DEBUG:
            print("[ENCRYPTION]")
            print("------------------")
            print("Plaintext        : " + plaintext)
            print("Key              : " + key)
            print("Ciphertext Bytes : ", end = "")
            print(ciphertext_bytes)
            print("------------------")

        self._write_ciphertext_bytes(ciphertext_bytes, output_file_path)
        return ciphertext_bytes

    def decrypt(self, ciphertext_file_path=CIPHERTEXT_FILE_PATH, key_file_path=KEY_FILE_PATH, output_file_path=PLAINTEXT_FILE_PATH):
        ciphertext_bytes = self._read_ciphertext_bytes(ciphertext_file_path)
        print(ciphertext_bytes)
        key = self._read_key(key_file_path)

        if len(key) != len(ciphertext_bytes):
            raise Exception("[DECRYPTION] key must be as long as the ciphertext byte count")

        n = len(ciphertext_bytes)
        plaintext = ""
        previous_cipher_byte = 0
        for i in range(n):
            ciphertext_byte = ciphertext_bytes[i]
            key_byte = ord(key[i])
            plaintext_byte = self._PRF(ciphertext_byte, key_byte, previous_cipher_byte)
            plaintext += chr(plaintext_byte)
            previous_cipher_byte = ciphertext_byte

        if DEBUG:
            print("[DECRYPTION]")
            print("------------------")
            print("Ciphertext Bytes : ", end = "")
            print(ciphertext_bytes)
            print("Key              : " + key)
            print("Plaintext        : " + plaintext)
            print("------------------")

        self._write_plaintext(plaintext, output_file_path)
        return plaintext

    def attack(self, ciphertexts_file_path=LIST_OF_CIPHERTEXTS_FILE_PATH):
        list_of_ciphertext_bytes = self._read_ciphertext_bytes(ciphertexts_file_path, True)

        pass

if __name__ == '__main__':

    many_time_pad = ManyTimePad()

    many_time_pad.encrypt(PLAINTEXT_FILE_PATH, KEY_FILE_PATH, CIPHERTEXT_FILE_PATH)
    many_time_pad.decrypt(CIPHERTEXT_FILE_PATH, KEY_FILE_PATH, OUTPUT_FILE_PATH)

    many_time_pad.attack(LIST_OF_CIPHERTEXTS_FILE_PATH)