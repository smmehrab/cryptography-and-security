
# ************************************************
# username  :   smmehrab
# fullname  :   s.m.mehrabul islam
# email     :   smmehrabul-2017614964@cs.du.ac.bd
# institute :   university of dhaka, bangladesh
# reg       :   2017614964
# ************************************************

import re
from batch_bruteforce import BatchBruteforce

DEBUG = True
HLINE = "___________________________________________\n"

REGEX_PLAINTEXT = '[^A-Za-z\s,.?!-().]'
REGEX_CIPHERTEXT_BYTES = '[^0-9,]'
REGEX_STRIP = '\s+'

DICTIONARY_FILE_PATH = "/usr/share/dict/words"
PLAINTEXT_FILE_PATH = "./data/mtp/plaintext.txt"
KEY_FILE_PATH = "./data/mtp/key.txt"
CIPHERTEXT_FILE_PATH = "./data/mtp/ciphertext.txt"

LIST_OF_CIPHERTEXTS_FILE_PATH = "./data/mtp/list_of_ciphertexts.txt"
ALPHABET_FILE_PATH = "./data/mtp/alphabet.txt"

OUTPUT_FILE_PATH = "./output/mtp.txt"

class MTPUtil:

    @staticmethod
    def _read_plaintext(path):
        with open(path, 'r') as file:
            data = file.read().rstrip()
        return re.sub(REGEX_PLAINTEXT, '',  data)
    
    @staticmethod
    def _read_ciphertext_bytes(path, reading_list=False):
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

    @staticmethod
    def _read_key(path):
        with open(path, 'r') as file:
            key = file.read().rstrip()
            return key

    @staticmethod
    def _write_ciphertext_bytes(ciphertext_bytes, path):
        with open(path, "w") as fhead:
            fhead.write("[")
            n = len(ciphertext_bytes)
            for i, ciphertext_byte in enumerate(ciphertext_bytes):
                fhead.write(str(ciphertext_byte))
                if i!=n-1:
                    fhead.write(", ")
            fhead.write("]")
            fhead.write("\n")

    @staticmethod
    def _write_plaintext(plaintext, path):
        with open(path, "w") as fhead:
            fhead.write(plaintext)

    @staticmethod
    def _output(key_bytes, list_of_plaintexts, execution_time, path):
        print("[Key Solved]")
        print(HLINE)
        print(key_bytes)
        print(HLINE)
        with open(path, 'w') as fhead:
            for i, plaintext in enumerate(list_of_plaintexts):
                print(f"Plaintext {i}   :   {plaintext}")
                fhead.write(plaintext + "\n")
        print(HLINE)
        print(f"Execution Time  :   {execution_time}s")
        print(HLINE)

    @staticmethod
    def _batch_size_prompt(number_of_positions, candidate_key_byte_counts):

        # Batch Size vs Combinations
        print(HLINE)
        print('{:15s} {:12s} '.format("Batch Size","Combinations"))
        print(HLINE)
        max_batch_size = (number_of_positions)//3
        combinations = 1
        for position in range(number_of_positions):
            combinations *= candidate_key_byte_counts[position]
            if position == 0:
                continue
            elif position <= max_batch_size:
                print('{:10d} {:17d} '.format(position+1, combinations))
            else:
                break
        print(HLINE)

        # Batch Size Input
        try:
            batch_size = int(input("Enter Batch Size:\n"))
        except ValueError:
            raise ValueError('Batch Size must be integer')

        if batch_size > number_of_positions:
            Overflow = ValueError('Batch Size must be less than number of positions (' + str(number_of_positions) + ")")
            raise Overflow
        elif batch_size < 1:
            Underflow = ValueError('Batch Size must be greater than 1')
            raise Underflow
        print(HLINE)

        return batch_size

class ManyTimePad():

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
            self._words = set([word.lower() for word in fhead.read().split()])

    def _PRF(self, text_byte, key_byte, previous_cipher_byte):
        return text_byte ^ ((key_byte+previous_cipher_byte)%256)

    def _get_key_byte(self, ciphertext_byte, plaintext_byte, previous_cipher_byte=0):
        return ((ciphertext_byte ^ plaintext_byte) - previous_cipher_byte) % 256

    def _encrypt(self, plaintext, key, previous_cipher_byte=0):
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
        return ciphertext_bytes

    def _decrypt(self, ciphertext_bytes, key, previous_cipher_byte=0):
        if len(key) != len(ciphertext_bytes):
            raise Exception("[DECRYPTION] key must be as long as the ciphertext byte count")
        n = len(ciphertext_bytes)
        
        plaintext = ""
        previous_cipher_byte = 0
        for i in range(n):
            ciphertext_byte = ciphertext_bytes[i]
            key_byte = ord(key[i]) if type(key[i]) == str else key[i]
            plaintext_byte = self._PRF(ciphertext_byte, key_byte, previous_cipher_byte)
            plaintext += chr(plaintext_byte)
            previous_cipher_byte = ciphertext_byte
        return plaintext

    def _generate_all_possible_candidate_key_bytes(self, list_of_ciphertext_bytes, number_of_positions):
        list_of_candidate_key_bytes = []

        # for each position
        for position in range(number_of_positions):
            candidate_key_bytes = []
            # try each member of the alphabet as plaintext_byte
            for alphabet_byte in self._alphabet_bytes:
                first_ciphertext_byte_on__previous_position = 0 if position == 0 else list_of_ciphertext_bytes[0][position-1]
                first_ciphertext_byte_on_position = list_of_ciphertext_bytes[0][position]
                candidate_key_byte = self._get_key_byte(first_ciphertext_byte_on_position, alphabet_byte, first_ciphertext_byte_on__previous_position)
                # use that candidate key to check if it satisfies all the ciphertexts (valid)
                is_valid = True
                for ciphertext_bytes in list_of_ciphertext_bytes:
                    previous_cipher_byte = 0 if position == 0 else ciphertext_bytes[position-1]
                    plaintext_byte = self._PRF(ciphertext_bytes[position], candidate_key_byte, previous_cipher_byte)
                    if plaintext_byte not in self._alphabet_bytes:
                        is_valid = False
                        break
                if is_valid:
                    candidate_key_bytes.append(candidate_key_byte)

            list_of_candidate_key_bytes.append(candidate_key_bytes)
        return list_of_candidate_key_bytes

    def encrypt(self, plaintext_file_path=PLAINTEXT_FILE_PATH, key_file_path=KEY_FILE_PATH):
        plaintext = MTPUtil._read_plaintext(plaintext_file_path)
        key = MTPUtil._read_key(key_file_path)
        
        ciphertext_bytes = self._encrypt(plaintext, key)

        if DEBUG:
            print(HLINE)
            print("[ENCRYPTION]")
            print(HLINE)
            print("Plaintext        : " + plaintext)
            print("Key              : " + key)
            print("Ciphertext Bytes : ", end = "")
            print(ciphertext_bytes)
            print(HLINE)

        MTPUtil._write_ciphertext_bytes(ciphertext_bytes, CIPHERTEXT_FILE_PATH)
        return ciphertext_bytes

    def decrypt(self, ciphertext_file_path=CIPHERTEXT_FILE_PATH, key_file_path=KEY_FILE_PATH):
        ciphertext_bytes = MTPUtil._read_ciphertext_bytes(ciphertext_file_path)
        key = MTPUtil._read_key(key_file_path)

        plaintext = self._decrypt(ciphertext_bytes, key)

        if DEBUG:
            print("[DECRYPTION]")
            print(HLINE)
            print("Ciphertext Bytes : ", end = "")
            print(ciphertext_bytes)
            print("Key              : " + key)
            print("Plaintext        : " + plaintext)
            print(HLINE)

        MTPUtil._write_plaintext(plaintext, self._output_file_path)
        return plaintext

    def attack(self, ciphertexts_file_path=LIST_OF_CIPHERTEXTS_FILE_PATH):

        list_of_ciphertext_bytes = MTPUtil._read_ciphertext_bytes(ciphertexts_file_path, True)

        number_of_positions = len(list_of_ciphertext_bytes[0])
        list_of_candidate_key_bytes = self._generate_all_possible_candidate_key_bytes(list_of_ciphertext_bytes, number_of_positions)

        candidate_key_byte_counts = [0]*number_of_positions
        for position in range(number_of_positions):
            candidate_key_byte_counts[position] = len(list_of_candidate_key_bytes[position])

        if DEBUG:
            print("[ATTACK]")
            print(HLINE)
            print("Generated All Possible Candidate Keys")
            print(HLINE)
            print(f"Number of Candidate Key Bytes for {number_of_positions} Positions:")
            for position in range(number_of_positions):
                # print(list_of_candidate_key_bytes[position])
                print(candidate_key_byte_counts[position], end=" ")
            print("")
            print(HLINE)
            print("Batch Brute Force")
            print(HLINE)

        # Batch Brute Force
        batch_size = MTPUtil._batch_size_prompt(number_of_positions, candidate_key_byte_counts)
        batch_bruteforce = BatchBruteforce(number_of_positions, list_of_candidate_key_bytes, list_of_ciphertext_bytes, self._words, batch_size, self._decrypt)
        key_bytes, execution_time = batch_bruteforce.start()

        # Get All Plaintexts
        list_of_plaintexts = []
        for i, ciphertext_bytes in enumerate(list_of_ciphertext_bytes):
            plaintext = self._decrypt(ciphertext_bytes, key_bytes)
            list_of_plaintexts.append(plaintext)

        # Output
        MTPUtil._output(key_bytes, list_of_plaintexts, execution_time, self._output_file_path)
        return list_of_plaintexts

if __name__ == '__main__':

    many_time_pad = ManyTimePad(ALPHABET_FILE_PATH, DICTIONARY_FILE_PATH, OUTPUT_FILE_PATH)

    many_time_pad.encrypt(PLAINTEXT_FILE_PATH, KEY_FILE_PATH)
    many_time_pad.decrypt(CIPHERTEXT_FILE_PATH, KEY_FILE_PATH)

    input("Press [ENTER] to Attack the Many Time Pad")

    many_time_pad.attack(LIST_OF_CIPHERTEXTS_FILE_PATH)
