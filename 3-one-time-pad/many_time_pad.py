
# ************************************************
# username  :   smmehrab
# fullname  :   s.m.mehrabul islam
# email     :   smmehrabul-2017614964@cs.du.ac.bd
# institute :   university of dhaka, bangladesh
# reg       :   2017614964
# ************************************************

import re, time

DEBUG = True
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

    def _get_score(self, text):
        score = 0
        for word in self._words:
            if word in text:
                score += (len(word)**2)
        return score

    def _batch_brute_force(self, index, key_bytes, list_of_ciphertext_bytes, list_of_candidate_key_bytes, limit, batch_size):
        # base case
        if index == limit:
            plaintexts = ""
            for ciphertext_bytes in list_of_ciphertext_bytes:
                batch_size_ciphertext_bytes = ciphertext_bytes[(index-batch_size):limit]
                plaintext = self._decrypt(batch_size_ciphertext_bytes, key_bytes)
                plaintexts += plaintext
                plaintexts += "\n"
            plaintexts = plaintexts[:-1]
            plaintexts_lower = plaintexts.lower()
            score = self._get_score(plaintexts_lower)
            return key_bytes, plaintexts, score
        # recurse
        best_key_bytes, best_plaintexts, best_score = None, None, 0
        for candidate_key_byte in list_of_candidate_key_bytes[index]:
            updated_key_bytes, plaintexts, score = self._batch_brute_force(index+1, key_bytes+[candidate_key_byte], list_of_ciphertext_bytes, list_of_candidate_key_bytes, limit, batch_size)
            if score > best_score:
                best_key_bytes, best_plaintexts, best_score = updated_key_bytes, plaintexts, score
        return best_key_bytes, best_plaintexts, best_score


    def encrypt(self, plaintext_file_path=PLAINTEXT_FILE_PATH, key_file_path=KEY_FILE_PATH):
        plaintext = self._read_plaintext(plaintext_file_path)
        key = self._read_key(key_file_path)
        
        ciphertext_bytes = self._encrypt(plaintext, key)

        if DEBUG:
            print("[ENCRYPTION]")
            print("------------------")
            print("Plaintext        : " + plaintext)
            print("Key              : " + key)
            print("Ciphertext Bytes : ", end = "")
            print(ciphertext_bytes)
            print("------------------")

        self._write_ciphertext_bytes(ciphertext_bytes, CIPHERTEXT_FILE_PATH)
        return ciphertext_bytes

    def decrypt(self, ciphertext_file_path=CIPHERTEXT_FILE_PATH, key_file_path=KEY_FILE_PATH):
        ciphertext_bytes = self._read_ciphertext_bytes(ciphertext_file_path)
        key = self._read_key(key_file_path)

        plaintext = self._decrypt(ciphertext_bytes, key)

        if DEBUG:
            print("[DECRYPTION]")
            print("------------------")
            print("Ciphertext Bytes : ", end = "")
            print(ciphertext_bytes)
            print("Key              : " + key)
            print("Plaintext        : " + plaintext)
            print("------------------")

        self._write_plaintext(plaintext, self._output_file_path)
        return plaintext

    def attack(self, ciphertexts_file_path=LIST_OF_CIPHERTEXTS_FILE_PATH):

        list_of_ciphertext_bytes = self._read_ciphertext_bytes(ciphertexts_file_path, True)

        number_of_positions = len(list_of_ciphertext_bytes[0])
        list_of_candidate_key_bytes = self._generate_all_possible_candidate_key_bytes(list_of_ciphertext_bytes, number_of_positions)

        if DEBUG:
            print("[ATTACK]")
            print("------------------")
            print("Generated All Possible Candidate Keys")
            print("------------------")
            print(f"Number of Candidate Key Bytes for {number_of_positions} Positions:")
            for position in range(number_of_positions):
                # print(list_of_candidate_key_bytes[position])
                print(len(list_of_candidate_key_bytes[position]), end=" ")
            print("")
            print("------------------")
            print("Brute Force Using Batches")
            print("------------------")

        # key_bytes = [87, 75, 116, 51, 85, 113, 72, 105, 76, 83, 113, 75, 84, 49, 71, 101, 71, 88, 108, 78, 113, 102, 113, 87, 84, 65, 51, 55, 99, 56, 103, 69, 116, 105, 110, 109, 96, 113, 79, 106, 122, 68, 66, 98, 77, 72, 112, 72, 55, 53, 104, 54, 99, 71]
        # print(len(key_bytes))
        # with open(OUTPUT_FILE_PATH, 'w') as fhead:
        #     for ciphertext_bytes in list_of_ciphertext_bytes:
        #         plaintext = self._decrypt(ciphertext_bytes, key_bytes)
        #         fhead.write(plaintext + "\n")
        # return

        # solve using batches
        batch_size = 9
        number_of_batches = (number_of_positions//batch_size)

        key_bytes = []
        for batch_index in range(number_of_batches):
            start_time = time.time()

            start_index = (batch_index*batch_size)
            limit = (batch_index+1)*batch_size
            batch_key_bytes , batch_plaintexts, batch_scores  = self._batch_brute_force(start_index, [], list_of_ciphertext_bytes, list_of_candidate_key_bytes, limit, batch_size)

            for key_byte in batch_key_bytes:
                key_bytes.append(key_byte)

            end_time = time.time()
            execution_time = round(float(end_time - start_time), 4)

            if DEBUG:
                print(f"Batch           :   {batch_index}")
                print(f"Batch Time      :   {execution_time}s")
                print(f"Batch Scores    :   {batch_scores}")
                print(f"Batch Key Bytes :   {batch_key_bytes}")
                print(f"Batch Plaintexts:\n{batch_plaintexts}")
                print("------------------")

        print(key_bytes)

if __name__ == '__main__':

    many_time_pad = ManyTimePad(ALPHABET_FILE_PATH, DICTIONARY_FILE_PATH, OUTPUT_FILE_PATH)

    many_time_pad.encrypt(PLAINTEXT_FILE_PATH, KEY_FILE_PATH)
    many_time_pad.decrypt(CIPHERTEXT_FILE_PATH, KEY_FILE_PATH)

    many_time_pad.attack(LIST_OF_CIPHERTEXTS_FILE_PATH)
