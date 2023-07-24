# ************************************************
# username  :   smmehrab
# fullname  :   s.m.mehrabul islam
# email     :   smmehrabul-2017614964@cs.du.ac.bd
# institute :   university of dhaka, bangladesh
# reg       :   2017614964
# ************************************************

import re, csv, time
from vigenere import Vigenere

REGEX = '[^A-Za-z]'

CIPHERTEXT_FILE_PATH = "./data/c.txt"
FREQUENCY_TABLE_FILE_PATH = "./data/frequency_table.csv"

DECRYPTED_PLAINTTEXT_FILE_PATH = "./output/decrypted_plaintext.txt"
PREDICTED_KEY_FILE_PATH = "./output/predicted_key.txt"
PREDICTED_PLAINTEXT_FILE_PATH = "./output/predicted_plaintext.txt"

MAX_KEYWORD_LENGTH = 100
FREQUENCY_MULTIPLIER = 100

class Kasiski:

    def __init__(self) -> None:
        pass

    def _get_text(self, path):
        with open(path, 'r') as file:
            data = file.read().rstrip()
        return re.sub(REGEX, '',  data)

    def _to_code(self, character):
        if ord(character) < 91:
            return ord(character)-ord('A')+26
        return ord(character)-ord('a')

    def _to_character(self, code):
        code %= 52
        if code >= 26:
            return chr(code+ord('A')-26)
        return chr(code+ord('a'))

    def _report(self, keyword_length, keyword, key_accuracy, plaintext_accuracy, execution_time):
        print("------------------------------------------------")
        print("[Report]")
        print(f"Keyword Length          :   {keyword_length}")
        print(f"Keyword                 :   {keyword}")
        print(f"Accuracy (key)          :   {key_accuracy}%")
        print(f"Accuracy (plaintext)    :   {plaintext_accuracy}%")
        print(f"Execution Time          :   {execution_time}s")
        print()
        print(f"[OUTPUT SAVED]")
        print(f"Predicted Keyword Path  :   {PREDICTED_KEY_FILE_PATH}")
        print(f"Predicted Plaintext Path:   {PREDICTED_PLAINTEXT_FILE_PATH}")
        print("------------------------------------------------")

    def _get_frequency(self, sequence):
        n = len(sequence)
        frequencies = []
        for i in range(52):
            multiplied_relative_frequency = FREQUENCY_MULTIPLIER*sequence.count(self._to_character(i))/n
            frequencies.append(multiplied_relative_frequency)
        return frequencies

    def _get_frequency_table(self):
        with open(FREQUENCY_TABLE_FILE_PATH, mode='r') as fhead:
            reader = csv.reader(fhead)
            f = {rows[0]:rows[1] for rows in reader}
        frequency_table = []
        for i in range(52):
            frequency_table.append(float(f.get(self._to_character(i))))
        return frequency_table

    def find_keyword_length(self, cipher):
        cipher_len = len(cipher)

        # count coincidences
        coincidences = []
        for shift in range(1, MAX_KEYWORD_LENGTH):
            coincidence = 0
            limit = cipher_len-shift
            for i in range(limit):
                if cipher[i] == cipher[i+shift]:
                    coincidence += 1
            coincidences.append(coincidence)

        # DEBUG

        # print(coincidences)
        avg_coincidence = sum(coincidences)/len(coincidences)
        range_coincidence = max(coincidences) - min(coincidences)
        std_coincidence = float(range_coincidence/4)
        threshold = (2*std_coincidence)
        # print(avg_coincidence)
        # print(range_coincidence)
        # print(std_coincidence)

        # find gap between spikes
        keyword_length = 0
        previous_spike = -1
        for index, coincidence in enumerate(coincidences):
            deviation = coincidence-avg_coincidence
            if deviation >= threshold:
                if previous_spike==-1:
                    previous_spike = index
                else:
                    keyword_length = (index-previous_spike)
                    return keyword_length
        # spike = False
        # for i in range(len(coincidences)-1):
        #     if spike == True:
        #         if coincidences[i+1]/coincidences[i]<2:
        #             keyword_length+=1
        #         else:
        #             keyword_length += 1
        #             return keyword_length
        #     else:
        #         if coincidences[i+1]/coincidences[i]>=2:
        #                 spike = True
        return 0

    def find_keyword(self, ciphertext, keyword_length):

        frequency_table = self._get_frequency_table()
        ciphertext_len = len(ciphertext)
        mono_sequences = []

        # generate all monoalphabetic sequences
        for shift in range(keyword_length):
            mono_sequence = ""
            for i in range(shift, ciphertext_len, keyword_length):
                mono_sequence += ciphertext[i]
            mono_sequences.append(mono_sequence)

        # get key letter for all monoalphabetic sequences
        keyword = ""
        for mono_sequence in mono_sequences:
            mono_frequency = self._get_frequency(mono_sequence)
            found = False
            threshold = 5
            for shift in range(52):
                found = True
                for i in range(52):
                    frequency = mono_frequency[(shift+i)%52]
                    standard_frequency = frequency_table[i]
                    if abs(standard_frequency-frequency)>=threshold:
                        found = False
                        break
                if found == True:
                    keyword += self._to_character(shift)
                    break

            if found == False:
                keyword += "?"

        return keyword

    def attack(self, ciphertext_file_path):
        start_time = time.time()

        ciphertext = self._get_text(ciphertext_file_path)

        keyword_length = self.find_keyword_length(ciphertext)
        keyword = self.find_keyword(ciphertext, keyword_length)

        with open(PREDICTED_KEY_FILE_PATH, "w") as fhead:
            fhead.write(keyword)

        vigenere = Vigenere()
        predicted_plaintext = vigenere.decrypt(ciphertext_file_path, PREDICTED_KEY_FILE_PATH, PREDICTED_PLAINTEXT_FILE_PATH, False)
        key_accuracy = vigenere.get_key_accuracy(PREDICTED_KEY_FILE_PATH)
        plaintext_accuracy = vigenere.get_plaintext_accuracy(PREDICTED_PLAINTEXT_FILE_PATH)

        end_time = time.time()
        execution_time = round(float(end_time - start_time), 4)
        self._report(keyword_length, keyword, key_accuracy, plaintext_accuracy, execution_time)

if __name__ == '__main__':

    kasiski = Kasiski()
    kasiski.attack(CIPHERTEXT_FILE_PATH)
