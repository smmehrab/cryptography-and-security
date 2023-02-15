# ************************************************
# username  :   smmehrab
# fullname  :   s.m.mehrabul islam
# email     :   smmehrabul-2017614964@cs.du.ac.bd
# institute :   university of dhaka, bangladesh
# reg       :   2017614964
# ************************************************

import time

# Batch Size 6 = Around 8s
# Batch Size 7 = Around 12s (best outcome for the given ciphertexts)
# Batch Size 8 = Around 22s
# Batch Size 9 = Around 80s
# Batch Size 10 = Around 120s
# Batch Size 15 = Couldn't finish yet

DEBUG = True
HLINE = "___________________________________________\n"

class BatchBruteforce():

    def __init__(self, number_of_positions, list_of_candidate_key_bytes, list_of_ciphertext_bytes, dictionary, batch_size, decrypt) -> None:
        self._number_of_positions = number_of_positions
        self._list_of_ciphertext_bytes = list_of_ciphertext_bytes
        self._list_of_candidate_key_bytes = list_of_candidate_key_bytes
        self._batch_size = batch_size
        self._dictionary = dictionary
        self._number_of_batches = (self._number_of_positions//self._batch_size)
        self._decrypt = decrypt

    def _get_score(self, text):
        score = 0
        for word in self._dictionary:
            if word in text:
                score += (len(word)**2)
        return score

    def _bruteforce(self, index, batch_key_bytes, limit, start_index):
        # base case
        if index == limit:
            plaintexts = ""
            for ciphertext_bytes in self._list_of_ciphertext_bytes:
                batch_size_ciphertext_bytes = ciphertext_bytes[start_index:limit]
                plaintext = self._decrypt(batch_size_ciphertext_bytes, batch_key_bytes, ciphertext_bytes[start_index-1])
                plaintexts += plaintext
                plaintexts += "\n"
            plaintexts = plaintexts[:-1]
            plaintexts_lower = plaintexts.lower()
            score = self._get_score(plaintexts_lower)
            return batch_key_bytes, plaintexts, score
        # recurse
        best_key_bytes, best_plaintexts, best_score = None, None, 0
        for candidate_key_byte in self._list_of_candidate_key_bytes[index]:
            updated_key_bytes, plaintexts, score = self._bruteforce(index+1, batch_key_bytes+[candidate_key_byte], limit, start_index)
            if score > best_score:
                best_key_bytes, best_plaintexts, best_score = updated_key_bytes, plaintexts, score
        return best_key_bytes, best_plaintexts, best_score

    def start(self):
        print("[Executing ... ] Batch Brute Force")
        print(HLINE)

        key_bytes = []
        total_time = 0

        for batch_index in range(self._number_of_batches):
            batch_start_time = time.time()

            start_index = (batch_index*self._batch_size)
            limit = (batch_index+1)*self._batch_size
            batch_key_bytes , batch_plaintexts, batch_scores  = self._bruteforce(start_index, [], limit, start_index)

            for key_byte in batch_key_bytes:
                key_bytes.append(key_byte)

            batch_end_time = time.time()
            batch_execution_time = round(float(batch_end_time - batch_start_time), 4)
            total_time += batch_execution_time

            if DEBUG:
                print(f"Batch           :   {batch_index}")
                print(f"Batch Time      :   {batch_execution_time}s")
                print(f"Batch Scores    :   {batch_scores}")
                print(f"Batch Key Bytes :   {batch_key_bytes}")
                print(f"Batch Plaintexts:\n{batch_plaintexts}")
                print(HLINE)

        batch_start_time = time.time()

        start_index = (self._number_of_batches*self._batch_size)
        limit = self._number_of_positions
        batch_key_bytes , batch_plaintexts, batch_scores  = self._bruteforce(start_index, [], limit, start_index)

        for key_byte in batch_key_bytes:
            key_bytes.append(key_byte)

        batch_end_time = time.time()
        batch_execution_time = round(float(batch_end_time - batch_start_time), 4)
        total_time += batch_execution_time

        return key_bytes, total_time
