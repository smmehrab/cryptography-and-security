# ************************************************
# username  :   smmehrab
# fullname  :   s.m.mehrabul islam
# email     :   smmehrabul-2017614964@cs.du.ac.bd
# institute :   university of dhaka, bangladesh
# reg       :   2017614964
# ************************************************

from BitVector import *

DEBUG = True
HLINE = "___________________________________________\n"

class RC4:
    """
        RC4
        - All internal states handled using BitVector
    """

    def __init__(self) -> None:
        pass

    def _initialize_state_vector(self, key_ascii):
        """
            State Vector - S
        """

        # key ascii to key ascii code
        key_length = len(key_ascii)
        key = []
        for c in key_ascii:
            key.append(ord(c))

        # Initialization
        S = [0]*256
        T = [0]*256
        for i in range(256):
            S[i] = i
            T[i] = key[i%key_length]

        # Initial Permutation
        j = 0
        for i in range(256):
            j = (j + S[i] + T[i]) % 256
            S[i], S[j] = S[j], S[i]

        return S

    def _exec_stream_cipher(self, input_bv, S, OUTPUT):
        """
            Stream Processing
            --------------------------------------------------------
            1. iterate through the input byte-by-byte
            2. encrypt or decrypt using byte size key stream
            --------------------------------------------------------
        """

        if DEBUG:
            print("[Stream Processing]")
            print(HLINE)

        total_bits = len(input_bv)
        byte_index = 0
        bit_index = 0

        i, j = 0, 0
        while bit_index<total_bits:

            # key stream
            i = (i+1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            t = (S[i] + S[j]) % 256
            k = S[t]
            k_bv = BitVector(intVal = k, size = 8)

            # input byte
            input_byte_bv = input_bv[bit_index:bit_index+8]

            if DEBUG:
                print(f"\r[{byte_index}] {input_byte_bv}", end="")

            byte_index += 1
            bit_index += 8

            # encryption/decryption
            output_byte_bv = input_byte_bv ^ k_bv

            # output
            output_byte_bv.write_to_file(OUTPUT)
        
        if DEBUG:
            print("")
            print(HLINE)
            print("[RC4 Successfully Applied]")
            print(HLINE)


    def apply(self, input_file_path, output_file_path, key_ascii):

        """
            Apply RC4 Encryption/Decryption
        """

        # Input Load
        with open(input_file_path, "rb") as input_file:
            meta_data = input_file.read(44)
            raw_data = input_file.read()
            input_bv = BitVector(rawbytes = raw_data)

        # Output Init
        OUTPUT = open(output_file_path, "wb")
        OUTPUT.write(meta_data)

        # RC4
        S = self._initialize_state_vector(key_ascii)
        self._exec_stream_cipher(input_bv, S, OUTPUT)

        return
