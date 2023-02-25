# ************************************************
# username  :   smmehrab
# fullname  :   s.m.mehrabul islam
# email     :   smmehrabul-2017614964@cs.du.ac.bd
# institute :   university of dhaka, bangladesh
# reg       :   2017614964
# ************************************************

from BitVector import *

from des_config import TMP_FILE_PATH
from des_config import key_permutation_1
from des_config import key_permutation_2
from des_config import shifts_for_round_key_gen
from des_config import ip
from des_config import ip_inverse
from des_config import expansion_permutation
from des_config import s_boxes
from des_config import p_box

class DES:
    """
        Data Encryption Standard (DES)
        - Operation Mode: ECB (Electronic Code Book)
        - All internal states handled using BitVector
    """

    def __init__(self) -> None:
        pass

    def _generate_round_keys(self, key):
        """
            Generate 16 Round Keys
            from a 56 bit Key
        """
        round_keys = []
        for round_count in range(16):
            [L, R] = key.divide_into_two()
            shift = shifts_for_round_key_gen[round_count]
            L <<= shift
            R <<= shift
            key = L + R
            round_key = key.permute(key_permutation_2)
            round_keys.append(round_key)
        return round_keys

    def _sbox_substitute(self, expanded_half_block):
        '''
            S-box Substitution
            48 bit              --> 32 bit
            expanded_half_block --> half_block
        '''
        half_block = BitVector(size = 32)
        segments = [expanded_half_block[(i*6):(i*6)+6] for i in range(8)]
        number_of_segments = len(segments)
        for sindex in range(number_of_segments):
            row = ((segments[sindex][0] << 1) + segments[sindex][-1])
            column = int(segments[sindex][1:-1])
            half_block[(sindex*4):(sindex*4)+4] = BitVector(intVal = s_boxes[sindex][row][column], size = 4)
        return half_block
    
    def _padding(self, block):
        block_bits_count = block.length()%64
        if block_bits_count != 0:
            padding_bits_count = 64-block_bits_count
            block.pad_from_right(padding_bits_count)
        return block

    def _fiestel(self, block, round_keys, encryption):
        """
            Fiestel Circuit
        """
        [L, R] = block.divide_into_two()
        for i in range(16):
            NEXT_L = R
            # Expansion
            EXPANDED_R = R.permute(expansion_permutation)
            # XOR with Round Key
            round_key_index = i if encryption else 15-i
            EXPANDED_R = EXPANDED_R ^ round_keys[round_key_index]
            # S-box Substitution
            R = self._sbox_substitute(EXPANDED_R)
            # P-box Permutation
            R = R.permute(p_box)
            # Update R, L
            R = L ^ R
            L = NEXT_L
        # Block Processed
        block = R + L
        return block

    def apply(self, input_raw, key_ascii, encryption=True):
        """
            Encrypt/Decrypt Applying DES
        """
        output = ""

        # Key
        key = BitVector(textstring=key_ascii)
        key = key.permute(key_permutation_1) # 64 bit --> 56 bit
        round_keys = self._generate_round_keys(key)

        # Input to BitVector
        if encryption:
            input_bv = BitVector(textstring=input_raw)
        else:
            input_bv = BitVector(hexstring=input_raw)

        # Iterate Input By Blocks
        total_bits = len(input_bv)
        bit_index = 0
        while bit_index<total_bits:
            # block
            block = input_bv[bit_index:min((bit_index+64), total_bits)]
            bit_index += 64
            block = self._padding(block)
            # ip
            block = block.permute(ip)
            # fiestel
            block = self._fiestel(block, round_keys, encryption)
            # ip inverse
            block = block.permute(ip_inverse)
            # output
            if encryption:
                output += block.get_bitvector_in_hex()
            else:
                output += block.get_bitvector_in_ascii()

        return output

    def apply_on_image(self, input_img_path, key_ascii, output_img_path, encryption=True):
        """
            Encrypt/Decrypt Image Applying DES
        """

        # Input Init
        with open(input_img_path, 'rb') as input_img_file:
            magic = input_img_file.readline()
            dimension = input_img_file.readline()
            maxval = input_img_file.readline()
            input_img_raw = input_img_file.read()

        with open(TMP_FILE_PATH, 'wb') as input_img_file:
            input_img_file.write(input_img_raw)

        # Output Init
        OUTPUT = open(output_img_path, "wb")
        OUTPUT.write(magic)
        OUTPUT.write(dimension)
        OUTPUT.write(maxval)

        # Key
        key = BitVector(textstring=key_ascii)
        key = key.permute(key_permutation_1) # 64 bit --> 56 bit
        round_keys = self._generate_round_keys(key)

        # Input Image to BitVector
        input_bv = BitVector(filename=TMP_FILE_PATH)

        # Iterate Input By Blocks
        while input_bv.more_to_read:
            # block
            block = input_bv.read_bits_from_file(64)
            block = self._padding(block)
            # ip
            block = block.permute(ip)
            # fiestel
            block = self._fiestel(block, round_keys, encryption)
            # ip inverse
            block = block.permute(ip_inverse)
            # output
            block.write_to_file(OUTPUT)

        OUTPUT.close()

