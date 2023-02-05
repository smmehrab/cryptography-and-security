
# ************************************************
# username  :   smmehrab
# fullname  :   s.m.mehrabul islam
# email     :   smmehrabul-2017614964@cs.du.ac.bd
# institute :   university of dhaka, bangladesh
# reg       :   2017614964
# ************************************************

from BitVector import *

DEBUG = False

class KeyChecker():

    def __init__(self, ciphertext, passphrase, hint, blocksize) -> None:
        self._ciphertext = ciphertext
        self._passphrase = passphrase
        self._hint = hint
        self._blocksize = blocksize

        self._blockbytes = blocksize//8
        self._passphrase_block_count = len(self._passphrase)//self._blockbytes

        # passphrase to bitvector
        self._bv_iv = BitVector(bitlist = [0]*self._blocksize)
        for i in range(0, self._passphrase_block_count):
            textstr = self._passphrase[i*self._blockbytes:(i+1)*self._blockbytes]
            self._bv_iv ^= BitVector(textstring = textstr)

        # ciphertext to bitvector
        self._ciphertext_bv = BitVector(hexstring = self._ciphertext)
        self._ciphertext_block_count = len(self._ciphertext_bv)//self._blocksize

        if DEBUG:
            print("--------------------------------------------")
            print("[KEY CHECKER]")
            print(f"Ciphertext  :\n{self._ciphertext}")
            print("--------------------------------------------")
            print(f"Cipher BV   :     {self._ciphertext_block_count} Blocks")
            print(f"Cipher BV   :\n{self._ciphertext_bv}")
            print("--------------------------------------------")
            print(f"Passphrase  :     {self._passphrase}")
            print(f"Passphrase  :     {self._passphrase_block_count} Blocks")
            print(f"Hint        :     {self._hint}")
            print(f"Block Size  :     {self._blocksize}")
            print(f"Block Bytes :     {self._blockbytes}")

    def decrypt(self, key):

        # key to bitvector
        key_bv = BitVector(intVal = key, size=self._blocksize)

        # plaintext bit vector
        plaintext_bv = BitVector(size = 0)

        # differential XORing of bit blocks and decryption
        previous_decrypted_block = self._bv_iv
        for i in range(0, self._ciphertext_block_count):
            bv = self._ciphertext_bv[i*self._blocksize:(i+1)*self._blocksize]
            temp = bv.deep_copy()
            # XOR with previous block
            bv ^= previous_decrypted_block
            previous_decrypted_block = temp
            # XOR with key
            bv ^= key_bv
            # update plaintext bitvector
            plaintext_bv += bv

        # bitvector to plaintext
        plaintext = plaintext_bv.get_text_from_bitvector()
        key = key_bv.get_bitvector_in_ascii()
        if DEBUG:
            print(plaintext)
        return key, plaintext

    def check(self, key):
        key, plaintext = self.decrypt(key)
        validity = (plaintext.find(self._hint) != -1)
        return validity
