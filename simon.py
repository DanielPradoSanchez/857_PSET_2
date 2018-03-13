# Adapted from https://github.com/inmcm/Simon_Speck_Ciphers/blob/master/Python/SimonSpeckCiphers/simon/simon.py

from __future__ import print_function
from collections import deque

__author__ = 'inmcm'

table = [bin(i).count('1') for i in range(256)]


def ones(n):
    w = 0
    while n:
        w += table[n & 255]
        n >>= 8
    return w


class SimonCipher(object):
    """Simon Block Cipher Object"""

    # Z Arrays (stored bit reversed for easier usage)
    z0 = 0b01100111000011010100100010111110110011100001101010010001011111
    z1 = 0b01011010000110010011111011100010101101000011001001111101110001
    z2 = 0b11001101101001111110001000010100011001001011000000111011110101
    z3 = 0b11110000101100111001010001001000000111101001100011010111011011
    z4 = 0b11110111001001010011000011101000000100011011010110011110001011

    # valid cipher configurations stored:
    # block_size:{key_size:(number_rounds,z sequence)}
    __valid_setups = {32: {64: (32, z0)},
                      48: {72: (36, z0), 96: (36, z1)},
                      64: {96: (42, z2), 128: (44, z3)},
                      96: {96: (52, z2), 144: (54, z3)},
                      128: {128: (68, z2), 192: (69, z3), 256: (72, z4)}}

    __valid_modes = ['ECB', 'CTR', 'CBC', 'PCBC', 'CFB', 'OFB']

    def __init__(self, key, key_size=128, block_size=128, mode='ECB', init=0, counter=0):
        """
        Initialize an instance of the Simon block cipher.
        :param key: Int representation of the encryption key
        :param key_size: Int representing the encryption key in bits
        :param block_size: Int representing the block size in bits
        :param mode: String representing which cipher block mode the object should initialize with
        :param init: IV for CTR, CBC, PCBC, CFB, and OFB modes
        :param counter: Initial Counter value for CTR mode
        :return: None
        """
        print(bin(key))

        # Setup block/word size
        try:
            self.possible_setups = self.__valid_setups[block_size]
            self.block_size = block_size
            self.word_size = self.block_size >> 1
        except KeyError:
            print('Invalid block size!')
            print('Please use one of the following block sizes:',
                  [x for x in self.__valid_setups.keys()])
            raise

        # Setup Number of Rounds, Z Sequence, and Key Size
        try:
            self.rounds, self.zseq = self.possible_setups[key_size]
            self.key_size = key_size
        except KeyError:
            print('Invalid key size for selected block size!!')
            print('Please use one of the following key sizes:',
                  [x for x in self.possible_setups.keys()])
            raise

        # Create Properly Sized bit mask for truncating addition and left shift outputs
        self.mod_mask = (2 ** self.word_size) - 1

        # Parse the given iv and truncate it to the block length
        try:
            self.iv = init & ((2 ** self.block_size) - 1)
            self.iv_upper = self.iv >> self.word_size
            self.iv_lower = self.iv & self.mod_mask
        except (ValueError, TypeError):
            print('Invalid IV Value!')
            print('Please Provide IV as int')
            raise

        # Parse the given Counter and truncate it to the block length
        try:
            self.counter = counter & ((2 ** self.block_size) - 1)
        except (ValueError, TypeError):
            print('Invalid Counter Value!')
            print('Please Provide Counter as int')
            raise

        # Check Cipher Mode
        try:
            position = self.__valid_modes.index(mode)
            self.mode = self.__valid_modes[position]
        except ValueError:
            print('Invalid cipher mode!')
            print('Please use one of the following block cipher modes:',
                  self.__valid_modes)
            raise

        # Parse the given key and truncate it to the key length
        try:
            self.key = key & ((2 ** self.key_size) - 1)
        except (ValueError, TypeError):
            print('Invalid Key Value!')
            print('Please Provide Key as int')
            raise

        # Pre-compile key schedule
        m = self.key_size // self.word_size
        self.key_schedule = []

        # Create list of subwords from encryption key
        k_init = [((self.key >> (self.word_size * ((m-1) - x)))
                   & self.mod_mask) for x in range(m)]

        k_reg = deque(k_init)  # Use queue to manage key subwords

        round_constant = self.mod_mask ^ 3  # Round Constant is 0xFFFF..FC

        # Generate all round keys
        for x in range(self.rounds):

            rs_3 = ((k_reg[0] << (self.word_size - 3)) +
                    (k_reg[0] >> 3)) & self.mod_mask

            if m == 4:
                rs_3 = rs_3 ^ k_reg[2]

            rs_1 = ((rs_3 << (self.word_size - 1)) +
                    (rs_3 >> 1)) & self.mod_mask

            c_z = ((self.zseq >> (x % 62)) & 1) ^ round_constant

            new_k = c_z ^ rs_1 ^ rs_3 ^ k_reg[m - 1]

            self.key_schedule.append(k_reg.pop())
            k_reg.appendleft(new_k)
        print(bin(self.key_schedule[0]))
        print(bin(self.key_schedule[1]))

    def encrypt_round(self, x, y, k):
        """
        Complete One Feistel Round
        :param x: Upper bits of current plaintext
        :param y: Lower bits of current plaintext
        :param k: Round Key
        :return: Upper and Lower ciphertext segments
        """

        # Generate all circular shifts
        ls_1_x = ((x >> (self.word_size - 1)) + (x << 1)) & self.mod_mask
        ls_8_x = ((x >> (self.word_size - 8)) + (x << 8)) & self.mod_mask
        ls_2_x = ((x >> (self.word_size - 2)) + (x << 2)) & self.mod_mask

        # XOR Chain
        xor_1 = (ls_1_x & ls_8_x) ^ y
        xor_2 = xor_1 ^ ls_2_x
        new_x = k ^ xor_2

        return new_x, x

    def decrypt_round(self, x, y, k):
        """Complete One Inverse Feistel Round
        :param x: Upper bits of current ciphertext
        :param y: Lower bits of current ciphertext
        :param k: Round Key
        :return: Upper and Lower plaintext segments
        """

        # Generate all circular shifts
        ls_1_y = ((y >> (self.word_size - 1)) + (y << 1)) & self.mod_mask
        ls_8_y = ((y >> (self.word_size - 8)) + (y << 8)) & self.mod_mask
        ls_2_y = ((y >> (self.word_size - 2)) + (y << 2)) & self.mod_mask

        # Inverse XOR Chain
        xor_1 = k ^ x
        xor_2 = xor_1 ^ ls_2_y
        new_x = (ls_1_y & ls_8_y) ^ xor_2

        return y, new_x

    def encrypt(self, plaintext):
        """
        Process new plaintext into ciphertext based on current cipher object setup
        :param plaintext: Int representing value to encrypt
        :return: Int representing encrypted value
        """
        try:
            b = (plaintext >> self.word_size) & self.mod_mask
            a = plaintext & self.mod_mask
        except TypeError:
            print('Invalid plaintext!')
            print('Please provide plaintext as int')
            raise

        self.leak = 0

        if self.mode == 'ECB':
            b, a = self.encrypt_function(b, a)

        elif self.mode == 'CTR':
            true_counter = self.iv + self.counter
            d = (true_counter >> self.word_size) & self.mod_mask
            c = true_counter & self.mod_mask
            d, c = self.encrypt_function(d, c)
            b ^= d
            a ^= c
            self.counter += 1

        elif self.mode == 'CBC':
            b ^= self.iv_upper
            a ^= self.iv_lower
            b, a = self.encrypt_function(b, a)

            self.iv_upper = b
            self.iv_lower = a
            self.iv = (b << self.word_size) + a

        elif self.mode == 'PCBC':
            f, e = b, a
            b ^= self.iv_upper
            a ^= self.iv_lower
            b, a = self.encrypt_function(b, a)
            self.iv_upper = b ^ f
            self.iv_lower = a ^ e
            self.iv = (self.iv_upper << self.word_size) + self.iv_lower

        elif self.mode == 'CFB':
            d = self.iv_upper
            c = self.iv_lower
            d, c = self.encrypt_function(d, c)
            b ^= d
            a ^= c

            self.iv_upper = b
            self.iv_lower = a
            self.iv = (b << self.word_size) + a

        elif self.mode == 'OFB':
            d = self.iv_upper
            c = self.iv_lower
            d, c = self.encrypt_function(d, c)
            self.iv_upper = d
            self.iv_lower = c
            self.iv = (d << self.word_size) + c

            b ^= d
            a ^= c

        ciphertext = (b << self.word_size) + a

        return ciphertext, self.leak

    def decrypt(self, ciphertext):
        """
        Process new ciphertest into plaintext based on current cipher object setup
        :param ciphertext: Int representing value to encrypt
        :return: Int representing decrypted value
        """
        try:
            b = (ciphertext >> self.word_size) & self.mod_mask
            a = ciphertext & self.mod_mask
        except TypeError:
            print('Invalid ciphertext!')
            print('Please provide ciphertext as int')
            raise

        if self.mode == 'ECB':
            a, b = self.decrypt_function(a, b)

        elif self.mode == 'CTR':
            true_counter = self.iv + self.counter
            d = (true_counter >> self.word_size) & self.mod_mask
            c = true_counter & self.mod_mask
            d, c = self.encrypt_function(d, c)
            b ^= d
            a ^= c
            self.counter += 1

        elif self.mode == 'CBC':
            f, e = b, a
            a, b = self.decrypt_function(a, b)
            b ^= self.iv_upper
            a ^= self.iv_lower

            self.iv_upper = f
            self.iv_lower = e
            self.iv = (f << self.word_size) + e

        elif self.mode == 'PCBC':
            f, e = b, a
            a, b = self.decrypt_function(a, b)
            b ^= self.iv_upper
            a ^= self.iv_lower
            self.iv_upper = (b ^ f)
            self.iv_lower = (a ^ e)
            self.iv = (self.iv_upper << self.word_size) + self.iv_lower

        elif self.mode == 'CFB':
            d = self.iv_upper
            c = self.iv_lower
            self.iv_upper = b
            self.iv_lower = a
            self.iv = (b << self.word_size) + a
            d, c = self.encrypt_function(d, c)
            b ^= d
            a ^= c

        elif self.mode == 'OFB':
            d = self.iv_upper
            c = self.iv_lower
            d, c = self.encrypt_function(d, c)
            self.iv_upper = d
            self.iv_lower = c
            self.iv = (d << self.word_size) + c

            b ^= d
            a ^= c

        plaintext = (b << self.word_size) + a

        return plaintext

    def encrypt_function(self, upper_word, lower_word):
        """
        Completes appropriate number of Simon Fiestel function to encrypt provided words
        Round number is based off of number of elements in key schedule
        upper_word: int of upper bytes of plaintext input 
                    limited by word size of currently configured cipher
        lower_word: int of lower bytes of plaintext input 
                    limited by word size of currently configured cipher
        x,y:        int of Upper and Lower ciphertext words            
        """
        x = upper_word
        y = lower_word

        # Run Encryption Steps For Appropriate Number of Rounds
        for k in self.key_schedule:
             # Generate all circular shifts
            ls_1_x = ((x >> (self.word_size - 1)) + (x << 1)) & self.mod_mask
            ls_8_x = ((x >> (self.word_size - 8)) + (x << 8)) & self.mod_mask
            ls_2_x = ((x >> (self.word_size - 2)) + (x << 2)) & self.mod_mask

            # XOR Chain
            xor_1 = (ls_1_x & ls_8_x) ^ y
            xor_2 = xor_1 ^ ls_2_x
            y = x
            x = k ^ xor_2

            self.leak += ones(x) + ones(y)

        return x, y

    def decrypt_function(self, upper_word, lower_word):
        """
        Completes appropriate number of Simon Fiestel function to decrypt provided words
        Round number is based off of number of elements in key schedule
        upper_word: int of upper bytes of ciphertext input 
                    limited by word size of currently configured cipher
        lower_word: int of lower bytes of ciphertext input 
                    limited by word size of currently configured cipher
        x,y:        int of Upper and Lower plaintext words            
        """
        x = upper_word
        y = lower_word

        # Run Encryption Steps For Appropriate Number of Rounds
        for k in reversed(self.key_schedule):
             # Generate all circular shifts
            ls_1_x = ((x >> (self.word_size - 1)) + (x << 1)) & self.mod_mask
            ls_8_x = ((x >> (self.word_size - 8)) + (x << 8)) & self.mod_mask
            ls_2_x = ((x >> (self.word_size - 2)) + (x << 2)) & self.mod_mask

            # XOR Chain
            xor_1 = (ls_1_x & ls_8_x) ^ y
            xor_2 = xor_1 ^ ls_2_x
            y = x
            x = k ^ xor_2

        return x, y

    def update_iv(self, new_iv):
        if new_iv:
            try:
                self.iv = new_iv & ((2 ** self.block_size) - 1)
                self.iv_upper = self.iv >> self.word_size
                self.iv_lower = self.iv & self.mod_mask
            except TypeError:
                print('Invalid Initialization Vector!')
                print('Please provide IV as int')
                raise
        return self.iv

def increment_by_one(hex_input):
    return hex(int(hex_input, 16)+1)

def flip(value):
    if value == '1':
        return '0'
    return '1'

def flip_next_one(key, index):
    new_key = key[:index] + flip(key[index]) + key[index+1:]
    return new_key

def get_ones_offset(plaintext, ones, simon_cipher):
    return abs(simon_cipher.encrypt(plaintext)[1] - ones)

def get_closest_key(plaintext_to_ones, start_key = None):
    if start_key is None:
        start_binary = bin(0)[2:].zfill(128)
        closest = bin(0)[2:].zfill(128)
        closest_ones = None
        current_key = start_binary
    else:
        start_binary = start_key
        closest = start_key
        closest_ones = None
        current_key = start_binary

    #target = 128*68/2
    key_input_to_ones = {}
    for index in range(128):
        print(index, current_key)
        new_inputs = {}
        current_keys = (current_key, flip_next_one(current_key, index))
        key_to_offsets = {}
        closest_average_one = None
        closest_key = None
        for key in current_keys:
            w = SimonCipher(int(key,2), key_size=128, block_size=64)
            for plaintext in plaintext_to_ones:
                if (key, plaintext) in key_input_to_ones:
                    current_ones = key_input_to_ones[(key, plaintext)]
                    new_inputs[(key, plaintext)] = current_ones
                else:
                    _, current_ones = w.encrypt(plaintext)
                    new_inputs[(key, plaintext)] = current_ones
                key_to_offsets.setdefault(key, []).append(abs(plaintext_to_ones[plaintext] - current_ones))
            average_one = sum(key_to_offsets[key])/len(key_to_offsets[key])
            if closest_average_one is None or closest_average_one > average_one:
                closest_key = key
                closest_average_one = average_one

        key_input_to_ones = new_inputs
        current_key = closest_key
    return current_key

def parse_data_into_plaintext_to_ones(data):
    plaintext_to_ones = {}
    for plaintext, ones in data:
        plaintext_to_ones[plaintext] = ones
    return plaintext_to_ones

def verify_key(key, plaintext_to_ones):
    max_offset = 0
    min_offset = float("inf")
    w = SimonCipher(int(key,2))
    all_ones = []
    wrong = 0
    for plaintext in plaintext_to_ones:
        _, current_ones = w.encrypt(plaintext)
        
        offset = abs(current_ones - plaintext_to_ones[plaintext])
        if offset != 0:
            wrong += 1
        all_ones.append(offset)
        if offset > max_offset:
            max_offset = offset
        if offset < min_offset:
            min_offset = offset
    average_ones = sum(all_ones)/len(all_ones)
    
    return max_offset, min_offset, average_ones, wrong/len(all_ones)


if __name__ == "__main__":
    
    with open("./data_1.txt", 'r') as data1:
        plaintext_to_ones1 = parse_data_into_plaintext_to_ones(eval(data1.read()))

    with open("./data_2.txt", 'r') as data2:
        plaintext_to_ones2 = parse_data_into_plaintext_to_ones(eval(data2.read()))

    with open("./data_3.txt", 'r') as data3:
        plaintext_to_ones3 = parse_data_into_plaintext_to_ones(eval(data3.read()))

    with open("./data_4.txt", 'r') as data4:
        plaintext_to_ones4 = parse_data_into_plaintext_to_ones(eval(data4.read()))

    with open("./data_5.txt", 'r') as data5:
        plaintext_to_ones5 = parse_data_into_plaintext_to_ones(eval(data5.read()))

    # with open("./data_6.txt", 'r') as data6:
    #     plaintext_to_ones6 = parse_data_into_plaintext_to_ones(eval(data6.read()))

    # with open("./data_7.txt", 'r') as data7:
    #     plaintext_to_ones7 = parse_data_into_plaintext_to_ones(eval(data7.read()))

    # with open("./data_8.txt", 'r') as data8:
    #     plaintext_to_ones8 = parse_data_into_plaintext_to_ones(eval(data8.read()))

    # with open("./data_9.txt", 'r') as data9:
    #     plaintext_to_ones9 = parse_data_into_plaintext_to_ones(eval(data9.read()))

    # #plaintext_to_ones = plaintext_to_ones1

    plaintext_to_ones = {**plaintext_to_ones1, **plaintext_to_ones2, 
                        **plaintext_to_ones3, **plaintext_to_ones4, 
                        **plaintext_to_ones5}#, **plaintext_to_ones6,
    #                     **plaintext_to_ones7, **plaintext_to_ones8,
    #                     **plaintext_to_ones9}
    
    #key = str(get_closest_key(plaintext_to_ones))#, start_key='010100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'))

    # key = 00100000000000000000000000000000101000000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000 # (396, 0, 74.1489)
    #key = '00100000000000000000000000000000001000000010000000000000000000000010000000000000000000000000000000000000000000000010000000000000'
    #print(key)
    

    # key = '010100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    # key = '000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000'
    
    # this key is pretty close!
    # key = '01010100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    # offsets               - (max,  min)
    # min key offsets       - (3241, 2603)
    # max key offsets       - (3205, 2680)
    # average key offsets   - (3246, 2666)
    # average key = '010000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000'
    #print(verify_key(key, plaintext_to_ones))
    











