from simon import SimonCipher
from simon import ones

def resolve_first_round_key_average(plaintext_to_ones):
    start_key = '0'*64
    current_key = start_key
    simon = SimonCipher(0)
    for index in range(len(start_key)):
        print(index, current_key)
        zero_bucket = []
        for plaintext in plaintext_to_ones:
            # Take plaintext and run through one level of encryption with 
            # a key of all zeros. This allows us to get ct2 (which is just
            # the left bits) and the pre-xored ct1 (ct1 but has not been
            # xored with a key yet, we pass in a key of zeros so the xor 
            # does nothing). We then append the number of ones for this 
            # plaintext to the zero bucket only if the pre-xored ct1 at
            # the current index is zero
            ones_for_plaintext = plaintext_to_ones[plaintext]
            plaintext_binary = str(bin(plaintext))[2:].zfill(128)
            right = plaintext_binary[len(plaintext_binary)//2:].zfill(64)
            left = plaintext_binary[:len(plaintext_binary)//2].zfill(64)
            ct1, ct2 = simon.encrypt_round(int(left,2), int(right,2), 0)
            pre_xor_bin = bin(ct1)[2:].zfill(64)
            value = pre_xor_bin[index]
            if value == '0':
                zero_bucket.append(ones_for_plaintext)
        # flip the current entry to 1 if this threshold is met
        # this threshold is derived from (68*128-1)/2 (total number of bits
        # minus the bit we are fixing in this scenario, we then divide by 2).
        # This gives us the expected number of ones for all of the other bits
        # We then consider the case where we set the bit of the key at this 
        # index to 1. This can be modeled similar to part a where we either have
        # t regular coin flips or t regular coin flips + 1. So now, if we want to know
        # whether or not we have the t/2 or t/2+1 scenario, we set our threshold to be
        # in between these two distributions (i.e. t/2 + 0.5)
        zero_bucket_average = sum(zero_bucket)/max(len(zero_bucket),1)
        if zero_bucket_average >= 8703/2+.5:
            current_key = flip_next_one(current_key, index)
    return current_key

def resolve_second_round_key_average(plaintext_to_ones, first_round_key):
    start_key = '0'*64
    simon = SimonCipher(0)

    current_key = start_key
    for index in range(len(start_key)):
        vote = 0
        print(index, current_key)
        zero_bucket = []
        for plaintext in plaintext_to_ones:
            # Take plaintext and run through one level of encryption given
            # the first round key. This allows us to use the same process we 
            # used for finding the first round key to get the next round key
            ones_for_plaintext = plaintext_to_ones[plaintext]
            plaintext_binary = str(bin(plaintext))[2:].zfill(128)
            right = plaintext_binary[len(plaintext_binary)//2:].zfill(64)
            left = plaintext_binary[:len(plaintext_binary)//2].zfill(64)
            binary_left = int(left, 2)
            binary_right = int(right, 2)
            first_round_ct1, first_round_ct2 = simon.encrypt_round(int(left,2), int(right,2), int(first_round_key, 2))

            # do same process as outlined in getting first round key
            next_round_ct1, _ = simon.encrypt_round(first_round_ct1, first_round_ct2, 0)
            pre_xor_bin = bin(next_round_ct1)[2:].zfill(64)
            pre_xor_ones = ones(int(pre_xor_bin, 2))
            value = pre_xor_bin[index]
            if value == '0':
                zero_bucket.append(ones_for_plaintext)
        zero_bucket_average = sum(zero_bucket)/max(len(zero_bucket),1)
        if zero_bucket_average >= 8703/2+.5:
            current_key = flip_next_one(current_key, index)
    return current_key

def flip(value):
    if value == '1':
        return '0'
    return '1'

def flip_next_one(key, index):
    new_key = key[:index] + flip(key[index]) + key[index+1:]
    return new_key

def parse_data_into_plaintext_to_ones(data):
    plaintext_to_ones = {}
    for plaintext, ones in data:
        plaintext_to_ones[plaintext] = ones
    return plaintext_to_ones

def verify_key(key, plaintext_to_ones):
    w = SimonCipher(int(key,2))
    wrong = 0
    for plaintext in plaintext_to_ones:
        _, current_ones = w.encrypt(plaintext)
        offset = abs(current_ones - plaintext_to_ones[plaintext])
        if offset != 0:
            wrong += 1
    return wrong

if __name__ == "__main__":
    # each file has 10000 pairs
    plaintext_to_ones_list = []
    with open("./data_1.txt", 'r') as data1:
        plaintext_to_ones_list += eval(data1.read())

    with open("./data_2.txt", 'r') as data2:
        plaintext_to_ones_list += eval(data2.read())

    with open("./data_3.txt", 'r') as data3:
        plaintext_to_ones_list += eval(data3.read())

    with open("./data_4.txt", 'r') as data4:
        plaintext_to_ones_list += eval(data4.read())

    with open("./data_5.txt", 'r') as data5:
        plaintext_to_ones_list += eval(data5.read())

    plaintext_to_ones = parse_data_into_plaintext_to_ones(plaintext_to_ones_list)
    round_key_1 = resolve_first_round_key_average(plaintext_to_ones)
    round_key_2 = resolve_second_round_key_average(plaintext_to_ones, round_key_1)
    master_key = round_key_2 + round_key_1
    print("verified", verify_key(master_key, plaintext_to_ones))


