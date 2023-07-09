from AES import *

def x931(v0, dt, totalNum, key_file):
    '''
    v0 : 128 bit Bitvector object containing seed value
    dt : 128 bit Bitvector object symbolizing data and time

    totalNum : total number of random numbers to generate
    key_file : filename for text file containing the ascii encryption key for AES

    Returns a list of BitVector objects, where each BitVector object represents a random number
    generated
    '''

    genTables()

    rand_num_list = []

    for i in range(totalNum):
        dt_encrypted = aes_encrypt_x931(dt, key_file)
        rand_num = aes_encrypt_x931(dt_encrypted.__xor__(v0), key_file)
        rand_num_list.append(rand_num)
        v0 = aes_encrypt_x931(rand_num.__xor__(dt_encrypted), key_file)

    return rand_num_list

def aes_encrypt_x931(bv, key_path):
    #print('encrypt')

    key_file = open(key_path)
    key_text = key_file.read()

    round_keys = gen_key_schedule(key_text) # gen key schedule from lecture code
    round = 0

    output = BitVector(size=0)

    if bv._getsize() < 128:
        bv += BitVector(size = 128 - bv._getsize())

    # round logic
    round = 0
    while (round < 15):
        if (round == 0): # add roundkey step only on first round
            bv = add_roundkey(bv, round_keys[0])
            round += 1

        bv = subbytes(bv) # Sub bytes step
        bv = shiftrows(bv) # Shift Rows step

        if (round != 14): # dont do mix columns on last step
            bv = mixcolumns(bv) # Mix Columns step

        bv = add_roundkey(bv, round_keys[round]) # Add round key
        
        round = round + 1 # increment round

    return bv