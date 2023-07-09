import sys
from BitVector import *

# python3 AES.py -e message.txt key.txt encrypted.txt
# python3 AES.py -d encrypted.txt key.txt decrypted.txt

'''
Homework Number: 4
Name: Dorien Penebacker
ECN Login: dpenebac
Due Date: 2/14/2023
'''

# from gen_tables.py
subBytesTable = []                                                  # for encryption
invSubBytesTable = []                                               # for decryption

AES_modulus = BitVector(bitstring='100011011')

def genTables():
    c = BitVector(bitstring='01100011')
    d = BitVector(bitstring='00000101')
    for i in range(0, 256):
        # For the encryption SBox
        a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        # For bit scrambling for the encryption SBox entries:
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
        # For the decryption Sbox:
        b = BitVector(intVal = i, size=8)
        # For bit scrambling for the decryption SBox entries:
        b1,b2,b3 = [b.deep_copy() for x in range(3)]
        b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
        check = b.gf_MI(AES_modulus, 8)
        b = check if isinstance(check, BitVector) else 0
        invSubBytesTable.append(int(b))

# from gen_key_schedule.py

def gen_key_schedule(key):
    key_words = []
    keysize, key_bv = gen_key_from_key(key)
    key_words = gen_key_schedule_256(key_bv)
    key_schedule = []
    #print("\nEach 32-bit word of the key schedule is shown as a sequence of 4 one-byte integers:")
    for word_index,word in enumerate(key_words):
        keyword_in_ints = []
        for i in range(4):
            keyword_in_ints.append(word[i*8:i*8+8].intValue())
        key_schedule.append(keyword_in_ints)
    num_rounds = None
    if keysize == 128: num_rounds = 10
    if keysize == 192: num_rounds = 12
    if keysize == 256: num_rounds = 14
    round_keys = [None for i in range(num_rounds+1)]
    for i in range(num_rounds+1):
        round_keys[i] = (key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] + 
                                                       key_words[i*4+3]).get_bitvector_in_hex()
    #print("\n\nRound keys in hex (first key for input block):\n")
    #for round_key in round_keys:
    #    print(round_key)
    
    return(round_keys)

def gee(keyword, round_constant, byte_sub_table):
    '''
    This is the g() function you see in Figure 4 of Lecture 8.
    '''
    rotated_word = keyword.deep_copy()
    rotated_word << 8
    newword = BitVector(size = 0)
    for i in range(4):
        newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
    newword[:8] ^= round_constant
    round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), AES_modulus, 8)
    return newword, round_constant

def gen_key_schedule_256(key_bv):
    byte_sub_table = gen_subbytes_table()
    #  We need 60 keywords (each keyword consists of 32 bits) in the key schedule for
    #  256 bit AES. The 256-bit AES uses the first four keywords to xor the input
    #  block with.  Subsequently, each of the 14 rounds uses 4 keywords from the key
    #  schedule. We will store all 60 keywords in the following list:
    key_words = [None for i in range(60)]
    round_constant = BitVector(intVal = 0x01, size=8)
    for i in range(8):
        key_words[i] = key_bv[i*32 : i*32 + 32]
    for i in range(8,60):
        if i%8 == 0:
            kwd, round_constant = gee(key_words[i-1], round_constant, byte_sub_table)
            key_words[i] = key_words[i-8] ^ kwd
        elif (i - (i//8)*8) < 4:
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        elif (i - (i//8)*8) == 4:
            key_words[i] = BitVector(size = 0)
            for j in range(4):
                key_words[i] += BitVector(intVal = 
                                 byte_sub_table[key_words[i-1][8*j:8*j+8].intValue()], size = 8)
            key_words[i] ^= key_words[i-8] 
        elif ((i - (i//8)*8) > 4) and ((i - (i//8)*8) < 8):
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        else:
            sys.exit("error in key scheduling algo for i = %d" % i)
    return key_words

def gen_subbytes_table():
    subBytesTable = []
    c = BitVector(bitstring='01100011')
    for i in range(0, 256):
        a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
    return subBytesTable

def gen_key_from_key(key):
    key = key
    keysize = 256
    key = key.strip()
    key += '0' * (keysize//8 - len(key)) if len(key) < keysize//8 else key[:keysize//8]  
    key_bv = BitVector( textstring = key )
    return keysize,key_bv


'''
XOR round key with input bitvector then returns the XORed 
bitvector
'''
def add_roundkey(bitvec, round_key):
    round_key_bv = BitVector(hexstring=round_key) # should be 128 bits

    bitvec = bitvec.__xor__(round_key_bv)
    #print(bitvec.get_hex_string_from_bitvector())

    return bitvec

'''
Subbytes function using the generated tables from lecture code
Returns bitvector output
'''
def subbytes(bitvec):

    output = BitVector(size=0)

    i = 0
    while (i != 128):
        # Calculates each row and column index based on the first and second half of each byte in the bitvector
        row = bitvec[i:i+4]
        column = bitvec[i+4:i+8]

        s_val = int(subBytesTable[int(row) * 16 + int(column)]) # use the row and column to grab the sub bytes table value using indexing 
        # it is row * 16 + column because we know the table will be 16x16

        output += BitVector(intVal=s_val, size=8)
        i += 8

    #print(output.get_hex_string_from_bitvector())
    return output

'''
Helper functions for shiftrows and invshift rows functions
to convert a bitvector to a statearray and back using
list indexing given in lecture code
'''
def bitvec_to_statearray(bitvec):

    statearray = [[0 for x in range(4)] for x in range(4)]

    for i in range(4):
        for j in range(4):
            statearray[j][i] = bitvec[32*i + 8*j:32*i + 8*(j+1)]

    return statearray

def statearray_to_bitvec(statearray):

    output = BitVector(size=0)
    for i in range(4):
        for j in range(4):
            output += statearray[j][i]

    return output


'''
Uses statearray format and logic given in lecture slides
to return new bitvector with shifted logic

First row == First row
Second row == Second Row << 8 (1 byte)
Third Row == Third Row << 16 (2 bytes)
Fourth Row == Fourth Row << 24 (3 bytes)
'''
def shiftrows(bitvec):

    output_state_array = [[0 for x in range(4)] for x in range(4)]

    statearray = bitvec_to_statearray(bitvec) # convert bitvector to statearray
    
    temp = BitVector(size=0)
    for i in range(4): # for each row in index
        for j in range(4): # for each column in index
            temp += statearray[i][j] # build entire row 'temp' value

        # i is the row so we know how many to shift
        if i == 0:
            temp = temp
        elif i == 1:
            temp = temp << 8
        elif i == 2:
           temp = temp << 16
        elif i == 3:
            temp = temp << 24

        # rebuilding the row array using the temp value
        for j in range(4): # for each column for specified row i
            output_state_array[i][j] = temp[8*j:8*(j+1)] # assign the specific temp indexed to the new output state array

        temp = BitVector(size=0)

    output = statearray_to_bitvec(output_state_array) # convert back to bitvector
    #print(output.get_hex_string_from_bitvector())

    return output

'''
Mix columns is basic algebra but in modulus format from lecture slides
Instead of using state arrays I used the bivector because each 'byte' is next
to each other instead of +4 away like it would've been in statearray

For each group of 4 bytes (32 bits)
4bytes == byte1, byte2, byte3, byte4

logic from lecture
for every byte x
    bytex = bytex * 2 xor bytex+1 * 3 xor bytex+2 xor bytex+3

where x + y is circular and goes back if it exceeds 1
'''

def mixcolumns(bitvec):

    output = BitVector(size=0)

    i = 0
    while (i < 128):
        # grabbing each byte
        byte1 = bitvec[i:i+8]
        byte2 = bitvec[i+8:i+16]
        byte3 = bitvec[i+16:i+24]
        byte4 = bitvec[i+24:i+32]

        # print(byte1, byte2, byte3, byte4, i)

        two = BitVector(bitstring='00000010') # setting bitvector values for 2 and 3
        three = BitVector(bitstring='00000011')

        # calculating new bytes based on logic shown above
        new1 = byte1.gf_multiply_modular(two, AES_modulus, 8).__xor__(byte2.gf_multiply_modular(three, AES_modulus, 8)).__xor__(byte3).__xor__(byte4)
        new2 = byte2.gf_multiply_modular(two, AES_modulus, 8).__xor__(byte3.gf_multiply_modular(three, AES_modulus, 8)).__xor__(byte4).__xor__(byte1)
        new3 = byte3.gf_multiply_modular(two, AES_modulus, 8).__xor__(byte4.gf_multiply_modular(three, AES_modulus, 8)).__xor__(byte1).__xor__(byte2)
        new4 = byte4.gf_multiply_modular(two, AES_modulus, 8).__xor__(byte1.gf_multiply_modular(three, AES_modulus, 8)).__xor__(byte2).__xor__(byte3)

        # append to output
        output += new1
        output += new2
        output += new3
        output += new4

        i += 32

    #print(output.get_hex_string_from_bitvector())
    return output

'''
Main encryption function which takes in 3 file paths and outputs to the last path
Uses main logic from lecture which is described below

256 bit key (14 rounds)
Last round does not use mix column rows
Word == 32 bits

Gen Round Keys (use helper function)
Add round key (first round only)

SubBytes
Shift Row
Mix Column (don't do on last iteration)
Add Round Key
'''
def aes_encrypt(plaintext_path, key_path, output_path):
    #print('encrypt')

    key_file = open(key_path)
    key_text = key_file.read()

    round_keys = gen_key_schedule(key_text) # gen key schedule from lecture code

    bv = BitVector(filename=plaintext_path)
    round = 0

    output = BitVector(size=0)

    while (bv.more_to_read):
        bitvec = bv.read_bits_from_file(128) # read 128 bits at a time

        # if not enough bits pad to the right to fill out 128 bit block with 0s
        if bitvec._getsize() > 0:
            if (bitvec._getsize() < 128):
                bitvec += BitVector(size = 128 - bitvec._getsize())

            # round logic
            round = 0
            while (round < 15):
                if (round == 0): # add roundkey step only on first round
                    bitvec = add_roundkey(bitvec, round_keys[0])
                    round += 1

                bitvec = subbytes(bitvec) # Sub bytes step
                bitvec = shiftrows(bitvec) # Shift Rows step

                if (round != 14): # dont do mix columns on last step
                    bitvec = mixcolumns(bitvec) # Mix Columns step

                bitvec = add_roundkey(bitvec, round_keys[round]) # Add round key
                
                round = round + 1 # increment round
                
            output += bitvec # append to output bitvector after round logic is finished

    FILEOUT = open(output_path, 'w')
    FILEOUT.write(output.get_hex_string_from_bitvector())
    FILEOUT.close()
    key_file.close()

    return

'''
Same as subbytes except uses the inversesubbytes table instead of subbytes table
'''
def invsubbytes(bitvec):

    output = BitVector(size=0)

    i = 0
    while (i != 128):
        # needs to be read from right to left
        row = bitvec[i:i+4]
        column = bitvec[i+4:i+8]

        s_val = int(invSubBytesTable[int(row) * 16 + int(column)])

        output += BitVector(intVal=s_val, size=8)
        i += 8

    #print(output.get_hex_string_from_bitvector())
    return output

'''
Same as shift rows but whenever shift left you shift right instead
'''
def invshiftrows(bitvec):

    output_state_array = [[0 for x in range(4)] for x in range(4)]

    statearray = bitvec_to_statearray(bitvec)
    
    temp = BitVector(size=0)
    for i in range(4):
        for j in range(4):
            temp += statearray[i][j]

        if i == 0:
            temp = temp
        elif i == 1:
            temp = temp >> 8
        elif i == 2:
           temp = temp >> 16
        elif i == 3:
            temp = temp >> 24

        for j in range(4):
            output_state_array[i][j] = temp[8*j:8*(j+1)]

        temp = BitVector(size=0)

    output = statearray_to_bitvec(output_state_array)
    #print(output.get_hex_string_from_bitvector())

    return output

'''
Same as mixcolumns except the mathematical logic has changed

logic from lecture
for every byte x
    bytex = bytex * 14 xor bytex+1 * 11 xor bytex+2 * 13 xor bytex+3 * 9
'''
def invmixcolumns(bitvec):

    output = BitVector(size=0)

    i = 0
    while (i < 128):
        byte1 = bitvec[i:i+8]
        byte2 = bitvec[i+8:i+16]
        byte3 = bitvec[i+16:i+24]
        byte4 = bitvec[i+24:i+32]

        # print(byte1, byte2, byte3, byte4, i)

        nine = BitVector(bitstring='000001001')
        eleven = BitVector(bitstring='00001011') # B
        thirteen = BitVector(bitstring='00001101') # D
        fourteen = BitVector(bitstring='00001110') # E
        # E B D 9

        new1 = byte1.gf_multiply_modular(fourteen, AES_modulus, 8).__xor__(byte2.gf_multiply_modular(eleven, AES_modulus, 8)).__xor__(byte3.gf_multiply_modular(thirteen, AES_modulus, 8)).__xor__(byte4.gf_multiply_modular(nine, AES_modulus, 8))
        new2 = byte2.gf_multiply_modular(fourteen, AES_modulus, 8).__xor__(byte3.gf_multiply_modular(eleven, AES_modulus, 8)).__xor__(byte4.gf_multiply_modular(thirteen, AES_modulus, 8)).__xor__(byte1.gf_multiply_modular(nine, AES_modulus, 8))
        new3 = byte3.gf_multiply_modular(fourteen, AES_modulus, 8).__xor__(byte4.gf_multiply_modular(eleven, AES_modulus, 8)).__xor__(byte1.gf_multiply_modular(thirteen, AES_modulus, 8)).__xor__(byte2.gf_multiply_modular(nine, AES_modulus, 8))
        new4 = byte4.gf_multiply_modular(fourteen, AES_modulus, 8).__xor__(byte1.gf_multiply_modular(eleven, AES_modulus, 8)).__xor__(byte2.gf_multiply_modular(thirteen, AES_modulus, 8)).__xor__(byte3.gf_multiply_modular(nine, AES_modulus, 8))

        output += new1
        output += new2
        output += new3
        output += new4

        i += 32

    #print(output.get_hex_string_from_bitvector())
    return output


'''
Main decryption algorithm which is the same as encryption except for the order of steps
Uses a reversed round key as well

256 bit key (14 rounds)
Last round does not use mix column rows

Gen Round Key (use helper function)

Inv Shift Row
Inv Sbox Substitution
Add Round Key
Inv Mix Column
'''
def aes_decrypt(ciphertext_path, key_path, output_path):
    #print('decrypt')

    key_file = open(key_path)
    key_text = key_file.read()

    round_keys = gen_key_schedule(key_text)

    ciphertext_file = open(ciphertext_path)
    bv = BitVector(hexstring=ciphertext_file.read()) # need to read into hexstring

    round = 0

    output = BitVector(size=0)

    for i in range(0, bv._getsize()//128): # should only run x == len // 128 times
        bitvec = bv[i*128:(i+1)*128] # read the first 128 bits based on iteration

        if bitvec._getsize() > 0: # do not need to pad as it should be even 128 bits
            round = 14
            while (round >= 0):
                if (round == 14): # 'first' round add roundkey
                    bitvec = add_roundkey(bitvec, round_keys[round])
                    round -= 1
                
                bitvec = invshiftrows(bitvec) # inv Shift Rows step
                bitvec = invsubbytes(bitvec) # inv Sub bytes step
                bitvec = add_roundkey(bitvec, round_keys[round]) # Add round key

                if (round != 0): # 'last' round do not do inverse mix columns
                    bitvec = invmixcolumns(bitvec) # inv Mix Columns step

                round = round - 1
                
            output += bitvec

    FILEOUT = open(output_path, 'w')
    FILEOUT.write(output.get_text_from_bitvector())
    FILEOUT.close()
    key_file.close()

    return

def main():
    #for i in range(0, (len(sys.argv))):
    #    print(i, sys.argv[i])

    genTables()

    if (sys.argv[1] == "-e"):
        aes_encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
    elif (sys.argv[1] == "-d"):
        aes_decrypt(sys.argv[2], sys.argv[3], sys.argv[4])

    return

if __name__ == "__main__":
    main()