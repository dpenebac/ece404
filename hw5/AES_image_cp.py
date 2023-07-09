from AES import *

def ctr_aes_image(iv, image_file='image.ppm', out_file='enc_image.ppm', key_file='keyCTR.txt'):
    '''
    iv : 128 bit initialization vector
    image_file : 
    out_file :
    key_file : filename containing encryption key in ASCII

    Writes encryption to out file
    '''

    genTables()

    key_file = open(key_file)
    key_text = key_file.read()

    round_keys = gen_key_schedule(key_text) # gen key schedule from lecture code

    bv = BitVector(filename=image_file)
    round = 0

    output = BitVector(size=0)

    FILEOUT = open(out_file, 'wb')

    header_bv = BitVector(size = 0)
    while(header_bv.getTextFromBitVector().count('\n') < 3):
        header_bv += bv.read_bits_from_file(8) # read one char at a time
    #print(header_bv.getTextFromBitVector())
    header_bv.write_to_file(FILEOUT)

    while (bv.more_to_read):
        plaintext_bitvec = bv.read_bits_from_file(128) # read 128 bits at a time
        bitvec = iv
    
        # if not enough bits pad to the right to fill out 128 bit block with 0s
        if plaintext_bitvec._getsize() > 0:
            if (plaintext_bitvec._getsize() < 128):
                print(128 - plaintext_bitvec._getsize())
                plaintext_bitvec += BitVector(size = 128 - plaintext_bitvec._getsize())

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
                
            bitvec = bitvec.__xor__(plaintext_bitvec)
            
            iv_increment = iv.int_val() + 1   
            iv = BitVector(intVal=iv_increment, size=iv._getsize())

            bitvec.write_to_file(FILEOUT)

    FILEOUT.close()
    key_file.close()

    return