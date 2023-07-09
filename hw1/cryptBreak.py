import sys
from BitVector import *

'''
Homework Number: 1
Name: Dorien Penebacker
ECN Login: dpenebac
Due Date: 01/19/2023
'''

def cryptBreak(ciphertextFile, key_bv):

    # Code below is used from DecryptForFun.py with small changes 
    #   BLOCKSIZE which is set to 16
    #   FILEIN = open(ciphertextFile) instead of open(argv[1])
    #   Key Input from user is removed

    PassPhrase = "Hopes and dreams of a million years"                          

    BLOCKSIZE = 16 # set to 16 for hw 1                                                          
    numbytes = BLOCKSIZE // 8  

    bv_iv = BitVector(bitlist = [0]*BLOCKSIZE)                                  
    for i in range(0,len(PassPhrase) // numbytes):                              
        textstr = PassPhrase[i*numbytes:(i+1)*numbytes]                         
        bv_iv ^= BitVector( textstring = textstr )                              

    FILEIN = open(ciphertextFile)                                               
    encrypted_bv = BitVector( hexstring = FILEIN.read() )                       

    msg_decrypted_bv = BitVector( size = 0 )                                    

    previous_decrypted_block = bv_iv                                            
    for i in range(0, len(encrypted_bv) // BLOCKSIZE):                          
        bv = encrypted_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE]                          
        temp = bv.deep_copy()                                                   
        bv ^=  previous_decrypted_block                                         
        previous_decrypted_block = temp                                         
        bv ^=  key_bv                                                           
        msg_decrypted_bv += bv                                                  
 
    outputtext = msg_decrypted_bv.get_text_from_bitvector()                     
    
    return outputtext

def test():
    i = 0
    while (i < 2 ** 16):
        key_bv = BitVector(intVal=i, size=16)
        decrypted_message = cryptBreak('ciphertext.txt', key_bv)
        if 'Sir Lewis' in decrypted_message:
            print(decrypted_message)
            print(key_bv.int_val())
            quit()
        #print(decrypted_message)
        print(key_bv.int_val())
        i = i + 1

if __name__ == '__main__':
    test()