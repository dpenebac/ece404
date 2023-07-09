'''
Homework Number: 6
Name: Dorien Penebacker
ECN Login: dpenebac
Due Date: 02/28/2023
'''

import sys
from mult_inv import *
from PrimeGenerator import *
from BitVector import *
import math

'''
python3 rsa.py -g p.txt q.txt
python3 rsa.py -e message.txt p.txt q.txt encrypted.txt
python3 rsa.py -d encrypted.txt p.txt q.txt decrypted.txt
'''

e = 65537

def rsa_key_gen(p_txt, q_txt):

    generator = PrimeGenerator(bits = 128) # what to set this?
    p = 0
    q = 0

    while (p == q  and math.gcd(p,e) != 1 and math.gcd(q, e) != 1):
        p = generator.findPrime()
        q = generator.findPrime()

    # write to file
    p_out = open(p_txt, "w")
    q_out = open(q_txt, "w")

    p_out.write(str(p))
    q_out.write(str(q))

    p_out.close()
    q_out.close()

    return p, q

def rsa_encrypt(message_txt, p_txt, q_txt, encrypted_txt):

    message_file = open(message_txt)
    p_file = open(p_txt)
    q_file = open(q_txt)

    message = message_file.read()
    p = p_file.read()
    q = q_file.read()

    p = int(p)
    q = int(q)

    n = p * q
    totient = (p - 1) * (q - 1)
    
    d = MI(e, totient)

    # c = message ^ e % n

    cipher = BitVector(size=0)
    bv = BitVector(filename = message_txt)

    while (bv.more_to_read):
        bitvec = bv.read_bits_from_file(128)

        if bitvec._getsize() > 0:
            if bitvec._getsize() < 128:
                bitvec.pad_from_right(128 - bitvec._getsize())
            
            bitvec.pad_from_left(128)

            cipher += BitVector(intVal=pow(bitvec.int_val(), e, n), size=256) # bitvec ^ e % n

    FILEOUT = open(encrypted_txt, "w")
    FILEOUT.write(cipher.get_bitvector_in_hex())
    FILEOUT.close()

    return

def rsa_decrypt(encrypted_txt, p_txt, q_txt, decrypted_txt):

    encrypted_file = open(encrypted_txt)

    p_file = open(p_txt)
    q_file = open(q_txt)

    p = p_file.read()
    q = q_file.read()

    p = int(p)
    q = int(q)

    n = p * q
    totient = (p - 1) * (q - 1)
    
    d = MI(e, totient)

    plaintext = BitVector(size=0)
    bv = BitVector(hexstring=encrypted_file.read())

    for i in range(0, bv._getsize()//256):
        bitvec = bv[i*256:(i+1)*256]

        if bitvec._getsize() > 0:

            # Lecture 12.5 pg 36
            vp = pow(bitvec.int_val(), d, p)
            vq = pow(bitvec.int_val(), d, q)
            xp = q * (MI(q, p) % p)
            xq = p * (MI(p, q) % q)

            plaintext += BitVector(intVal=(vp * xp + vq * xq) % n, size=256)[128:] # remove padding
    
    FILEOUT = open(decrypted_txt, "w")
    FILEOUT.write(plaintext.get_text_from_bitvector())
    FILEOUT.close()
    return

def main():
    if (sys.argv[1] == "-g"):
        rsa_key_gen(sys.argv[2], sys.argv[3])
    elif (sys.argv[1] == "-e"):
        rsa_encrypt(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])
    elif (sys.argv[1] == "-d"):
        rsa_decrypt(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5])

    return

if __name__ == "__main__":
    main()