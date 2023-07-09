'''
Homework Number: 6
Name: Dorien Penebacker
ECN Login: dpenebac
Due Date: 02/28/2023
'''

import sys
import solve_pRoot
import sys
from mult_inv import *
from PrimeGenerator import *
from BitVector import *
import math

# python3 breakRSA.py -e message.txt enc1.txt enc2.txt enc3.txt n_1_2_3.txt
# python3 breakRSA.py -c enc1.txt enc2.txt enc3.txt n_1_2_3.txt cracked.txt

e = 3

def rsa_key_gen():

    generator = PrimeGenerator(bits = 128) # what to set this?
    p = 0
    q = 0

    while (p == q  and math.gcd(p,e) != 1 and math.gcd(q, e) != 1):
        p = generator.findPrime()
        q = generator.findPrime()

    return p, q

def rsa_encrypt(message_txt, p, q, encrypted_txt):

    message_file = open(message_txt)

    message = message_file.read()

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

def breakRSA_encrypt(message_txt, enc1_txt, enc2_txt, enc3_txt, n_1_2_3_txt):

    message_file = open(message_txt)

    p1,q1, = rsa_key_gen()
    p2,q2, = rsa_key_gen()
    p3,q3, = rsa_key_gen()

    n1 = p1 * q1
    n2 = p2 * q2
    n3 = p3 * q3

    totient1 = (p1 - 1) * (q1 - 1)
    totient2 = (p2 - 1) * (q2 - 1)
    totient3 = (p3 - 1) * (q3 - 1)
    
    d1 = MI(e, totient1)
    d2 = MI(e, totient2)
    d3 = MI(e, totient3)

    rsa_encrypt(message_txt, p1, q1, enc1_txt)
    rsa_encrypt(message_txt, p2, q2, enc2_txt)
    rsa_encrypt(message_txt, p3, q3, enc3_txt)

    FILEOUT = open(n_1_2_3_txt, "w")
    FILEOUT.write(str(n1))
    FILEOUT.write("\n")
    FILEOUT.write(str(n2))
    FILEOUT.write("\n")
    FILEOUT.write(str(n3))
    FILEOUT.write("\n")

    return

def breakRSA_crack(enc1_txt, enc2_txt, enc3_txt, n_1_2_3_txt, cracked_txt):

    FILEIN = open(n_1_2_3_txt)
    n1 = FILEIN.readline()
    n2 = FILEIN.readline()
    n3 = FILEIN.readline()

    n1 = int(n1)
    n2 = int(n2)
    n3 = int(n3)

    N = n1 * n2 * n3 # lecture 12

    N1 = n2 * n3
    N2 = n1 * n3
    N3 = n1 * n2

    # ci = Ni * (MI(Ni) mod ni)
    c1 = N1 * (MI(N1, n1))
    c2 = N2 * (MI(N2, n2))
    c3 = N3 * (MI(N3, n3))
    
    enc1_file = open(enc1_txt)
    enc2_file = open(enc2_txt)
    enc3_file = open(enc3_txt)

    bv1 = BitVector(hexstring=enc1_file.read())
    bv2 = BitVector(hexstring=enc2_file.read())
    bv3 = BitVector(hexstring=enc3_file.read())

    output = BitVector(size=0)

    for i in range(0, bv1._getsize()//256):
        bitvec1 = bv1[i*256:(i+1)*256]
        bitvec2 = bv2[i*256:(i+1)*256]
        bitvec3 = bv3[i*256:(i+1)*256]

        if bitvec1._getsize() > 0:

            # a = m^3 = sum(ai * ci) mod M
            a = (c1 * bitvec1.int_val() + c2 * bitvec2.int_val() + c3 * bitvec3.int_val()) % N
            m = solve_pRoot.solve_pRoot(3, a)

            output += BitVector(intVal=m, size=256)[128:]
            
    FILEOUT = open(cracked_txt, "w")
    FILEOUT.write(output.get_text_from_bitvector())
    FILEOUT.close()

    return

def main():
    if (sys.argv[1] == "-e"):
        breakRSA_encrypt(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])
    elif (sys.argv[1] == "-c"):
        breakRSA_crack(sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6])

    return

if __name__ == "__main__":
    main()