import cryptBreak
from BitVector import *
key_bv = BitVector(intVal=123, size=16)
d = cryptBreak.cryptBreak('output.txt', key_bv)
print(d)