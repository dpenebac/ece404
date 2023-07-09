#!/usr/bin/env python
'''
Homework Number: 3
Name: Dorien Penebacker
ECN Login: dpenebac
Due Date: 2/2/2023
'''

# from lecture code
# edits made to replace multiplication and division with ones researched referenced below

from copy import *

import sys
if len(sys.argv) != 3:
    sys.exit("\nUsage:   %s  <integer>  <integer>\n" % sys.argv[0])

a,b = int(sys.argv[1]),int(sys.argv[2])

def MI(num, mod):
    '''
    This function uses ordinary integer arithmetic implementation of the
    Extended Euclid's Algorithm to find the MI of the first-arg integer
    vis-a-vis the second-arg integer.
    '''
    NUM = num; MOD = mod
    x, x_old = 0, 1
    y, y_old = 1, 0
    while mod:
        q = division(num, mod)
        num, mod = mod, num % mod
        x, x_old = x_old - multiply2(q, x), x
        y, y_old = y_old - multiply2(q, y), y
    if num != 1:
        print("\nNO MI. However, the GCD of %d and %d is %u\n" % (NUM, MOD, num))
    else:
        MI = (x_old + MOD) % MOD
        print("\nMI of %d modulo %d is: %d\n" % (NUM, MOD, MI))

# https://www.geeksforgeeks.org/multiplication-two-numbers-shift-operator/

def multiply2(a, b):
    # need to check if it is negative to negate it at the end
    negA = False
    negB = False

    # we negate if it is negative using twos complement
    if (a < 0):
        a = ~a + 1
        negA = True
    if (b < 0):
        b = ~b + 1
        negB = True

    # if b[0] is set, then we increment out by a
    # we then shift a by 1 to check the next power of 2
    # then do this for all the bits of b by checking
    out = 0
    while (b):
        if (b & 1): # checks if lsb is set
            out += a # increase output by a
        a = a << 1 # multiply a by 2
        b = b >> 1 # divide b by 2
    
    # if one of the inputs were negative need to re negate using twos complement
    if (negA or negB):
        out = ~out + 1
    
    return out

# https://www.prodevelopertutorial.com/divide-two-integers-without-using-multiplication-division-and-mod-operator/

'''
Main alogrithm
a is dividend 
b is divisor

1. Check if a >= b
2. shift b << 2 (multiply b by 2)
3. if b <= a, goto 2
4. Multiply out by however many times b was shifted
5. Decrement a by the current shifted value of b
6. goto 1
'''

def division(a, b):
    out = 0
    # need to check if it is negative to negate it at the end

    negA = False
    negB = False
    if (a < 0):
        negA = True
    if (b < 0):
        negB = True

    # use abs function to revert negation
    a = abs(a)
    b = abs(b)
    
    # formula described above
    while (a >= b):
        t = b
        c = 1
        while (t <= a):
            t = t << 1
            c = c << 1
        out = out + (c >> 1)
        a = a - (t >> 1)
    
    # re negate back if negative
    if (negA or negB):
        sign = -1
    else:
        sign = 1
        
    return multiply2(out, sign)

c = MI(a, b)
print(c)