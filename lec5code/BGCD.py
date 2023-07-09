#!/usr/bin/env python

##  BGCD.py

import sys
if len(sys.argv) != 3:
    sys.exit("\nUsage:   %s  <integer>  <integer>\n" % sys.argv[0])

a,b = int(sys.argv[1]),int(sys.argv[2])

def bgcd(a,b):
    if a == b: return a                                         
    if a == 0: return b                                         
    if b == 0: return a                                         
    if (~a & 1): # a is even                                    
        if (b & 1): # b is odd                                
            return bgcd(a >> 1, b) # if a.even and b.odd : bgcd(a/2, b)            
        else:                                                   
            return bgcd(a >> 1, b >> 1) << 1 # if a.even and b.even : 2 * bgcd(a/2 , b/2)           
    if (~b & 1):                                              
        return bgcd(a, b >> 1) # if b.even and a.odd : bgcd(a, b / 2)                                
    if (a > b):                                                 
        return bgcd( (a-b) >> 1, b) # if a.even and b.even and a > b : bgcd((a-b)/2, b)                            
    return bgcd( (b-a) >> 1, a ) # if a.even and b.even and b > a : bgcd((b-a)/2, a)                              

gcdval = bgcd(a, b)
print("\nBGCD: %d\n" % gcdval)
