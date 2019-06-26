
import os, sys, socket, struct, select, time

ICMP_ECHO_REQUEST = 8 # Seems to be the same on Solaris.
import binascii
def inpre(st):
    print '#########'
    for i in st:
        print ord(i)
def receive_one_ping():
    icmp = socket.getprotobyname("tcp")
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    
    while True:
        whatReady = select.select([my_socket], [], [], 0.01)
        if whatReady[0] == []: # Timeout
            continue
        recPacket, addr = my_socket.recvfrom(1024)
        #123.120.36.165
        dd = chr(123)+chr(120)+chr(36)+chr(165)
        tcp_header = struct.pack('!LL' , 7765, 7756)
        if dd in recPacket and tcp_header in recPacket:
            inpre(recPacket)
        icmpHeader = recPacket[20:28]
        type, code, checksum, packetID, sequence = struct.unpack(
            "bbHHh", icmpHeader
        )
receive_one_ping()