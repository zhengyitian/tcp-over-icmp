import socket



def create_socket():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.bind((srcip,srcport))
    except Exception as e:
        print('Socket could not be created.  Message: ' + e.message)
        return (False,'Socket could not be created.  Message: ' + e.message)
    
    return (True,s)

import socket,sys,struct,os
from ctypes import *

def checksum(msg):
    s = 0

    # loop taking 2 characters at a time
    for i in range(0, len(msg)-1, 2):
        w = ord(msg[i]) + (ord(msg[i+1]) << 8 )
        s = s + w

    s = (s>>16) + (s & 0xffff)
    s = s + (s >> 16)

    #complement and mask to 4 byte short
    s = ~s & 0xffff

    return s

def construct_ip_header(source_ip,dest_ip,ihl=5,ver=4,pid=0,offs=0,ttl=255,proto=socket.IPPROTO_TCP):
    ip_ihl = ihl
    ip_ver = ver
    ip_tos = 0
    ip_tot_len = 0  # kernel will fill the correct total length
    ip_id = pid   #Id of this packet
    ip_frag_off = offs
    ip_ttl = ttl
    ip_proto = proto
    ip_check = 0   # kernel will fill the correct checksum
    ip_saddr = socket.inet_aton ( source_ip )
    ip_daddr = socket.inet_aton ( dest_ip )

    ip_ihl_ver = (ip_ver << 4) + ip_ihl

    # the ! in the pack format string means network order
    ip_header = struct.pack('!BBHHHBBH4s4s' , ip_ihl_ver, ip_tos, ip_tot_len, ip_id, ip_frag_off, ip_ttl, ip_proto, ip_check, ip_saddr, ip_daddr)
    return ip_header

def construct_tcp_header(source_ip,dest_ip,srcp,dstp,seq,ackno,flags,user_data="",doff=5,wsize=5840,urgptr=0):
    tcp_source = srcp   # source port
    tcp_dest = dstp   # destination port
    tcp_seq = seq
    tcp_ack_seq = ackno
    tcp_doff = doff
    #tcp flags
    #flags=[HS,CWR,ECE,URG,ACK,PSH,RST,SYN,FIN]
    tcp_fin = flags[8]
    tcp_syn = flags[7]
    tcp_rst = flags[6]
    tcp_psh = flags[5]
    tcp_ack = flags[4]
    tcp_urg = flags[3]
    tcp_window = socket.htons(5840)    #   maximum allowed window size
    tcp_check = 0
    tcp_urg_ptr = urgptr

    tcp_offset_res = (tcp_doff << 4) + 0
    tcp_flags = tcp_fin + (tcp_syn << 1) + (tcp_rst << 2) + (tcp_psh <<3) + (tcp_ack << 4) + (tcp_urg << 5)

    # the ! in the pack format string means network order
    tcp_header = struct.pack('!HHLLBBHHH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window, tcp_check, tcp_urg_ptr)

    # pseudo header fields
    source_address = socket.inet_aton( source_ip )
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header) + len(user_data)

    psh = struct.pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length)
    psh = psh + tcp_header + user_data

    tcp_check = checksum(psh)

    # make the tcp header again and fill the correct checksum
    tcp_header = struct.pack('!HHLLBBH' , tcp_source, tcp_dest, tcp_seq, tcp_ack_seq, tcp_offset_res, tcp_flags,  tcp_window) + struct.pack('H' , tcp_check) + struct.pack('!H' , tcp_urg_ptr)
    return tcp_header

def construct_tcp_packet(ip_header,tcp_header,user_data=""):
    packet=''
    packet = ip_header + tcp_header + user_data
    return packet


latest_raw_buffer = ''
latest_tcp_header = ''
srcip   = "192.168.199.126"
#srcip   =  '124.120.36.165'
destip  = "154.92.15.210"
srcport = 12352
destport = 12233
def three_way_handshake(s):
    try:
        global latest_raw_buffer
        global latest_tcp_header
        srcip = '124.120.36.165'
        #send SYN
        iphead=construct_ip_header(srcip,destip)
        tcphead=construct_tcp_header(srcip,destip,srcport,destport,1,0,[0,0,0,0,0,0,0,1,0])
        tcppacket = construct_tcp_packet(iphead,tcphead)
        ret = s.sendto(tcppacket,(destip, destport))
        #receive ACK/SYN
        raw_buffer = s.recv(4096)
        latest_raw_buffer = raw_buffer
        ss = raw_buffer[24:28]
        import binascii
        print binascii.hexlify(ss)
        seq = struct.unpack('!L',ss)[0]
        print 'seq',seq
        for i in ss:
            print ord(i)
        


        #send ack package
        iphead=construct_ip_header(srcip,destip)
        tcphead=construct_tcp_header(srcip,destip,srcport,destport,2,seq + 1,[0,0,0,0,1,0,0,0,0],'aa')
        tcppacket = construct_tcp_packet(iphead,tcphead,'aa')
        ret = s.sendto(tcppacket,(destip, destport))
        
        #iphead=construct_ip_header(srcip,destip)
        #tcphead=construct_tcp_header(srcip,destip,srcport,destport,2,seq + 1,[0,0,0,0,1,0,0,0,0])
        #tcppacket = construct_tcp_packet(iphead,tcphead,'aaaaaaaa')
        #ret = s.sendto(tcppacket,(destip, destport))        


    except Exception as e:
        print('Three way handshake failed: '  + e.message)
        return (False,'Three way handshake failed: '  + e.message)
    
    return (True,s)
a,b = create_socket()
print a,b
three_way_handshake(b)