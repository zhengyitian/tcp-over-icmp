import os, sys, socket, struct, select, time

ICMP_ECHO_REQUEST = 0 # Seems to be the same on Solaris.
#ICMP_ECHO_REQUEST = 8 # Seems to be the same on Solaris.
def my_decry(da):
    r = (ord(da[1])+17)/13+(ord(da[3])+19)/17+(ord(da[9])+23)/19+(ord(da[10])+17)/13+(ord(da[30])+19)/17+(ord(da[90])+23)/19
    r2 = (ord(da[11])+17)/13+(ord(da[31])+19)/17+(ord(da[91])+23)/19+(ord(da[12])+17)/13+(ord(da[32])+19)/17+(ord(da[92])+23)/19
    return chr(r %251)+chr(r2 % 249)

def checksum(source_string):
    sum = 0
    countTo = (len(source_string)/2)*2
    count = 0
    while count<countTo:
        thisVal = ord(source_string[count + 1])*256 + ord(source_string[count])
        sum = sum + thisVal
        sum = sum & 0xffffffff # Necessary?
        count = count + 2

    if countTo<len(source_string):
        sum = sum + ord(source_string[len(source_string) - 1])
        sum = sum & 0xffffffff # Necessary?

    sum = (sum >> 16)  +  (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

import binascii
dest_addr2 = '144.202.17.72'
icmp = socket.getprotobyname("icmp")
so = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)

def sendOne(add,pacId):
    dest_addr  =  socket.gethostbyname(add)
    my_checksum = 0
    ID =  100 & 0xFFFF
    header = struct.pack("bbHHh", 8, 0, my_checksum, ID, 1)
    da = 190 * 'a'
    da2 = my_decry(da)
    data = da+da2
 
    my_checksum = checksum(header + data)

    header = struct.pack(
        "bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), ID, 1
    )
    packet = header + data
    so.sendto(packet, (dest_addr, 1)) # Don't know about the 1


def rec():
    whatReady = select.select([so], [], [], 4)
    if whatReady[0] == []: # Timeout
        print 'timeout'
        return
    rp, addr = so.recvfrom(1024)
    recPacket = rp
    print recPacket,addr
    if ord(rp[9])!=1 :
        return    
    icmpHeader = recPacket[20:28]
    type, code, checksum, packetID, sequence = struct.unpack(
        "bbHHh", icmpHeader
    )
    #if packetID != 100 & 0xFFFF :
        #print 'wrong_1 ',packetID
        #return
    if len(recPacket) <28+192:
        print('len_wrong')
        return
    s = recPacket[28:28+192]
    if my_decry(s[:190]) != s[-2:]:
        print('decry_wrong')
        return
    
    if ord(rp[9])!=1 or ord(rp[20])!=8:
        print('not_ 8')
        return

    s = ''
    co = 0
    for i in recPacket:
        if co <30 : print co,':',ord(i)
        co += 1
        s += str(ord(i))+','
    sendOne(addr[0],packetID)
    return

while True:
    rec()

def receive_one_ping(my_socket, ID, timeout):
    timeLeft = timeout
    while True:
        startedSelect = time.time()
        whatReady = select.select([my_socket], [], [], timeLeft)
        howLongInSelect = (time.time() - startedSelect)
        if whatReady[0] == []: # Timeout
            return
        timeReceived = time.time()
        recPacket, addr = my_socket.recvfrom(1024)
        print recPacket
        s = ''
        co = 0
        for i in recPacket:
            if co <30 : print co,':',ord(i)
            co += 1
            s += str(ord(i))+','
        return

        if 'QQQ' in recPacket:
            i9 = 9
            print recPacket
            s = ''
            co = 0
            for i in recPacket:
                if co <30 : print co,':',ord(i)
                co += 1
                s += str(ord(i))+','
            print s
        icmpHeader = recPacket[20:28]
        type, code, checksum, packetID, sequence = struct.unpack(
            "bbHHh", icmpHeader
        )
        if packetID == ID:
            bytesInDouble = struct.calcsize("d")
            timeSent = struct.unpack("d", recPacket[28:28 + bytesInDouble])[0]
            return timeReceived - timeSent

        timeLeft = timeLeft - howLongInSelect
        if timeLeft <= 0:
            return


def send_one_ping(my_socket, dest_addr, ID):
    dest_addr  =  socket.gethostbyname(dest_addr)
    my_checksum = 0

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, my_checksum, ID, 1)
    bytesInDouble = struct.calcsize("d")
    data = (192 - bytesInDouble) * "Q"
    data = struct.pack("d", time.time()) + data

    my_checksum = checksum(header + data)

    header = struct.pack(
        "bbHHh", ICMP_ECHO_REQUEST, 0, socket.htons(my_checksum), ID, 1
    )
    packet = header + data
    #for i in packet:

        #print ord(i)
    my_socket.sendto(packet, (dest_addr, 1)) # Don't know about the 1


def do_one(dest_addr, timeout):
    icmp = socket.getprotobyname("icmp")
    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    except socket.error, (errno, msg):
        if errno == 1:
            msg = msg + (
                " - Note that ICMP messages can only be sent from processes"
                " running as root."
            )
            raise socket.error(msg)
        raise # raise the original error

    my_ID = os.getpid() & 0xFFFF
    my_ID = 100 & 0xFFFF
    try:
        send_one_ping(my_socket, dest_addr, my_ID)
    except:
        print("error")
    delay = time.time() 
    delay = receive_one_ping(my_socket, my_ID, timeout)

    my_socket.close()
    return delay


def verbose_ping(dest_addr, timeout = 2, count = 4):
    for i in xrange(count):
        print "ping %s..." % dest_addr,
        try:
            delay  =  do_one(dest_addr, timeout)
        except socket.gaierror, e:
            print "failed. (socket error: '%s')" % e[1]
            break

        if delay  ==  None:
            print "failed. (timeout within %ssec.)" % timeout
        else:
            delay  =  delay * 1000
            print "get ping in %0.4fms" % delay
    print

def dodo(a):
    while True:
        t = do_one(a,2)
        print(t)

def do_one2(dest_addr, timeout):
    icmp = socket.getprotobyname("icmp")
    try:
        my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    except socket.error, (errno, msg):
        if errno == 1:
            msg = msg + (
                " - Note that ICMP messages can only be sent from processes"
                " running as root."
            )
            raise socket.error(msg)
        raise # raise the original error

    my_ID = 100
    while True:
        delay = receive_one_ping(my_socket, my_ID, timeout)
        print delay

    my_socket.close()
    return delay


if __name__ == '__main__':
    do_one2("192.168.2.2", 20)
    #verbose_ping("heise.de")
    #verbose_ping("192.168.100.1")
    #verbose_ping("192.168.2.2")
    #verbose_ping("baidu.com")
    #dodo("192.168.199.160")
    #verbose_ping("a-test-url-taht-is-not-available.com")
    #verbose_ping("192.168.199.1")
