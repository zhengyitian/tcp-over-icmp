import struct
s = struct.pack('!L',8080)
for i in s:
    print ord(i)