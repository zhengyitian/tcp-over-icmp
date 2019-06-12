import socket,json
def mf():
    f = open('/root/a.txt','wb')
    f.write('a'*1024*1024*100)
    f.close()
mf()    
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('127.0.0.1', 9999))
print('Bind UDP on 9999...')
while True:
    data, addr = s.recvfrom(1024)
    m = json.loads(data)
    sta = m['s']
    l = m['l']
    f = open('/root/a.txt','rb')
    f.seek(sta)
    s2 = f.read(l)
    f.close()   
    s.sendto(s2, addr)
