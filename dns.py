#https://www.ietf.org/rfc/rfc1035.txt
#Resolve-DnsName url -Server 127.0.0.1

import socket
import glob
import json

port =53

ip = "127.0.0.1"

sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)

dom =''
sock.bind((ip,port))

def load_zones():
    jsonzone={}
    zonefiles = glob.glob("zones/*.zone")
    
    for zone in zonefiles:
        with open(zone) as zonedata:
            data = json.load(zonedata)
            zonename = data["$origin"]
            jsonzone[zonename] = data
            
    return jsonzone

zonedata = load_zones()


def getflags(flags):
    byte1 = bytes(flags[:1])
    byte2 = bytes(flags[1:2])
    
    rflags=""
    QR ="1"
    OPCODE =""
    for bit in range(1,5):
        OPCODE += str(ord(byte1)&(1<<bit))
        
    AA ="1" #authoritative answer
    TC ="0" #truncate
    RD="0" # recursion desired
    RA = "0" # recursion available
    Z ="000" # 3 reserved bits
    RCODE ="0000" # response code
    
    response = int(QR+OPCODE+AA+TC+RD,2).to_bytes(1,byteorder='big')+int(RA+Z+RCODE,2).to_bytes(1,byteorder='big')
    
    return response
        
def getquestiondomain(data):
    state =0
    expected_length = 0
    domainstring =''
    domainparts =[]
    x=0
    y=0
    for byte in data:
        if state == 1:
            if byte != 0:
                domainstring += chr(byte)
            x+=1
            if x == expected_length:
                domainparts.append(domainstring)
                domainstring=''
                state = 0
                x = 0
            
            if byte ==0:
                domainparts.append(domainstring)
                break
        else:
            state=1
            expected_length =byte
        y+=1
        
    questiontype = data[y:y+2]
    #print(questiontype)
    
    #print(domainparts)
    return (domainparts,questiontype)

def getzone(domain):
    global zonedata
    zone_name = '.'.join(domain)
    return zonedata[zone_name]

def getrecs(data):
    domain,questiontype =getquestiondomain(data)
    qt=''
    if questiontype == b'\x00\x01':
        qt = 'a'
        
    zone = getzone(domain)
    
    return (zone[qt], qt, domain)



def buildquestion(domainname, rectype):
    qbytes = b''
    for part in domainname:
        length = len(part)
        qbytes += bytes([length])
        
        for char in part:
            qbytes += ord(char).to_bytes(1,byteorder='big')
        
    if rectype == 'a':
        qbytes += (1).to_bytes(2,byteorder='big')
        
    qbytes += (1).to_bytes(2,byteorder='big')
    
    
    #print(qbytes)
    
    return qbytes

def rectobytes(domainname, rectype, recttl, recval):
    
    rbytes =b'\xc0\x0c' # some compression shiet
    
    if rectype == 'a':
        rbytes = rbytes + bytes([0]) + bytes([1]) # get 0,1 as a list and covert that into bytes
    
    rbytes = rbytes + bytes([0]) + bytes([1])
    
    rbytes += int(recttl).to_bytes(4,byteorder='big')
    
    if rectype == 'a':
        rbytes = rbytes + bytes([0]) + bytes([4])
        
        
        for part in recval.split('.'):
            rbytes += bytes([int(part)])
    return rbytes

def buildresponse(data):
    # transaction id
    TransactionID = data[:2]
    
    Flags = getflags(data[2:4])
    #print(Flags)
    
    QDCOUNT= b'\x00\x01' #question count
    
    #print(getrecs(data[12:]))
    #print(len(getrecs(data[12:])[0])) # 0th a record
    
    # answer count
    ANCOUNT = len(getrecs(data[12:])[0]).to_bytes(2,byteorder='big')
    #print(ANCOUNT)
    
    #NAMESERVER count
    NSCOUNT = (0).to_bytes(2,byteorder='big')

    #additional section
    ARCOUNT = (0).to_bytes(2,byteorder='big')
    
    dnsheader = TransactionID + Flags + QDCOUNT + ANCOUNT + NSCOUNT +ARCOUNT
    
    #print(dnsheader)
    
    dnsbody = b''
    records, rectype, domainname = getrecs(data[12:])
    ##
    global dom
    dom = '.'.join(domainname) # ignore this , only for printing it below
    ##
    dnsquestion = buildquestion(domainname,rectype)
    #print(dnsquestion)
    
    for record in records:
        dnsbody += rectobytes(domainname, rectype, record['ttl'], record['value'])
    
    return dnsheader + dnsquestion + dnsbody

while 1:
    print("server starting")
    data, addr = sock.recvfrom(512)
    print(f"request from {addr} for {dom}")
    with open("logfile.txt","a") as logfile:
        logfile.write(f"request from {addr} for {dom}")
    #print(data)
    r = buildresponse(data)
    sock.sendto(r,addr)