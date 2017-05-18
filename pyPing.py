"""

ICMP(Internet Control Message Protocol) - Echo Request:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0|0|0|0|0|0|0|0|0|0|1|1|1|1|1|1|1|1|1|1|2|2|2|2|2|2|2|2|2|2|3|3|
|0|1|2|3|4|5|6|7|8|9|0|1|2|3|4|5|6|7|8|9|0|1|2|3|4|5|6|7|8|9|0|1|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Type = 8    |   Code = 0    |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Identifier           |        Sequence Number        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Time Stamp                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Payload                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

ICMP(Internet Control Message Protocol) - Echo Reply:
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|0|0|0|0|0|0|0|0|0|0|1|1|1|1|1|1|1|1|1|1|2|2|2|2|2|2|2|2|2|2|3|3|
|0|1|2|3|4|5|6|7|8|9|0|1|2|3|4|5|6|7|8|9|0|1|2|3|4|5|6|7|8|9|0|1|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|   Type = 0    |   Code = 0    |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Identifier           |        Sequence Number        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           Time Stamp                          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                            Payload                            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

"""

import time
import socket
import struct
import random

def setIcmpEchoRquestPacket(seqNum = 0):
    Type = 8
    Code = 0
    Identifier = 0
    SequenceNumber = seqNum
    TimeStamp = int(time.time())
    Payload = bytes([i for i in range(0, 48)])
    prePacket = struct.pack('!BBHHHLL48s', Type, Code, 0, Identifier, SequenceNumber, TimeStamp, 0, Payload)

    Sum = 0
    for i in range(0, len(prePacket), 2):
        Sum += ((prePacket[i] << 8) | prePacket[i + 1])
    Checksum = 0xFFFF - (((Sum & 0xFFFF0000) >> 16) + (Sum & 0xFFFF))

    return struct.pack('!BBHHHLL48s', Type, Code, Checksum, Identifier, SequenceNumber, TimeStamp, 0, Payload)

def getIcmpEchoReplyPacket(packet, t1, t2):

    Checksum = 0

    for i in range(0, len(packet), 2):
        Checksum += (packet[i] << 8) + packet[i + 1]
    Checksum = ((Checksum & 0xFFFF0000) >> 16) + (Checksum & 0xFFFF)

    if Checksum == 0xFFFF:
        print('%4d.%06dms TTL = %03d SeqNum = %05d' % ((t2 - t1) * 1000, (t2 - t1) * 1000000000 % 1000000, packet[8], (packet[26] << 8) + packet[27]))
    else:
        print('Checksum Error!')

seqNum = 0
dstIP = 'www.baidu.com'
print('Try to ping %s (%s)' % (dstIP, socket.gethostbyname(dstIP)))
while True:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.settimeout(5)
        r = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        r.settimeout(5)
        s.sendto(setIcmpEchoRquestPacket(seqNum), (dstIP, 80))
        t1 = time.time()
        packet = r.recvfrom(1024)
        t2 = time.time()
        getIcmpEchoReplyPacket(packet[0], t1, t2)
        seqNum = (seqNum + 1) & 0xFFF
        time.sleep(1)
    except socket.timeout:
        print('Timeout')
    except KeyboardInterrupt:
        exit()