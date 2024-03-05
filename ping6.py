#!/usr/local/bin/python3
# encoding: utf-8

from functools import wraps
import os
import time
import enum
import struct
import binascii
import socket
import select
import threading
import ipaddress

def memoized(func):
    @wraps(func)
    def closure(*args, **kwargs):
        cls = args[0]
        attrname = '_memoized_{0}'.format(func.__name__)
        if not hasattr(cls, attrname):
            setattr(cls, attrname, func(*args, **kwargs))
        return getattr(cls, attrname)
    return closure

def memoized_property(func):
    return property(memoized(func))

def checksum(value):
    def carry_around(a, b):
        c = a + b
        return (c & 0xffff) + (c >> 16)

    result = 0
    for _ in range(0, len(value), 2):
        x = (value[_] << 8) + value[_ + 1]
        result = carry_around(result, x)
    return ~result & 0xffff

class Ping6Error(Exception): pass

class Ping6Timeout(Ping6Error):
    def __init__(self, message='Request timeout for ICMP packet.', addr=None, timeout=None):
        self.addr = addr
        self.timeout = timeout
        self.message = message
        if self.timeout is not None:
            message += ' (Timeout={}s)'.format(self.timeout)
        super().__init__(self.message)

class Icmp6Type(enum.IntEnum):
    ECHO_REQUEST = 128
    ECHO_REPLY = 129

class Ip6Packet(object):
    HEADER_FORMAT = "!BBHHBBQQQQ"

    @classmethod
    def factory(cls, raw):
        self = cls()
        self.raw = raw
        return self

    @property
    def src_addr(self):
        return ipaddress.ip_address(self.header['src_addr_hi'] << 64 | self.header['src_addr_lo'])

    @property
    def dest_addr(self):
        return ipaddress.ip_address(self.header['dest_addr_hi'] << 64 | self.header['dest_addr_lo'])

    @property
    def ttl(self):
        return self.header['ttl']

    @property
    def header_size(self):
        return struct.calcsize(self.HEADER_FORMAT)

    @property
    def payload_size(self):
        return self.header['payload_length'] - self.header_size

    @property
    @memoized
    def header(self):
        header_keys = ('version', 'type', 'flow_label', 'payload_length', 'protocol', 'ttl', 'src_addr_hi', 'src_addr_lo', 'dest_addr_hi', 'dest_addr_lo')
        return dict(zip(header_keys, struct.unpack(self.HEADER_FORMAT, self.raw[0:self.header_size])))

    @property
    @memoized
    def payload(self):
        return self.raw[self.header_size:]

class Icmp6Packet(object):
    HEADER_FORMAT = "!BbHHh"
    TIME_FORMAT = "!d"
    
    @classmethod
    def factory(cls, raw):
        self = cls()
        self.raw = raw
        return self

class EchoRequest(Icmp6Packet):
    def __init__(self, seq=0, size=64):
        super().__init__()
        self._seq = seq
        self.size = size - 8
        self.timestamp = time.time()

    @property
    @memoized
    def id(self):
        if hasattr(threading, 'get_native_id'):
            thread_id = threading.get_native_id()
        else:
            thread_id = threading.currentThread().ident
        return binascii.crc32(bytes.fromhex("{process_id:08x}{thread_id:08x}".format(process_id=os.getpid(), thread_id=thread_id))) & 0xffff

    @property
    def seq(self):
        return self._seq & 0xffff

    @property
    @memoized
    def header(self):
        header = struct.pack(self.HEADER_FORMAT, Icmp6Type.ECHO_REQUEST, 0, 0, self.id, self.seq)
        real_checksum = checksum(header + self.payload)
        return struct.pack(self.HEADER_FORMAT, Icmp6Type.ECHO_REQUEST, 0, socket.htons(real_checksum), self.id, self.seq)

    @property
    @memoized
    def payload(self):
        return struct.pack(self.TIME_FORMAT, self.timestamp) + b'Q' * (self.size - struct.calcsize(self.TIME_FORMAT))
        # s = ''
        # for x in range(0x42, 0x42 + self.size):
        #     s += '{:02x}'.format(x & 0xff)
        # return bytes.fromhex(s)

    @property
    @memoized
    def raw_packet(self):
        return self.header + self.payload

class EchoReply(Icmp6Packet):
    @property
    def id(self):
        return self.header['id']

    @property
    def seq(self):
        return self.header['seq']

    @property
    def type(self):
        return self.header['type']
        #return Icmp6Type(self.header['type'])

    @property
    @memoized
    def timestamp(self):
        return struct.unpack(self.TIME_FORMAT, self.payload[0:struct.calcsize(self.TIME_FORMAT)])[0]
    
    @property
    def header_size(self):
        return struct.calcsize(self.HEADER_FORMAT)

    @property
    @memoized
    def header(self):
        header_keys = ('type', 'code', 'checksum', 'id', 'seq')
        return dict(zip(header_keys, struct.unpack(self.HEADER_FORMAT, self.raw[0:self.header_size])))
    
    @property
    @memoized
    def payload(self):
        return self.raw[self.header_size:]
    
class Ping6(object):
    def __init__(self, ttl=None, size=64, timeout=10):
        self.timeout = timeout
        self.seq = 0
        self.ttl = ttl
        self.size = size

    def execute(self, addr):
        def lower_limit_zero(value):
            if value < 0:
                return 0
            return value

        self.seq += 1
        echo_request = EchoRequest(seq=self.seq, size=self.size)
        family, type, proto, canonname, sockaddr = socket.getaddrinfo(addr, None, family=socket.AF_INET6)[0]
        _socket = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.getprotobyname("ipv6-icmp"))
        _socket.sendto(echo_request.raw_packet, sockaddr)
        
        limited_unixtime = time.time() +  self.timeout
        while True:
            select_timeout = lower_limit_zero(limited_unixtime - time.time())
            selected = select.select([_socket, ], [], [], select_timeout)
            if selected[0] == []: # The empty that first element of selected result means timed out
                raise Ping6Timeout(addr=addr, timeout=self.timeout)
            raw_packet, _ = _socket.recvfrom(2048)
            #ip = Ip6Packet.factory(raw_packet)
            echo_reply = EchoReply.factory(raw_packet)
            if echo_reply.id:
                if echo_reply.type == Icmp6Type.ECHO_REQUEST:
                    #logger.debug('Received ICMP type, "ECHO_REQUEST". Packet filtered.')
                    continue
                if echo_reply.id != echo_request.id:
                    #logger.debug('Mismatch ICMP echos and replies identifier. Packet filtered.')
                    continue
                if echo_reply.seq != echo_request.seq:
                    #logger.debug('Mismatch ICMP echos and replies sequence number. Packet filtered.')
                    continue
            if echo_reply.type == Icmp6Type.ECHO_REPLY:
                return {
                    'addr': ipaddress.ip_address(sockaddr[0]),
                    'seq': echo_reply.seq,
                    'roundtrip': (time.time() - echo_reply.timestamp) * 1000.0}

def ping6(addr, times=1, interval=1.0, ttl=None, size=64, timeout=10):
    results = []
    ping = Ping6(ttl=ttl, size=size, timeout=timeout)
    for _ in range(times):
        results.append(ping.execute(addr))
        time.sleep(interval)
    return results

def main():
    print(ping6('::1'))
    print(ping6('localhost'))
    print(ping6('google.com', 5))

if __name__ == '__main__':
    main()