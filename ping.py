#!/usr/local/bin/python3
# encoding: utf-8

from functools import wraps
import enum
import os
import struct
import socket
import time
import threading
import zlib

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

def checksum(value, bits=16):
    carry = 1 << bits
    result = sum(value[::2]) + (sum(value[1::2]) << (bits // 2))
    while result >= carry:
        result = sum(divmod(result, carry))
    return ~result & ((1 << bits) - 1)

class PingError(Exception): pass
class HostUnknown(PingError):
    def __init__(self, message="Cannot resolve: Unknown host.", addr=None):
        self.addr = addr
        self.message = message if self.addr is None else message + " (Host='{}')".format(self.addr)
        super().__init__(self.message)

class Ip(object):
    HEADER_FORMAT = "!BBHHHBBHII"
    
    def __init__(self):
        pass
    
    @classmethod
    def factory(cls, raw):
        self = cls()
        self.raw = raw
        return self
    
    @memoized
    @property
    def header(self):
        header_keys = ('version', 'tos', 'len', 'id', 'flags', 'ttl', 'protocol', 'checksum', 'src_addr', 'dest_addr')
        return dict(zip(header_keys, struct.unpack(self.HEADER_FORMAT, self.raw[0:struct.calcsize(self.HEADER_FORMAT)])))
    
    @memoized
    @property
    def payload(self):
        return self.raw[struct.calcsize(self.HEADER_FORMAT):]

class IcmpPacket(object):
    HEADER_FORMAT = "!BBHHH"
    TIME_FORMAT = "!d"
    
    def __init__(self):
        self._seq = 0
    
    @classmethod
    def factory(cls, raw):
        self = cls()
        self.raw = raw
        return self

class IcmpType(enum.IntEnum):
    ECHO_REPLY = 0
    DESTINATION_UNREACHABLE = 3
    REDIRECT_MESSAGE = 5
    ECHO_REQUEST = 8
    ROUTER_ADVERTISEMENT = 9
    ROUTER_SOLICITATION = 10
    TIME_EXCEEDED = 11
    BAD_IP_HEADER = 12
    TIMESTAMP = 13
    TIMESTAMP_REPLY = 14

class EchoRequest(IcmpPacket):
    def __init__(self, size=56):
        super().__init__()
        self.size = size
        self.epoch = time.time()

    @memoized
    @property
    def id(self):
        if hasattr(threading, 'get_native_id'):
            thread_id = threading.get_native_id()
        else:
            thread_id = threading.currentThread().ident
        process_id = os.getpid()
        return zlib.crc32("{}{}".format(process_id, thread_id).encode("ascii")) & 0xffff

    @property
    def seq(self):
        return self._seq
    
    @memoized
    @property
    def header(self):
        header = struct.pack(Icmp.HEADER_FORMAT, IcmpType.ECHO_REQUEST, 0, 0, self.id, self.seq)
        real_checksum = checksum(header + self.payload)
        return struct.pack(Icmp.HEADER_FORMAT, IcmpType.ECHO_REQUEST, 0, socket.htons(real_checksum), self.id, self.seq)
    
    @memoized
    @property
    def payload(self):
        return struct.pack(Icmp.TIME_FORMAT, time.time()) + b'Q' * (self.size - struct.calcsize(Icmp.TIME_FORMAT))
    
    @memoized
    @property
    def packet(self):
        return self.header + self.payload

class EchoReply(IcmpPacket):
    @property
    def id(self):
        return self.header['id']

    @property
    def seq(self):
        return self.header['seq']

    @memoized
    @property
    def header(self):
        header_keys = ('type', 'code', 'checksum', 'id', 'seq')
        return dict(zip(header_keys, struct.unpack(Icmp.HEADER_FORMAT, self.raw[0:struct.calcsize(Icmp.HEADER_FORMAT)])))
    
    @memoized
    @property
    def payload(self):
        return self.raw[struct.calcsize(Icmp.HEADER_FORMAT):]
    
    @memoized
    @property
    def epoch(self):
        return struct.unpack(Icmp.TIME_FORMAT, self.payload[0:struct.calcsize(Icmp.TIME_FORMAT)])[0]

class Ping(object):
    def __init__(self, ttl=None):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        if ttl:
            try:  # IPPROTO_IP is for Windows and BSD Linux.
                if self.socket.getsockopt(socket.IPPROTO_IP, socket.IP_TTL):
                    self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
            except OSError as err:
                pass
            try:
                if self.socket.getsockopt(socket.SOL_IP, socket.IP_TTL):
                    self.socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            except OSError as err:
                pass
    
    def execute(self, addr):
        try:
            addr = socket.gethostbyname(addr)
        except socket.gaierror as e:
            raise HostUnknown(addr=addr) from e
        print(addr)
        echo_request = EchoRequest()
        self.socket.sendto(echo_request.packet, (addr, 0))
        raw, addr = self.socket.recvfrom(1500)
        ip = Ip.factory(raw)
        echo_reply = EchoReply.factory(ip.payload)
        print(addr)
        print('ttl=', ip.header['ttl'])
        print('protocol=', ip.header['protocol'])
        print('type=', echo_reply.header['type'])
        print('id=', echo_reply.id)
        print('seq=', echo_reply.seq)
        print('request_time=', echo_request.epoch, time.ctime(echo_request.epoch))
        print('reply_time=', echo_reply.epoch, time.ctime(echo_reply.epoch))
        print('time=', '{:.6f}'.format(echo_reply.epoch - echo_request.epoch))
    
def ping(addr):
    ping = Ping()
    return ping.execute(addr)

def main():
    ping('127.0.0.1')
    ping('8.8.8.8')
    ping('google.com')

if __name__ == '__main__':
    main()