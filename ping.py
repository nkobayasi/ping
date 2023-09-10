#!/usr/local/bin/python3
# encoding: utf-8

from functools import wraps
import enum
import os
import select
import struct
import socket
import time
import threading
import zlib
import ipaddress
import logging
import logging.handlers

__version__ = "4.0.4"

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

class StderrHandler(logging.StreamHandler):
    def __init__(self):
        super().__init__()
        self.setFormatter(logging.Formatter('[%(process)d] %(message)s'))

class SyslogHandler(logging.handlers.SysLogHandler):
    def __init__(self, filename):
        super().__init__()
        self.setFormatter(logging.Formatter('%(levelname)s: %(name)s.%(funcName)s(): %(message)s'))

class FileHandler(logging.handlers.WatchedFileHandler):
    def __init__(self, filename):
        super().__init__(filename, encoding='utf-8')
        self.setFormatter(logging.Formatter('[%(asctime)s] [%(process)d] %(levelname)s: %(name)s.%(funcName)s(): %(message)s'))

logger = logging.getLogger('ping').getChild(__name__)
logger.addHandler(StderrHandler())
logger.setLevel(logging.DEBUG)

class PingError(Exception): pass

class HostUnknown(PingError):
    def __init__(self, message='Cannot resolve: Unknown host.', addr=None):
        self.addr = addr
        self.message = messsage
        if self.addr is not None:
            message += ' (Host="{}")'.format(self.addr)
        super().__init__(self.message)

class PingTimeout(PingError):
    def __init__(self, message='Request timeout for ICMP packet.', addr=None, timeout=None):
        self.addr = addr
        self.timeout = timeout
        self.message = message
        if self.timeout is not None:
            message += ' (Timeout={}s)'.format(self.timeout)
        super().__init__(self.message)

class TimeExceeded(PingError): pass

class TimeToLiveExpired(TimeExceeded):
    def __init__(self, message='Time exceeded: Time To Live expired.', ip=None):
        self.ip = ip
        self.icmp = EchoReply(ip.payload)
        self.message = message
        super().__init__(self.message)

class DestinationUnreachable(PingError):
    def __init__(self, message='Destination unreachable.', ip=None):
        self.ip = ip
        self.icmp = EchoReply(ip.payload)
        self.message = message
        if ip is not None:
            self.message += ' (Host="{}")'.format(ip.src_addr)
        super().__init__(self.message)

class DestinationHostUnreachable(DestinationUnreachable):
    def __init__(self, message='Destination unreachable: Host unreachable.', ip=None):
        super().__init__(message, ip=ip)

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

class IcmpTimeExceededCode(enum.IntEnum):
    TTL_EXPIRED = 0
    FRAGMENT_REASSEMBLY_TIME_EXCEEDED = 1

class IcmpDestinationUnreachableCode(enum.IntEnum):
    DESTINATION_NETWORK_UNREACHABLE = 0
    DESTINATION_HOST_UNREACHABLE = 1
    DESTINATION_PROTOCOL_UNREACHABLE = 2
    DESTINATION_PORT_UNREACHABLE = 3
    FRAGMENTATION_REQUIRED = 4
    SOURCE_ROUTE_FAILED = 5
    DESTINATION_NETWORK_UNKNOWN = 6
    DESTINATION_HOST_UNKNOWN = 7
    SOURCE_HOST_ISOLATED = 8
    NETWORK_ADMINISTRATIVELY_PROHIBITED = 9
    HOST_ADMINISTRATIVELY_PROHIBITED = 10
    NETWORK_UNREACHABLE_FOR_TOS = 11
    HOST_UNREACHABLE_FOR_TOS = 12
    COMMUNICATION_ADMINISTRATIVELY_PROHIBITED = 13
    HOST_PRECEDENCE_VIOLATION = 14
    PRECEDENCE_CUTOFF_IN_EFFECT = 15

class IpPacket(object):
    HEADER_FORMAT = "!BBHHHBBHII"
    
    @classmethod
    def factory(cls, raw):
        self = cls()
        self.raw = raw
        return self
    
    @property
    def src_addr(self):
        return ipaddress.ip_address(self.header['src_addr'])

    @property
    def dest_addr(self):
        return ipaddress.ip_address(self.header['dest_addr'])
    
    @property
    def payload_size(self):
        return self.header['len'] - struct.calcsize(self.HEADER_FORMAT)

    @property
    def ttl(self):
        return self.header['ttl']
    
    @property
    @memoized
    def header(self):
        header_keys = ('version', 'tos', 'len', 'id', 'flags', 'ttl', 'protocol', 'checksum', 'src_addr', 'dest_addr')
        return dict(zip(header_keys, struct.unpack(self.HEADER_FORMAT, self.raw[0:struct.calcsize(self.HEADER_FORMAT)])))
    
    @property
    @memoized
    def payload(self):
        return self.raw[struct.calcsize(self.HEADER_FORMAT):]

class IcmpPacket(object):
    HEADER_FORMAT = "!BBHHH"
    TIME_FORMAT = "!d"
    
    @classmethod
    def factory(cls, raw):
        self = cls()
        self.raw = raw
        return self

class EchoRequest(IcmpPacket):
    def __init__(self, seq=0, size=56):
        super().__init__()
        self._seq = seq
        self.size = size
        self.timestamp = time.time()

    @property
    @memoized
    def id(self):
        if hasattr(threading, 'get_native_id'):
            thread_id = threading.get_native_id()
        else:
            thread_id = threading.currentThread().ident
        process_id = os.getpid()
        return zlib.crc32("{}{}".format(process_id, thread_id).encode('ascii')) & 0xffff

    @property
    def seq(self):
        return self._seq & 0xffff

    @property
    @memoized
    def header(self):
        header = struct.pack(self.HEADER_FORMAT, IcmpType.ECHO_REQUEST, 0, 0, self.id, self.seq)
        real_checksum = checksum(header + self.payload)
        return struct.pack(self.HEADER_FORMAT, IcmpType.ECHO_REQUEST, 0, socket.htons(real_checksum), self.id, self.seq)
    
    @property
    @memoized
    def payload(self):
        return struct.pack(self.TIME_FORMAT, self.timestamp) + b'Q' * (self.size - struct.calcsize(self.TIME_FORMAT))
    
    @property
    @memoized
    def raw_packet(self):
        return self.header + self.payload

class EchoReply(IcmpPacket):
    def __repr__(self):
        return '<IcmpPacket: type.name="{}" id={} seq={}>'.format(self.type.name, self.id, self.seq)

    @property
    def id(self):
        return self.header['id']

    @property
    def seq(self):
        return self.header['seq']

    @property
    def type(self):
        return IcmpType(self.header['type'])

    @property
    @memoized
    def header(self):
        header_keys = ('type', 'code', 'checksum', 'id', 'seq')
        return dict(zip(header_keys, struct.unpack(self.HEADER_FORMAT, self.raw[0:struct.calcsize(self.HEADER_FORMAT)])))
    
    @property
    @memoized
    def payload(self):
        return self.raw[struct.calcsize(self.HEADER_FORMAT):]
    
    @property
    @memoized
    def timestamp(self):
        return struct.unpack(self.TIME_FORMAT, self.payload[0:struct.calcsize(self.TIME_FORMAT)])[0]

class Ping(object):
    def __init__(self, ttl=None, timeout=10):
        self.timeout = timeout
        self.seq = 0
        self.ttl = ttl
    
    def execute(self, addr):
        def try_setsockopt(socket, level, optname, value):
            try:
                if socket.getsockopt(level, optname):
                    socket.setsockopt(level, optname, value)
            except OSError as err:
                pass

        def lower_limit_zero(value):
            if value < 0:
                return 0
            return value
        
        self.seq += 1
        # Open and prepare socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        if self.ttl:
            try_setsockopt(self.socket, socket.IPPROTO_IP, socket.IP_TTL, self.ttl)
            try_setsockopt(self.socket, socket.SOL_IP, socket.IP_TTL, self.ttl)
        # Resolve address
        try:
            addr = socket.gethostbyname(addr)
        except socket.gaierror as e:
            raise HostUnknown(addr=addr) from e
        # ICMP request
        echo_request = EchoRequest(seq=self.seq)
        self.socket.sendto(echo_request.raw_packet, (addr, 0))
        # ICMP response
        limited_unixtime = time.time() +  self.timeout
        while True:
            select_timeout = lower_limit_zero(limited_unixtime - time.time())
            selected = select.select([self.socket, ], [], [], select_timeout)
            if selected[0] == []: # The empty that first element of selected result means timed out
                raise PingTimeout(addr=addr, timeout=self.timeout)
            raw_packet, addr = self.socket.recvfrom(1500)
            ip = IpPacket.factory(raw_packet)
            echo_reply = EchoReply.factory(ip.payload)
            if echo_reply.header['type'] == IcmpType.TIME_EXCEEDED:
                if echo_reply.header['code'] == IcmpTimeExceededCode.TTL_EXPIRED:
                    raise TimeToLiveExpired(ip=ip)
                raise TimeExceeded()
            if echo_reply.header['type'] == IcmpType.DESTINATION_UNREACHABLE:
                if echo_reply.header['code'] == IcmpDestinationUnreachableCode.DESTINATION_HOST_UNREACHABLE:
                    raise DestinationHostUnreachable(ip=ip)
                raise DestinationUnreachable(ip=ip)
            if echo_reply.header['id']:
                if echo_reply.header['type'] == IcmpType.ECHO_REQUEST:
                    logger.debug('Received ICMP type, "ECHO_REQUEST". Packet filtered.')
                    continue
                if echo_reply.id != echo_request.id:
                    logger.debug('Mismatch ICMP echos and replies identifier. Packet filtered.')
                    continue
                if echo_reply.seq != echo_request.seq:
                    logger.debug('Mismatch ICMP echos and replies sequence number. Packet filtered.')
                    continue
            if echo_reply.header['type'] == IcmpType.ECHO_REPLY:
                return {
                    'addr': ip.src_addr,
                    'size': ip.payload_size,
                    'seq': echo_reply.seq,
                    'roundtrip': (time.time() - echo_reply.timestamp) * 1000.0, 
                    'ttl': ip.ttl}
            logger.debug('Uncaught ICMP packet: {!s}'.format(echo_reply))

def ping(addr, times=1, interval=1.0, ttl=None, timeout=10):
    results = []
    ping = Ping(ttl=ttl, timeout=timeout)
    for _ in range(times):
        results.append(ping.execute(addr))
        time.sleep(interval)
    return results

def main():
    print(ping('127.0.0.1', 4))
    print(ping('8.8.8.8', 4))
    print(ping('google.com'))

if __name__ == '__main__':
    main()