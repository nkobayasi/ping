#!/usr/local/bin/python3
# encoding: utf-8

import time
import math
import statistics
import sqlite3
import sys
import logging
import logging.handlers
import ping as pinglib
import utils

class StderrHandler(logging.StreamHandler):
    def __init__(self):
        super().__init__()
        self.setFormatter(logging.Formatter('[%(process)d] %(message)s'))

class StdoutHandler(logging.StreamHandler):
    def __init__(self):
        super().__init__(stream=sys.stdout)
        self.setFormatter(logging.Formatter('%(message)s'))

class SyslogHandler(logging.handlers.SysLogHandler):
    def __init__(self, filename):
        super().__init__()
        self.setFormatter(logging.Formatter('%(levelname)s: %(name)s.%(funcName)s(): %(message)s'))

class FileHandler(logging.handlers.WatchedFileHandler):
    def __init__(self, filename):
        super().__init__(filename, encoding='utf-8')
        self.setFormatter(logging.Formatter('[%(asctime)s] [%(process)d] %(levelname)s: %(name)s.%(funcName)s(): %(message)s'))

class PingRecord(object):
    @classmethod
    def from_result(cls, result):
        if 'error' in result:
            self = PingFailureRecord(
                addr=result['addr'],
                error=result['error'])
            return self
        else:
            self = PingSuccessRecord(
                addr=result['addr'],
                roundtrip=result['roundtrip'],
                size=result['size'],
                ttl=result['ttl'],
                seq=result['seq'])
            return self

class PingSuccessRecord(PingRecord):
    def __init__(self, addr, roundtrip, size, ttl, seq):
        self.addr = addr
        self.roundtrip = roundtrip
        self.size = size
        self.ttl = ttl
        self.seq = seq
        
    def __str__(self):
        return '{} bytes from {}: icmp_seq={} ttl={} time={:.2f} ms'.format(self.size, self.addr, self.seq, self.ttl, self.roundtrip)

class PingFailureRecord(PingRecord):
    def __init__(self, addr, error):
        self.addr = addr
        self.error = error

    def __str__(self):
        return 'response from {}: {}'.format(self.addr, self.error)

class TimeElapsed(object):
    def __init__(self):
        self.epoch = time.time()
    
    def measure(self):
        return time.time() - self.epoch
    
    @property
    def seconds(self):
        return self.measure()

    @property
    def milliseconds(self):
        return self.measure() * 1000.0

class Pings(object):
    class Static(object):
        def __init__(self, pings):
            self.pings = pings
    
        def __str__(self):
            return 'rtt min/avg/max/mdev = {:.3f}/{:.3f}/{:.3f}/{:.3f} ms'.format(self.min, self.average, self.max, self.standard_deviation)
            
        @property
        def min(self):
            return min(map(lambda _: _.roundtrip, self.pings.succeed))
    
        @property
        def max(self):
            return max(map(lambda _: _.roundtrip, self.pings.succeed))
    
        @property
        def average(self):
            return statistics.mean(map(lambda _: _.roundtrip, self.pings.succeed))
        
        @property
        def standard_deviation(self):
            return statistics.stdev(map(lambda _: _.roundtrip, self.pings.succeed))
        
    def __init__(self):
        self.records = []
        self.elapsed = TimeElapsed()
        
    def __str__(self):
        return '{} packets transmitted, {} received, {:.1f}% packet loss'.format(self.transmitted, self.recieved, self.failed*100.0/self.transmitted)
        
    @property
    def transmitted(self):
        return len(self.records)
    count=transmitted

    @property
    def succeed(self):
        return list(filter(lambda _: isinstance(_, PingSuccessRecord), self.records))

    @property
    def recieved(self):
        return len(self.succeed)
    
    @property
    def failed(self):
        return self.transmitted - self.recieved
        
    @property
    def static(self):
        return self.Static(self)
    
    def add(self, record: PingRecord):
        print(record)
        self.records.append(record)
    append=add
    
    def execute(self, addr):
        ping = pinglib.Ping()
        try:
            self.add(PingRecord.from_result(ping.execute(addr)))
        except (pinglib.PingTimeout, pinglib.HostUnknown) as e:
            self.add(PingRecord.from_result({'addr': e.addr, 'error': e.message}))
        except pinglib.PingError as e:
            self.add(PingRecord.from_result({'addr': e.ip.src_addr.compressed, 'error': e.message}))

def main():
    logging.getLogger('ping').setLevel(logging.DEBUG)
    pings = Pings()
    for _ in range(6):
        pings.execute('127.0.0.1')
        pings.execute('192.168.12.1')
        pings.execute('1.1.1.1')
        pings.execute('8.8.8.8')
        pings.execute('google.com')
        #pings.execute('ping.symantec.com')
        #
        time.sleep(1.0)
    print(pings)
    print(pings.static)
    print('{:.0f}ms'.format(pings.elapsed.milliseconds))

if __name__ == '__main__':
    main()