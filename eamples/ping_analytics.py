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
    def __init__(self, addr, roundtrip, size, ttl, seq):
        self.addr = addr
        self.roundtrip = roundtrip
        self.size = size
        self.ttl = ttl
        self.seq = seq

    @classmethod
    def from_result(cls, result):
        self = cls(
            addr=result['addr'],
            roundtrip=result['roundtrip'],
            size=result['size'],
            ttl=result['ttl'],
            seq=result['seq'])
        return self

    @classmethod
    def from_ip(cls, ip: pinglib.IpPacket):
        echo_reply = pinglib.EchoReply.factory(ip.payload)
        self = cls(
            addr=ip.src_addr,
            roundtrip=(time.time() - echo_reply.epoch) * 1000.0,
            size=ip.payload_size,
            ttl=ip.ttl,
            seq=echo_reply.seq)
        return self

class Pings(object):
    class Static(object):
        def __init__(self, pings):
            self.pings = pings
    
        def __str__(self):
            return ' min: {:.2f}ms, max: {:.2f}ms, avg: {:.2f}ms, mdev: {:.2f}ms'.format(self.min, self.max, self.average, self.standard_deviation)
            
        @property
        def min(self):
            return min(map(lambda _: _.roundtrip, self.pings.records))
    
        @property
        def max(self):
            return max(map(lambda _: _.roundtrip, self.pings.records))
    
        @property
        def average(self):
            return statistics.mean(map(lambda _: _.roundtrip, self.pings.records))
        
        @property
        def standard_deviation(self):
            return statistics.stdev(map(lambda _: _.roundtrip, self.pings.records))
        
    def __init__(self):
        self.records = []
        
    @property
    def static(self):
        return self.Static(self)
    
    def add(self, record):
        self.records.append(record)
    append=add

class PingAnalytics(object):
    def __init__(self):
        self.logger = logging.getLogger('ping_analytics').getChild('PingAnalytics')
        self.logger.addHandler(FileHandler('ping_analytics.log'))
        self.logger.setLevel(logging.DEBUG)
        self.db = sqlite3.connect('ping_analytics.db')
        cursor = self.db.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS histories(
                error boolean,
                error_string text,
                addr varchar(15),
                size integer,
                roundtrip float,
                ttl integer,
                epoch datetime)""")
        self.db.commit()
        
    def create(self):
        cursor = self.db.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS histories(
                error boolean,
                error_string text,
                addr varchar(15),
                size integer,
                roundtrip float,
                ttl integer,
                epoch datetime)""")
        self.db.commit()
    
    def recreate(self):
        cursor = self.db.cursor()
        cursor.execute("""DROP TABLE IF EXISTS histories""")
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS histories(
                error boolean,
                error_string text,
                addr varchar(15),
                size integer,
                roundtrip float,
                ttl integer,
                epoch datetime)""")
        self.db.commit()
        
    def reset(self):
        cursor = self.db.cursor()
        cursor.execute("""DELETE FROM histories""")
        self.db.commit();

    def record(self, result):
        print('{addr} からの応答: バイト数 ={size} 時間 ={rtt:.1f}ms TTL={ttl}'.format(
            addr=result['addr'].compressed,
            size=result['size'],
            rtt=result['roundtrip'],
            ttl=result['ttl']))
        cursor = self.db.cursor()
        cursor.execute("""INSERT INTO histories(error, addr, size, roundtrip, ttl, epoch) VALUES(false, ?, ?, ?, ?, ?)""", (
            result['addr'].compressed,
            result['size'],
            result['roundtrip'],
            result['ttl'],
            int(time.time()), ))
        self.db.commit();

    def failure(self, result):
        print('{addr} からの応答: {err}'.format(addr=result['addr'], err=result['error']))
        self.logger.error('{addr} からの応答: {err}'.format(addr=result['addr'], err=result['error']))
        cursor = self.db.cursor()
        cursor.execute("""INSERT INTO histories(error, addr, error_string, epoch) VALUES(true, ?, ?, ?)""", (
            result['addr'],
            result['error'],
            int(time.time()), ))
        self.db.commit();
        
    @property
    def result(self):
        cursor = self.db.cursor()
        cursor.execute("""SELECT addr, min(roundtrip) AS min, max(roundtrip) AS max, avg(roundtrip) AS avg FROM histories WHERE NOT error GROUP BY addr""")
        return cursor.fetchall()

    @property
    def jitter(self):
        cursor = self.db.cursor()
        cursor.execute("""
            SELECT
                histories.addr,
                avg(abs(roundtrip - addr.avg)) AS avg_diff_from_avg,
                avg(abs(roundtrip - addr.min)) AS jitter
            FROM
                histories
                    INNER JOIN (SELECT addr, min(roundtrip) AS min, avg(roundtrip) AS avg FROM histories WHERE NOT error GROUP BY addr) addr ON histories.addr = addr.addr
            GROUP BY
                histories.addr""")
        return cursor.fetchall()

    @property
    def variance(self):
        cursor = self.db.cursor()
        cursor.execute("""
            SELECT
                histories.addr,
                avg((roundtrip - addr.avg) * (roundtrip - addr.avg)) AS variance
            FROM
                histories
                    INNER JOIN (SELECT addr, avg(roundtrip) AS avg FROM histories WHERE NOT error GROUP BY addr) addr ON histories.addr = addr.addr
            GROUP BY
                histories.addr""")
        return cursor.fetchall()

    @property
    def standard_deviation(self):
        return list(map(lambda _: (_[0], math.sqrt(_[1])), self.variance))

def main():
    logging.getLogger('ping').setLevel(logging.DEBUG)
    ping = pinglib.Ping()
    analytics = PingAnalytics()
    for _ in range(60 * 60 * 6):
        try:
            analytics.record(ping.execute('127.0.0.1'))
            analytics.record(ping.execute('192.168.12.1'))
            analytics.record(ping.execute('1.1.1.1'))
            analytics.record(ping.execute('8.8.8.8'))
            analytics.record(ping.execute('google.com'))
        except (pinglib.PingTimeout, pinglib.HostUnknown) as e:
            analytics.failure({'addr': e.addr, 'error': e.message})
        except pinglib.PingError as e:
            analytics.failure({'addr': e.ip.src_addr.compressed, 'error': e.message})
        time.sleep(1.0)
    print(analytics.result)
    print(analytics.jitter)
    print(analytics.standard_deviation)

if __name__ == '__main__':
    main()