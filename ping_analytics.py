#!/usr/local/bin/python3
# encoding: utf-8

import time
import sqlite3
import ping as pinglib

class PingResult(object):
    def __init__(self):
        pass

    @classmethod
    def factory(cls, ip: IpPacket):
        echo_reply = EchoReply.factory(ip.payload)
        self = cls()
        self.addr = ip.src_addr
        self.roundtrip = (time.time() - echo_reply.epoch) * 1000.0
        self.size = ip.payload_size
        self.ttl = ip.ttl
        return self

class Pings(object):
    pass

class PingsStatic(object):
    def __init__(self, results):
        self.results = results

    def __str__(self):
        return '{!s}, min: {:.2f}, max: {:.2f}, avg: {:.2f}'.format(self.results, self.min, self.max, self.avg)
        
    @property
    def min(self):
        return min(map(lambda _: _['roundtrip'], self.results))

    @property
    def max(self):
        return max(map(lambda _: _['roundtrip'], self.results))

    @property
    def avg(self):
        return sum(map(lambda _: _['roundtrip'], self.results)) / len(self.results)

class PingAnalytics(object):
    def __init__(self):
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

    def record(self, result):
        cursor = self.db.cursor()
        cursor.execute("""INSERT INTO histories(error, addr, size, roundtrip, ttl, epoch) VALUES(false, ?, ?, ?, ?, ?)""", (
            result['addr'].compressed,
            result['size'],
            result['roundtrip'],
            result['ttl'],
            int(time.time()), ))
        self.db.commit();

    def failure(self, result):
        cursor = self.db.cursor()
        cursor.execute("""INSERT INTO histories(error, addr, error_string, epoch) VALUES(true, ?, ?, ?)""", (
            result['addr'],
            result['error'],
            int(time.time()), ))
        self.db.commit();
        
    @property
    def result(self):
        cursor = self.db.cursor()
        cursor.execute("""SELECT addr, min(roundtrip) AS min, max(roundtrip) AS max, avg(roundtrip) AS avg FROM histories GROUP BY addr""")
        return cursor.fetchall()

    @property
    def jitter(self):
        cursor = self.db.cursor()
        cursor.execute("""
            SELECT
                histories.addr,
                avg(abs(roundtrip - avg.avg)) AS jitter
            FROM
                histories
                    INNER JOIN (SELECT addr, avg(roundtrip) AS avg FROM histories GROUP BY addr) avg ON histories.addr = avg.addr
            GROUP BY
                histories.addr""")
        return cursor.fetchall()

def main():
    ping = pinglib.Ping()
    analytics = PingAnalytics()
    for _ in range(60 * 60 * 6):
        try:
            analytics.record(ping.execute('127.0.0.1'))
            analytics.record(ping.execute('192.168.12.1'))
            analytics.record(ping.execute('1.1.1.1'))
            analytics.record(ping.execute('8.8.8.8'))
            analytics.record(ping.execute('google.com'))
        except pinglib.PingTimeout as e:
            analytics.failure({'addr': e.addr, 'error': e.message})
        except pinglib.PingError as e:
            analytics.failure({'addr': e.ip.src_addr.compressed, 'error': e.message})
        time.sleep(1.0)
    print(analytics.result)
    print(analytics.jitter)

if __name__ == '__main__':
    main()