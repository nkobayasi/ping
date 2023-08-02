#!/usr/local/bin/python3
# encoding: utf-8

import time
import sqlite3
import ping as pinglib

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
    for _ in range(60 * 10):
        analytics.record(ping.execute('127.0.0.1'))
        analytics.record(ping.execute('192.168.12.1'))
        analytics.record(ping.execute('1.1.1.1'))
        analytics.record(ping.execute('8.8.8.8'))
        analytics.record(ping.execute('google.com'))
        time.sleep(1.0)
    print(analytics.result)
    print(analytics.jitter)

if __name__ == '__main__':
    main()