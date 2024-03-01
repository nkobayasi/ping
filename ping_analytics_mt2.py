#!/usr/local/bin/python3
# encoding: utf-8

import sys
import signal
import time
import statistics
import sqlite3
import threading
import multiprocessing
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

class PingMT(threading.Thread):
    def __init__(self, jobq, resultq):
        super().__init__(daemon=True)
        self.jobq = jobq
        self.resultq = resultq
        
    def run(self):
        ping = pinglib.Ping()
        while True:
            try:
                self.resultq.put(ping.execute(self.jobq.get()))
            except (pinglib.PingTimeout, pinglib.HostUnknown) as e:
                self.resultq.put({'addr': e.addr, 'error': e.message})
            except pinglib.PingError as e:
                self.resultq.put({'addr': e.ip.src_addr.compressed, 'error': e.message})

class Producer(threading.Thread):
    def __init__(self, jobq, targets):
        super().__init__(daemon=True)
        self.jobq = jobq
        self.targets = targets

    def run(self):
        #for _ in range(6 * 60 * 60):
        while True:
            for target in self.targets:
                self.jobq.put(target)
            time.sleep(1.0)
    
class Consumer(threading.Thread):
    def __init__(self, resultq):
        super().__init__(daemon=True)
        self.resultq = resultq

    def run(self):
        analytics = PingAnalytics()
        while True:
            result = self.resultq.get()
            if 'error' in result:
                analytics.failure(result)
            else: 
                analytics.record(result)

def main():
    targets = ['127.0.0.1', '192.168.12.1', '192.168.0.1', '1.1.1.1', '8.8.8.8', 'google.com']
    jobq = multiprocessing.Queue()
    resultq = multiprocessing.Queue()
    for _ in range(len(targets)+2):
        PingMT(jobq=jobq, resultq=resultq).start()
    Producer(jobq=jobq, targets=targets).start()
    Consumer(resultq=resultq).start()
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        sys.exit()

if __name__ == '__main__':
    main()