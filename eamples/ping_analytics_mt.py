#!/usr/local/bin/python3
# encoding: utf-8

import sys
import signal
import time
import statistics
import sqlite3
import logging
import threading
import multiprocessing
import ping as pinglib

logger = logging.getLogger('ping')
#logger.setLevel(logging.DEBUG)

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
        if 'error' in result:
            self.failure(result)
        else: 
            self.success(result)
    
    def success(self, result):
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
        
class PingMT(threading.Thread):
    def __init__(self, resultq, target):
        super().__init__(daemon=True)
        self.target = target
        self.resultq = resultq
        
    def run(self):
        ping = pinglib.Ping()
        while True:
            try:
                self.resultq.put(ping.execute(self.target))
            except (pinglib.PingTimeout, pinglib.HostUnknown) as e:
                self.resultq.put({'addr': e.addr, 'error': e.message})
            except pinglib.PingError as e:
                self.resultq.put({'addr': e.ip.src_addr.compressed, 'error': e.message})
            time.sleep(1.0)
            
def main():
    resultq = multiprocessing.Queue()
    for target in ['127.0.0.1', '192.168.12.1', '192.168.0.1', '1.1.1.1', '8.8.8.8', 'google.com']:
        PingMT(resultq=resultq, target=target).start()
    #
    analytics = PingAnalytics()
    try:
        while True:
            analytics.record(resultq.get())
    except KeyboardInterrupt:
        sys.exit()

if __name__ == '__main__':
    main()