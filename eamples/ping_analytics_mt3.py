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

logger = logging.getLogger('ping').getChild('analytics')
logger.addHandler(StderrHandler())
logger.setLevel(logging.DEBUG)

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
    def __init__(self, resultq, target, terminated):
        super().__init__()
        self.target = target
        self.resultq = resultq
        self.terminated = terminated
        
    def run(self):
        ping = pinglib.Ping()
        while not self.terminated.wait(timeout=1.0):
            try:
                self.resultq.put(ping.execute(self.target))
            except (pinglib.PingTimeout, pinglib.HostUnknown) as e:
                self.resultq.put({'addr': e.addr, 'error': e.message})
            except pinglib.PingError as e:
                self.resultq.put({'addr': e.ip.src_addr.compressed, 'error': e.message})
            
def main():
    terminated = threading.Event()
    resultq = multiprocessing.Queue()
    for target in ['127.0.0.1', '192.168.12.1', '192.168.0.1', '1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', 'google.com']:
        PingMT(resultq=resultq, target=target, terminated=terminated).start()
    #
    analytics = PingAnalytics()
    try:
        while True:
            analytics.record(resultq.get())
    except KeyboardInterrupt:
        terminated.set()
        #sys.exit()

if __name__ == '__main__':
    main()