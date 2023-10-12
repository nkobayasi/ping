#!/usr/local/bin/python3
# encoding: utf-8

import argparse
import logging
import ping as pinglib

class StderrHandler(logging.StreamHandler):
    def __init__(self):
        super().__init__()
        self.setFormatter(logging.Formatter('[%(process)d] %(message)s'))

logger = logging.getLogger('ping').getChild('cli')
logger.addHandler(StderrHandler())

class Option(object):
    def __init__(self):
        parser = argparse.ArgumentParser(prog='ping3', description='A pure python3 version of ICMP ping implementation using raw socket.', epilog='!!Note!! ICMP messages can only be sent from processes running as root.')
        parser.add_argument('-v', '--version', action='version', version=pinglib.__version__)
        parser.add_argument('-c', '--count', dest='count', metavar='COUNT', type=int, default=4, help='How many pings should be sent. Default is %(default)s.')
        parser.add_argument('-t', '--timeout', dest='timeout', metavar='TIMEOUT', type=float, default=4, help='Time to wait for a response, in seconds. Default is %(default)s.')
        parser.add_argument('-i', '--interval', dest='interval', metavar='INTERVAL', type=float, default=1.0, help='Time to wait between each packet, in seconds. Default is %(default)s.')
        parser.add_argument('-I', '--interface', dest='interface', metavar='INTERFACE', default='', help='LINUX ONLY. The gateway network interface to ping from. Default is "%(default)s".')
        parser.add_argument('-S', '--src', dest='src_addr', metavar='SRC_ADDR', default='', help='The IP address to ping from. This is for multiple network interfaces. Default is "%(default)s".')
        parser.add_argument('-T', '--ttl', dest='ttl', metavar='TTL', type=int, default=64, help='The Time-To-Live of the outgoing packet. Default is %(default)s.')
        parser.add_argument('-s', '--size', dest='size', metavar='SIZE', type=int, default=56, help='The ICMP packet payload size in bytes. Default is %(default)s.')
        parser.add_argument('-D', '--debug', action='store_true', dest='debug', help='Turn on DEBUG mode.')
        parser.add_argument('-E', '--exceptions', action='store_true', dest='exceptions', help='Turn on EXCEPTIONS mode.')
        parser.add_argument(dest='dest_addr', metavar='DEST_ADDR', nargs='*', default=['localhost', '127.0.0.1'], help='The destination address, can be an IP address or a domain name. Ex. 192.168.1.1/example.com.')
        self.args = parser.parse_args()

def main():
    option = Option()
    if option.args.debug:
        logging.getLogger('ping').setLevel(logging.DEBUG)
        logger.debug(option.args)
    for addr in option.args.dest_addr:
        print(pinglib.ping(addr, times=option.args.count, interval=option.args.interval, ttl=option.args.ttl, size=option.args.size))

if __name__ == '__main__':
    main()