#!/usr/local/bin/python3
# encoding: utf-8

import datetime
import sqlite3
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import matplotlib.ticker as ticker

def main():
    db = sqlite3.connect('ping_analytics.db')
    db.row_factory = sqlite3.Row
    cursor = db.cursor()

    x = []
    y = {'192.168.0.1': [], '8.8.8.8': []}

    from_epoch = int(datetime.datetime.fromisoformat('2025-08-18 21:00:00').timestamp())
    to_epoch = int(datetime.datetime.fromisoformat('2025-08-19 09:00:00').timestamp())
    for row in cursor.execute("SELECT epoch FROM histories WHERE not error AND addr = '127.0.0.1' AND epoch BETWEEN ? AND ? ORDER BY epoch", (from_epoch, to_epoch, )).fetchall():
        x.append(datetime.datetime.fromtimestamp(row['epoch']))
        for addr in y.keys():
            _ = cursor.execute("SELECT roundtrip FROM histories WHERE not error AND addr = ? AND epoch = ?", (addr, row['epoch'], )).fetchone()
            if _ is None or _['roundtrip'] < 0.1:
                y[addr].append(None)
            else:
                y[addr].append(_['roundtrip'])

    fig, ax = plt.subplots(figsize=(12.8, 4.8), layout='constrained')
    for addr in y.keys():
        ax.plot(x, y[addr], 'o', markersize=0.2, label=addr)
    ax.set_xlabel('Date/Time', fontsize=6.0)
    ax.set_ylabel('RTT [ms]', fontsize=6.0)
    ax.xaxis.set_major_formatter(mdates.DateFormatter('%m/%d %H:%M'))
    ax.xaxis.set_minor_locator(ticker.AutoMinorLocator(n=6))
    ax.tick_params('both', labelsize=5.0)
    ax.tick_params('x', labelrotation=45)
    ax.set_title('Ping Round Trip Time', fontsize='small')
    ax.legend(fontsize='xx-small', markerscale=5.0)
    fig.savefig('ping_analytics.png', dpi=200)

if __name__ == '__main__':
    main()