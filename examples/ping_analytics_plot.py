#!/usr/local/bin/python3
# encoding: utf-8

import datetime
import sqlite3
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import matplotlib.ticker as ticker

def main():
    db = sqlite3.connect('ping_analytics_1.db')
    db.row_factory = sqlite3.Row
    cursor = db.cursor()

    x = []
    y = {}

    for row in cursor.execute("SELECT addr FROM histories GROUP BY addr").fetchall():
        y[row['addr']] = []

    from_epoch = int(datetime.datetime.fromisoformat('2024-12-01 00:00:00').timestamp())
    to_epoch = int(datetime.datetime.fromisoformat('2024-12-06 00:00:00').timestamp())
    for t in range(from_epoch, to_epoch, 5):
        x.append(datetime.datetime.fromtimestamp(t))
        for addr in y.keys():
            row = cursor.execute("SELECT ifnull(roundtrip, 0.0) AS roundtrip FROM histories WHERE not error AND addr = ? AND epoch = ?", (addr, t, )).fetchone()
            if row is not None:
                y[addr].append(row['roundtrip'])
            else:
                y[addr].append(None)
    
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
    fig.savefig('ping_analytics_00.png', dpi=200)

if __name__ == '__main__':
    main()