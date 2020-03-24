#!/usr/bin/env python3

import sqlite3
import csv
import argparse
from datetime import datetime

VERSION = '0.1'
CSV_HEADER_1 = ['WigleWifi-1.4', f'appRelease={VERSION}', 'model=ssid-logger',
    f'release={VERSION}', 'device=ssid-logger', 'display=ssid-logger',
    'board=ssid-logger', 'brand=ssid-logger']
CSV_HEADER_2 = ['MAC', 'SSID', 'AuthMode', 'FirstSeen', 'Channel', 'RSSI',
    'CurrentLatitude', 'CurrentLongitude', 'AltitudeMeters', 'AccuracyMeters', 'Type']

def main():
    parser = argparse.ArgumentParser(description='Convert sqlite3 beacon.db to a csv file')
    parser.add_argument('-i', '--input', required=True, help='input sqlite3 db file')
    parser.add_argument('-o', '--output', required=True, help='output csv file name')
    args = parser.parse_args()
    print(args.input)

    conn = sqlite3.connect(f'file:{args.input}?mode=ro', uri=True)
    c = conn.cursor()
    sql = 'pragma query_only = on;'
    c.execute(sql)
    sql = 'pragma temp_store = 2;' # to store temp table and indices in memory
    c.execute(sql)
    sql = 'pragma journal_mode = off;' # disable journal for rollback (we don't use this)
    c.execute(sql)
    conn.commit()

    sql = '''select ap.bssid, ap.ssid, authmode.mode, ts, channel, rssi, lat, lon, alt, acc  from beacon
        inner join ap on ap.id=beacon.ap
        inner join authmode on authmode.id=beacon.authmode;'''
    c.execute(sql)

    with open(args.output, 'w') as csvfile:
        csvwriter = csv.writer(csvfile, delimiter=',')
        csvwriter.writerow(CSV_HEADER_1)
        csvwriter.writerow(CSV_HEADER_2)
        for row in c.fetchall():
            tmp = list(row)
            tmp[3] = datetime.utcfromtimestamp(row[3])
            tmp[6] = f'{row[6]:-2.6f}'
            tmp[7] = f'{row[7]:-2.6f}'
            tmp[8] = f'{row[8]:-2.6f}'
            tmp[9] = f'{row[9]:-2.6f}'
            tmp.append('WIFI')
            csvwriter.writerow(tmp)

    conn.close()

if __name__ == '__main__':
    main()
