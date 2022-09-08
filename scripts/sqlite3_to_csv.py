#!/usr/bin/env python3

import sqlite3
import csv
import argparse
from datetime import datetime
import time
import os.path
import sys
import shlex

VERSION = '0.3.0'
CSV_PRE_HEADER = 'WigleWifi-1.4,appRelease={},model={},release={},device=ssid-logger,display=ssid-logger,board=ssid-logger,brand=ssid-logger'
CSV_HEADER = ['MAC', 'SSID', 'AuthMode', 'FirstSeen', 'Channel', 'RSSI',
    'CurrentLatitude', 'CurrentLongitude', 'AltitudeMeters', 'AccuracyMeters', 'Type']

# borrowed from distro.py module
def _parse_os_release_content():
    props = {'version_id': 'unknown', 'id': 'linux'}
    if os.path.exists('/etc/os-release'):
        path = '/etc/os-release'
    elif os.path.exists('/usr/lib/os-release'):
        path = '/usr/lib/os-release'
    else:
        return props

    with open(path, 'r') as lines:
        lexer = shlex.shlex(lines, posix=True)
        lexer.whitespace_split = True

        tokens = list(lexer)
        for token in tokens:
            if '=' in token:
                k, v = token.split('=', 1)
                props[k.lower()] = v
            else:
                pass
    return props

def process_text(data):
    try:
        ret = data.decode('utf-8')
        return ret
    except UnicodeDecodeError:
        return None
# use our converter for text to skip ssid with unparsable utf-8
sqlite3.register_converter('text', process_text)

def main():
    parser = argparse.ArgumentParser(description='Convert sqlite3 beacon.db to a csv file')
    parser.add_argument('-a', '--after', help='filter beacon with timestamp more recent than AFTER (YYYY-mm-dd[THH:MM])')
    parser.add_argument('-b', '--before', help='filter beacon with timestamp older than BEFORE (YYYY-mm-dd[THH:MM])')
    parser.add_argument('-i', '--input', required=True, help='input sqlite3 db file')
    parser.add_argument('--force', action='store_true', default=False, help='force overwrite of existing file')
    parser.add_argument('-o', '--output', required=True, help='output csv file name')
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f'Error: {args.input} not found', file=sys.stderr)
        sys.exit(-1)
    if os.path.exists(args.output) and not args.force:
        print(f'Error: {args.output} already exists. Use --force to overwrite', file=sys.stderr)
        sys.exit(-1)

    if args.after:
        try:
            start_time = time.mktime(time.strptime(args.after, '%Y-%m-%dT%H:%M'))
        except  ValueError:
            try:
                date = time.strptime(args.after, '%Y-%m-%d')
                date = time.strptime('%sT00:00' % args.after, '%Y-%m-%dT%H:%M')
                start_time = time.mktime(date)
            except ValueError:
                print(f"Error: can't parse {args.after} timestamp (expected format YYYY-mm-dd[THH:MM])", file=sys.stderr)
                sys.exit(-1)
    if args.before:
        try:
            end_time = time.mktime(time.strptime(args.before, '%Y-%m-%dT%H:%M'))
        except  ValueError:
            try:
                date = time.strptime(args.before, '%Y-%m-%d')
                date = time.strptime('%sT00:00' % args.before, '%Y-%m-%dT%H:%M')
                end_time = time.mktime(date)
            except ValueError:
                print(f"Error: can't parse {args.before} timestamp (expected format YYYY-mm-dd[THH:MM])", file=sys.stderr)
                sys.exit(-1)

    try:
        conn = sqlite3.connect(f'file:{args.input}?mode=ro', uri=True, detect_types=sqlite3.PARSE_DECLTYPES)
        c = conn.cursor()
        sql = 'pragma query_only = on;'
        c.execute(sql)
        sql = 'pragma temp_store = 2;' # to store temp table and indices in memory
        c.execute(sql)
        sql = 'pragma journal_mode = off;' # disable journal for rollback (we don't use this)
        c.execute(sql)
        conn.commit()
    except sqlite3.DatabaseError as d:
        print(f'Error: {args.input} is not an sqlite3 db ({d})', file=sys.stderr)
        sys.exit(-1)

    sql = '''select ap.bssid, ap.ssid, authmode.mode, ts, channel, rssi, lat, lon, alt, acc  from beacon
        inner join ap on ap.id=beacon.ap
        inner join authmode on authmode.id=beacon.authmode;'''
    c.execute(sql)

    props = _parse_os_release_content()
    with open(args.output, 'w', encoding='utf-8') as csvfile:
        csvwriter = csv.writer(csvfile, delimiter=',')
        csvwriter.writerow(CSV_PRE_HEADER.format(VERSION, props['id'], props['version_id']).split(','))
        csvwriter.writerow(CSV_HEADER)
        row = c.fetchone()  # TODO: try/catch this one too
        while row is not None:
            tmp = list(row)
            if tmp[1] is None:
                try:
                    row = c.fetchone()
                except sqlite3.OperationalError as o:
                    pass
                continue
            if args.after and tmp[3] < start_time:
                continue
            if args.before and tmp[3] > end_time:
                continue
            tmp[3] = datetime.utcfromtimestamp(row[3])
            tmp[6] = f'{row[6]:-2.6f}'
            tmp[7] = f'{row[7]:-2.6f}'
            tmp[8] = f'{row[8]:-2.6f}'
            tmp[9] = f'{row[9]:-2.6f}'
            tmp.append('WIFI')
            csvwriter.writerow(tmp)
            try:
                row = c.fetchone()
            except sqlite3.OperationalError as o:
                pass

    conn.close()

if __name__ == '__main__':
    main()
