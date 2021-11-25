#!/usr/bin/env python3

# copied from a wigle.net kml download
KML_TEMPLATE = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<kml xmlns="http://www.opengis.net/kml/2.2" xmlns:gx="http://www.google.com/kml/ext/2.2" xmlns:xal="urn:oasis:names:tc:ciq:xsdschema:xAL:2.0" xmlns:atom="http://www.w3.org/2005/Atom">
    <Document>
        <name>WiGLE_Upload-20211123-00732</name>
        <Style id="highConfidence">
            <IconStyle id="highConfidenceStyle">
                <scale>1.0</scale>
                <heading>0.0</heading>
                <Icon>
                    <href>http://maps.google.com/mapfiles/ms/icons/green.png</href>
                    <refreshInterval>0.0</refreshInterval>
                    <viewRefreshTime>0.0</viewRefreshTime>
                    <viewBoundScale>0.0</viewBoundScale>
                </Icon>
            </IconStyle>
        </Style>
        <Style id="mediumConfidence">
            <IconStyle id="medConfidenceStyle">
                <scale>1.0</scale>
                <heading>0.0</heading>
                <Icon>
                    <href>http://maps.google.com/mapfiles/ms/icons/yellow.png</href>
                    <refreshInterval>0.0</refreshInterval>
                    <viewRefreshTime>0.0</viewRefreshTime>
                    <viewBoundScale>0.0</viewBoundScale>
                </Icon>
            </IconStyle>
        </Style>
        <Style id="lowConfidence">
            <IconStyle id="lowConfidenceStyle">
                <scale>1.0</scale>
                <heading>0.0</heading>
                <Icon>
                    <href>http://maps.google.com/mapfiles/ms/icons/red.png</href>
                    <refreshInterval>0.0</refreshInterval>
                    <viewRefreshTime>0.0</viewRefreshTime>
                    <viewBoundScale>0.0</viewBoundScale>
                </Icon>
            </IconStyle>
        </Style>
        <Style id="zeroConfidence">
            <IconStyle id="zeroConfidenceStyle">
                <scale>1.0</scale>
                <heading>0.0</heading>
                <Icon>
                    <href>https://maps.google.com/mapfiles/kml/pal2/icon18.png</href>
                    <refreshInterval>0.0</refreshInterval>
                    <viewRefreshTime>0.0</viewRefreshTime>
                    <viewBoundScale>0.0</viewBoundScale>
                </Icon>
            </IconStyle>
        </Style>
        <Style id="bluetoothClassic">
            <IconStyle id="bluetoothClassicStyle">
                <scale>1.0</scale>
                <heading>0.0</heading>
                <Icon>
                    <href>http://maps.google.com/mapfiles/ms/icons/blue.png</href>
                    <refreshInterval>0.0</refreshInterval>
                    <viewRefreshTime>0.0</viewRefreshTime>
                    <viewBoundScale>0.0</viewBoundScale>
                </Icon>
            </IconStyle>
        </Style>
        <Style id="bluetoothLe">
            <IconStyle id="bluetoothLeStyle">
                <scale>1.0</scale>
                <heading>0.0</heading>
                <Icon>
                    <href>http://maps.google.com/mapfiles/ms/icons/lightblue.png</href>
                    <refreshInterval>0.0</refreshInterval>
                    <viewRefreshTime>0.0</viewRefreshTime>
                    <viewBoundScale>0.0</viewBoundScale>
                </Icon>
            </IconStyle>
        </Style>
        <Style id="cell">
            <IconStyle id="cellStyle">
                <scale>1.0</scale>
                <heading>0.0</heading>
                <Icon>
                    <href>http://maps.google.com/mapfiles/ms/icons/pink.png</href>
                    <refreshInterval>0.0</refreshInterval>
                    <viewRefreshTime>0.0</viewRefreshTime>
                    <viewBoundScale>0.0</viewBoundScale>
                </Icon>
            </IconStyle>
        </Style>
        <Folder>
            <name>Wifi Networks</name>{placemarks}
        </Folder>
        <Folder>
            <name>Cellular Networks</name>
        </Folder>
        <Folder>
            <name>Bluetooth Networks</name>
        </Folder>
    </Document>
</kml>
'''
GPX_HEADER = '''<?xml version="1.0" encoding="UTF-8"?>
<gpx version="1.1" creator="convert.py - https://github.com/solsticedhiver/ssid-logger" xmlns="http://www.topografix.com/GPX/1/1">
    <metadata>
        <author>
            <name>solsTiCe d\'Hiver</name>
            <email>solstice.dhiver@gmail.com</email>
            <link>https://github.com/solsticedhiver/ssid-logger</link>
        </author>
        <time>{now}</time>
        <bounds minlat="{minlat}" minlon="{minlon}" maxlat="{maxlat}" maxlon="{maxlon}"/>
    </metadata>
    <trk>
        <trkseg>'''

import sqlite3
import argparse
from datetime import datetime
import os.path
import sys
import csv
import io

class Place:
    def __init__(self, mac, ssid, authmode, firstseen, channel, rssi, lat, lon, alt, acc, ttype):
        self.mac = mac
        self.ssid = ssid
        self.authmode = authmode
        try:
            firstseen.date()
            self.firstseen = firstseen
        except AttributeError:
            self.firstseen = datetime.strptime(firstseen, "%Y-%m-%d %H:%M:%S")
        self.channel = int(channel)
        self.rssi = int(rssi)
        self.lat = float(lat)
        self.lon = float(lon)
        self.alt = float(alt)
        self.acc = float(acc)
        self.type = ttype

    def __str__(self):
        return f'mac: {self.mac}, ssid: {self.ssid}, authmode: {self.authmode}, firstseen: {self.firstseen}, channel: {self.channel}, '+ \
            f'rssi: {self.rssi}, lat: {self.lat}, lon: {self.lon}, alt: {self.alt}, acc: {self.acc}'

def read_db(input_file):
    places = []
    try:
        conn = sqlite3.connect(f'file:{input_file}?mode=ro', uri=True, detect_types=sqlite3.PARSE_DECLTYPES)
        c = conn.cursor()
        sql = 'pragma query_only = on;'
        c.execute(sql)
        sql = 'pragma temp_store = 2;' # to store temp table and indices in memory
        c.execute(sql)
        sql = 'pragma journal_mode = off;' # disable journal for rollback (we don't use this)
        c.execute(sql)
        conn.commit()
    except sqlite3.DatabaseError as d:
        print(f'Error: {args.input} is not an sqlite3 db', file=sys.stderr)
        return places

    sql = '''select ap.bssid, ap.ssid, authmode.mode, ts, channel, rssi, lat, lon, alt, acc  from beacon
        inner join ap on ap.id=beacon.ap
        inner join authmode on authmode.id=beacon.authmode;'''
    c.execute(sql)

    row = c.fetchone()  # TODO: try/catch this one too
    while row is not None:
        tmp = list(row)
        if tmp[1] is None:
            try:
                row = c.fetchone()
            except sqlite3.OperationalError as o:
                pass
            continue
        tmp[3] = datetime.utcfromtimestamp(row[3])
        tmp[6] = f'{row[6]:-2.6f}'
        tmp[7] = f'{row[7]:-2.6f}'
        tmp[8] = f'{row[8]:-2.6f}'
        tmp[9] = f'{row[9]:-2.6f}'
        tmp.append('WIFI')
        places.append(Place(*tmp))
        try:
            row = c.fetchone()
        except sqlite3.OperationalError as o:
            pass

    conn.close()

    return places

def read_csv(input_file):
    places = []
    with open(input_file, 'r', encoding='utf-8') as csvfile:
        csvreader = csv.reader(csvfile, delimiter=',')
        # skip the 2 header lines
        next(csvreader)
        next(csvreader)
        for row in csvreader:
            places.append(Place(*row))
    return places

def write_kml(places, filename):
    with io.open(filename, mode='w', encoding='utf-8') as output_file:
        # don't use output_file.write(KML_TEMPLATE.format(placemarks=places_str))
        # to avoid a big string in memory
        header, footer = KML_TEMPLATE.format(placemarks='==CUT==').split('==CUT==')
        output_file.write(header)

        for place in places:
            encryption = 'Unknown'
            if 'WPA3' in place.authmode:
                encryption = 'WPA3'
            elif 'WPA2' in place.authmode:
                encryption = 'WPA2'
            elif 'WPA' in place.authmode:
                encryption = 'WPA'
            elif 'WEP' in place.authmode:
                encryption = 'WEP'
            elif 'ESS' in place.authmode:
                encryption = 'None'

            if place.acc > 10:
                confidence = '#lowConfidence'
            elif place.acc >= 6:
                confidence = '#mediumConfidence'
            elif place.acc < 6:
                confidence = '#highConfidence'

            placemark = f'''
            <Placemark>
                <name>{place.ssid}</name>
                <open>1</open>
                <description>Network ID: {place.mac.upper()}
Encryption: {encryption}
Time: {place.firstseen.isoformat()}
Signal: {place.rssi}
Accuracy: {place.acc}
Type: {place.type}</description>
                <styleUrl>{confidence}</styleUrl>
                <Point>
                    <coordinates>{place.lon},{place.lat}</coordinates>
                </Point>
            </Placemark>'''
            output_file.write(placemark)

        output_file.write(footer.lstrip('\n'))

def write_gpx(places, filename):
    now = datetime.utcnow()
    minlat = 360.0
    minlon = 360.0
    maxlat= 0.0
    maxlon = 0.0
    for place in places:
        if place.lat > maxlat: maxlat = place.lat
        if place.lon > maxlon: maxlon = place.lon
        if place.lat < minlat: minlat = place.lat
        if place.lon < minlon: minlon = place.lon

    with io.open(filename, mode='w', encoding='utf-8') as output_file:
        output_file.write(GPX_HEADER.format(now=now.isoformat(), minlat=minlat, minlon=minlon, maxlat=maxlat, maxlon=maxlon))
        for place in places:
            encryption = 'Unknown'
            if 'WPA3' in place.authmode:
                encryption = 'WPA3'
            elif 'WPA2' in place.authmode:
                encryption = 'WPA2'
            elif 'WPA' in place.authmode:
                encryption = 'WPA'
            elif 'WEP' in place.authmode:
                encryption = 'WEP'
            elif 'ESS' in place.authmode:
                encryption = 'None'

            trkpt = f'<trkpt lat="{place.lat}" lon="{place.lon}"/>'
            output_file.write(trkpt)
        output_file.write('</trkseg>\n</trk>\n')
        # also add waypoint ?
        for place in places:
            wpt = f'''    <wpt lat="{place.lat}" lon="{place.lon}">
        <ele>{place.alt}</ele>
        <time>{place.firstseen.isoformat()}</time>
        <cmt>Name: {place.ssid}
Network ID: {place.mac.upper()}
Encryption: {encryption}
Signal: {place.rssi}
Accuracy: {place.acc}
Type: {place.type}</cmt>
        <desc>Name: {place.ssid}
Network ID: {place.mac.upper()}
Encryption: {encryption}
Signal: {place.rssi}
Accuracy: {place.acc}
Type: {place.type}</desc>
    </wpt>\n'''
            output_file.write(wpt)
        output_file.write('</gpx>')

def main():
    parser = argparse.ArgumentParser(description='Convert sqlite3 beacon.db or csv file to kml or gpx GPS track file')
    parser.add_argument('-i', '--input', required=True, help='input file [sqlite3|csv]')
    parser.add_argument('-o', '--output', required=True, help='output file name [gpx|kml]')
    parser.add_argument('--force', action='store_true', default=False, help='force overwrite of existing file')
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f'Error: {args.input} not found', file=sys.stderr)
        sys.exit(-1)
    if os.path.exists(args.output) and not args.force:
        print(f'Error: {args.output} already exists. Use --force to overwrite', file=sys.stderr)
        sys.exit(-1)

    in_ext = os.path.splitext(args.input)[1]
    out_ext = os.path.splitext(args.output)[1]

    if in_ext == '.db':
        places = read_db(args.input)
    elif in_ext == '.csv':
        places = read_csv(args.input)
    else:
        print(f'Error: unknown extension {in_ext}', file=sys.stderr)
        sys.exit(-1)

    if out_ext == '.kml':
        write_kml(places, args.output)
    elif out_ext == '.gpx':
        write_gpx(places, args.output)
    else:
        print(f'Error: unknown extension {out_ext}', file=sys.stderr)
        sys.exit(-1)

if __name__ == '__main__':
    main()
