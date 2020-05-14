#!/usr/bin/python

# extract a beacon frame from a pcap file for each authmode found in wiglewifi.csv

import sys
import csv
from scapy.all import *

if sys.argv[1] == '-h' or sys.argv[1] == '--help' or len(sys.argv) != 4:
    print('Usage: extract-pcap.py PCAP_IN WIGLEWIFI PCAP_OUT')
    sys.exit(1)

authmode = set()
with open(sys.argv[2], encoding='utf-8', errors='ignore') as f:
    csvreader = csv.reader(f, delimiter=',')
    next(csvreader) # skip first 2 lines
    next(csvreader)
    while True:
        try:
            row = next(csvreader)
            if row[-1] == 'WIFI':
                authmode.add(row[2])
        except csv.Error as c:
            pass
        except StopIteration as s:
            break

authmode.discard('')

print(':: reading csv file')
with open(sys.argv[2], encoding='utf-8', errors='ignore') as f:
    flines = f.readlines()

print(':: reading pcap file')
packets = rdpcap(sys.argv[1])

print(':: looking for packet for each authmode')
number = []
for a in sorted(list(authmode)):
    # print(f':: looking packet for {a} authmode')
    found = False
    for line in flines:
        if f',{a},' in line:
            mac = line.split(',')[0]
            # look up beacon with mac in pcap file
            for i,p in enumerate(packets):
                if p.haslayer(Dot11) :
                    if p.type == 0 and p.subtype == 8:
                        if p.addr2 == mac:
                            number.append(i)
                            found = True
                            print(f'found packet for {mac} and authmode {a}')
                            break
            if found:
                break
    if not found:
        print(f':: missing beacon frame for {a} authmode')

#print(number)
wrpcap(sys.argv[3], [packets[i] for i in number])
