#!/usr/bin/python

# script that sends beacon for a (fake) AP

from scapy.all import Dot11,Dot11Beacon,Dot11Elt,RadioTap,sendp,hexdump

netSSID = 'testSSID' # network name here
iface = 'wlp0s20u2'  # interface name here

dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2='22:22:22:22:22:22', addr3='33:33:33:33:33:33')
beacon = Dot11Beacon(cap='ESS+privacy')
essid = Dot11Elt(ID='SSID',info=netSSID, len=len(netSSID))
WPA2_PSK_CCMP_TKIP = [b'\x01\x00',
    b'\x00\x0f\xac\x04',
    b'\x02\x00',
    b'\x00\x0f\xac\x04',
    b'\x00\x0f\xac\x02',
    b'\x01\x00',
    b'\x00\x0f\xac\x02',
    b'\x00\x00']
WPA2_PSK_FT_PSK_CCMP_TKIP = [b'\x01\x00',
    b'\x00\x0f\xac\x04',
    b'\x02\x00',
    b'\x00\x0f\xac\x04',
    b'\x00\x0f\xac\x02',
    b'\x02\x00',
    b'\x00\x0f\xac\x02',
    b'\x00\x0f\xac\x04',
    b'\x00\x00']
WPA2_EAP_FT_EAP_CCMP_TKIP = [b'\x01\x00',
    b'\x00\x0f\xac\x04',
    b'\x02\x00',
    b'\x00\x0f\xac\x04',
    b'\x00\x0f\xac\x02',
    b'\x02\x00',
    b'\x00\x0f\xac\x01',
    b'\x00\x0f\xac\x03',
    b'\x00\x00']
WPA2_PSK_SHA256_CCMP_TKIP = [b'\x01\x00',
    b'\x00\x0f\xac\x04',
    b'\x02\x00',
    b'\x00\x0f\xac\x04',
    b'\x00\x0f\xac\x02',
    b'\x01\x00',
    b'\x00\x0f\xac\x06',
    b'\x00\x00']
rsn_bytes = b''.join(WPA2_PSK_CCMP_TKIP)
rsn = Dot11Elt(ID='RSNinfo', info=rsn_bytes, len=len(rsn_bytes))

frame = RadioTap()/dot11/beacon/essid/rsn

frame.show()
print("HexDump of frame:")
hexdump(frame)

sendp(frame, iface=iface, inter=0.100, loop=1)
