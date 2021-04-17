#!/usr/bin/python

# script that sends beacon for a (fake) AP

from scapy.all import Dot11,Dot11Beacon,Dot11Elt,RadioTap,sendp,hexdump

netSSID = 'testSSID' # network name here
iface = 'wlp0s20f0u1'  # interface name here

# Cipher suite selectors
# 00-0F-AC-00 Use group cipher suite
# 00-0F-AC-01 WEP (WEP-40)
# 00-0F-AC-02 TKIP
# 00-0F-AC-03 Reserved
# 00-0F-AC-04 CCMP-128
# 00-0F-AC-05 WEP-104
# 00-0F-AC-06 BIP-CMAC-128
# 00-0F-AC-07 Group address traffic not allowed
# 00-0F-AC-08 GCMP-128
# 00-0F-AC-09 GCMP-256
# 00-0F-AC-10 CCMP-256
# 00-0F-AC-11 BIP-GMAC-128
# 00-0F-AC-12 BIP-GMAC-256
# 00-0F-AC-13 BIP-CMAC-256
# 00-0F-AC-14-255 Reserved
# 00-0F-AC-06 BIP-CMAC-128
# Other OUI: vendor specific
#
# AKM suite selectors
# 00-0F-AC-00 Reserved
# 00-0F-AC-01 802.1X (EAP)
# 00-0F-AC-02 PSK
# 00-0F-AC-03 FT over 802.1x (EAP+FT)
# 00-0F-AC-04 FT with PSK (PSK+FT)
# 00-0F-AC-05 802.1X or PMKSA with SHA256 (EAP-SHA256 ?)
# 00-0F-AC-06 PSK-SHA256
# 00-0F-AC-07 TDLS
# 00-0F-AC-08 SAE-SHA256
# 00-0F-AC-09 FT over SAE-SHA256 (FT+SAE-SHA256 ?)
# 00-0F-AC-10 AP Peer Key Authentication
# 00-0F-AC-11 802.1X with suite B compliant EAP SHA-256
# 00-0F-AC-12 802.1X with suite B compliant EAP SHA-384
# 00-0F-AC-13 FT+802.1X with SHA-384
# 00-0F-AC-14-255 Reserved
# Other OUI: Vendor Specific

dot11 = Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2='22:22:22:22:22:22', addr3='33:33:33:33:33:33')
beacon = Dot11Beacon(cap='ESS+privacy')
essid = Dot11Elt(ID='SSID',info=netSSID, len=len(netSSID))
WPA2_PSK_CCMP_TKIP = [
    b'\x01\x00',
    b'\x00\x0f\xac\x04',
    b'\x02\x00',
    b'\x00\x0f\xac\x04',
    b'\x00\x0f\xac\x02',
    b'\x01\x00',
    b'\x00\x0f\xac\x02',
    b'\x00\x00']
WPA2_PSK_FT_PSK_CCMP_TKIP = [
    b'\x01\x00',
    b'\x00\x0f\xac\x04',
    b'\x02\x00',
    b'\x00\x0f\xac\x04',
    b'\x00\x0f\xac\x02',
    b'\x02\x00',
    b'\x00\x0f\xac\x02',
    b'\x00\x0f\xac\x04',
    b'\x00\x00']
WPA2_EAP_FT_EAP_CCMP_TKIP = [
    b'\x01\x00',
    b'\x00\x0f\xac\x04',
    b'\x02\x00',
    b'\x00\x0f\xac\x04',
    b'\x00\x0f\xac\x02',
    b'\x02\x00',
    b'\x00\x0f\xac\x01',
    b'\x00\x0f\xac\x03',
    b'\x00\x00']
WPA2_EAP_FT_EAP_CCMP_TKIP_PSK_FT_PSK_CCMP_TKIP = [
    b'\x01\x00',
    b'\x00\x0f\xac\x04',
    b'\x02\x00',
    b'\x00\x0f\xac\x04',
    b'\x00\x0f\xac\x02',
    b'\x04\x00',
    b'\x00\x0f\xac\x01',
    b'\x00\x0f\xac\x03',
    b'\x00\x0f\xac\x02',
    b'\x00\x0f\xac\x04',
    b'\x00\x00']
WPA2_PSK_SHA256_CCMP_TKIP = [
    b'\x01\x00',
    b'\x00\x0f\xac\x04',
    b'\x02\x00',
    b'\x00\x0f\xac\x04',
    b'\x00\x0f\xac\x02',
    b'\x01\x00',
    b'\x00\x0f\xac\x06',
    b'\x00\x00']
WPA2_PSK_FT_SHA256_CCMP_TKIP = [
    b'\x01\x00',
    b'\x00\x0f\xac\x04',
    b'\x02\x00',
    b'\x00\x0f\xac\x04',
    b'\x00\x0f\xac\x02',
    b'\x02\x00',
    b'\x00\x0f\xac\x06',
    b'\x00\x0f\xac\x08',
    b'\x00\x00']
WPA2_SAE_SHA256_CCMP = [
    b'\x01\x00',
    b'\x00\x0f\xac\x04',
    b'\x01\x00',
    b'\x00\x0f\xac\x04',
    b'\x01\x00',
    b'\x00\x0f\xac\x08',
    b'\x00\x00']
WPA2_EAP_PSK_CCMP_TKIP = [
    b'\x01\x00',
    b'\x00\x0f\xac\x04',
    b'\x02\x00',
    b'\x00\x0f\xac\x04',
    b'\x00\x0f\xac\x02',
    b'\x02\x00',
    b'\x00\x0f\xac\x01',
    b'\x00\x0f\xac\x02',
    b'\x00\x00']
rsn_bytes = b''.join(WPA2_PSK_CCMP_TKIP)
rsn = Dot11Elt(ID='RSNinfo', info=rsn_bytes, len=len(rsn_bytes))

frame = RadioTap()/dot11/beacon/essid/rsn

frame.show()
print("HexDump of frame:")
hexdump(frame)

sendp(frame, iface=iface, inter=0.100, loop=1)
