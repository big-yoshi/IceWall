print("[*] Importing Modules")
from scapy.all import *
import playsound
import sys
import threading
import multiprocessing
import time
from colors import bcolors
from socket import gethostbyaddr as gha
import datetime
import os.path
import os

print("[+] Modules Got Imported", time.process_time())
bc = bcolors

###########

threads = {}

proc = []

dt_date = datetime.datetime.now().date()
dt_time = datetime.datetime.now().time()

pk_path = 'packet/'
if !os.path.exists('packet'):
    os.mkdir('packet')

pk_dir_ = pk_path + str(dt_date) + '/'

pk_dirs = pk_path + str(dt_date)
if os.path.exists(pk_dirs):
    pass
else:
    os.mkdir(pk_dirs)

name = pk_dir_ + str(dt_time).replace(":", "-").split('.')[0] + ".pcap"


###########


def sniff_4_TCP(Payload=False):
    TCP_dst = None
    TCP_src = None
    TCP_dport = None
    TCP_sport = None
    while True:
        packet = sniff(count=1)
        for pck in packet:

            if pck.haslayer(TCP):

                TCP_dst = pck[IP].dst
                TCP_src = pck[IP].src
                TCP_dport = pck[IP][TCP].dport
                TCP_sport = pck[IP][TCP].sport
                tcp_string = str("\n[{}] src: {}::{}-{}   |   dst: {}::{}-{}\n").format(str(time.ctime()), TCP_src,
                                                                                        TCP_sport,
                                                                                        get_domain(TCP_src),
                                                                                        TCP_dst, TCP_dport,
                                                                                        get_domain(TCP_dst))

                print(tcp_string)
                if Payload:
                    print(packet.hexdump())
                print("-" * 60)


def get_domain(ip):
    try:
        host = gha(ip)[0]
        host = str(host)
        return host
    except:
        return ''


def w_packet():
    while True:
        packet = sniff(count=1)
        wrpcap(name, packet, append=True)


def mainSHell():
    while True:
        cmd = input("shell-->> ")
        print(cmd)
        if "help" in str(cmd):
            print(
                """help  to show command
                start    [ monpack: a packet monitor built to detect malware packets
                         tcpsniffer: sniff for tcp packets and payloads ]
                exit     exit the shell
                """)
        if 'pids' in str(cmd):
            print(threads)
