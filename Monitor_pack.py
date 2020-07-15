from scapy.all import *
import socket
import random
from Libs import name, threads
from colors import bcolors

dont_rep = []
router_ip = '192.168.0.1'


# Will be in the main thread

def MyIp():
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP
        rand_port = random.randrange(1, 1000)
        sock.connect((router_ip, rand_port))
        myip = sock.getsockname()[0]

        return myip
    except:
        pass


# not main
# this will be in another process to monitor packets


def mal_rec():
    my_ip = MyIp()
    pid = os.getpid()
    threads['monPack'] == pid


    try:
        while True:

            pack_file = rdpcap(name)
            for pak in pack_file:

                if pak.haslayer(IP):

                    try:
                        TCP_dst = pak.getlayer(IP).dst
                        TCP_src = pak.getlayer(IP).src
                        TCP_dport = pak.getlayer(IP).dport
                        TCP_sport = pak.getlayer(IP).sport

                        if int(TCP_sport) == 443 or int(TCP_dport) == 443 or int(TCP_sport) == 80 or int(
                                TCP_dport) == 80:
                            pass
                        else:
                            if int(TCP_sport) != 80 or int(TCP_sport) != 433:
                                if TCP_src == my_ip:
                                    pass
                                else:
                                    str_ = "{}[=] Possible Threat Connection {}::{} {}".format(bcolors.OKBLUE, TCP_src,
                                                                                               TCP_sport, bcolors.END)
                                    p_all = "dst: {}:{} src: {}:{}".format(TCP_dst, TCP_dport, TCP_src, TCP_sport)

                                    if str_ not in dont_rep:
                                        print(str_)
                                        print(p_all)
                                        dont_rep.append(str_)
                            elif int(TCP_dport) != 80 or int(TCP_dport) != 433:
                                if TCP_dst == my_ip:
                                    pass
                                else:

                                    str_ = "{}[=] Possible Threat Connection {}::{} {}".format(bcolors.OKBLUE, TCP_dst,
                                                                                               TCP_dport, bcolors.END)
                                    p_all = "dst: {}:{} src: {}:{}".format(TCP_dst, TCP_dport, TCP_src, TCP_sport)

                                    if str_ not in dont_rep:
                                        print(str_)
                                        print(p_all)
                                        dont_rep.append(str_)

                    except KeyboardInterrupt:
                        exit(0)
                    except:
                        pass
    except Exception as e:
        print(e)
