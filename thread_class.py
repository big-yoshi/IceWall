from Libs import *
from Monitor_pack import *
import sys
import os
import multiprocessing


class sniffThread(threading.Thread):

    def __init__(self):
        Thread.__init__(self)

        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def stopped(self):
        return self._stop_event.is_set()

    def run(self):
        print("[+] SnifferThread is Active now")
        sniff_4_TCP()

    def exit_thread(self):
        sys.exit(1)

    def get_pid(self):
        return os.getpid()


class PcapThread(threading.Thread):

    def __init__(self):
        Thread.__init__(self)

        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def stopped(self):
        return self._stop_event.is_set()

    def run(self):
        print("[+] WriterThread is Active now ")
        w_packet()

    def exit_thread(self):
        sys.exit(1)

    def get_pid(self):
        return os.getpid()


class shellThread(threading.Thread):
    def __init__(self):
        Thread.__init__(self)

    def run(self):
        lo = ''

    def exit_thread(self):
        sys.exit(1)

    def get_pid(self):
        return os.getpid()

class monPack():
    def __init__(self):
        self.pid = ''
    def run(self):
        mlp = multiprocessing.Process(target=mal_rec,args=())
        mlp.daemon = True
        mlp.start()
        mlp.join()



