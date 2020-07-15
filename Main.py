from thread_class import *

SECS_TO_SNIFF = 1

print("[+] Monitoring The Whole Network")


def main():
    sniffer = sniffThread()

    writer = PcapThread()

    threads['main_thread'] = os.getpid()
    threads['writer_thread'] = writer.get_pid()
    threads['sniffer_thread'] = sniffer.get_pid()

    sniffer.start()
    writer.start()


try:
    main()

except KeyboardInterrupt:
    print("[-] Exiting")
    try:
        raise Exception
    except:
        pass
    sys.exit(0)

except Exception as e:
    print("[-] ERROR: ", e)
    sys.exit(0)
