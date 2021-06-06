from scapy.all import *
import argparse
import traceback

'''
steganoDetector
Detecting if pcap file given 
in argument contains ARP attack
'''

mac = ""
ip = ""
macIpMap = {}

# defining function to process packet
def process_sniffed_packet(packet):
    global mac, ip, macIpMap
    if ARP in packet and packet[ARP].op in (1,2): #who-has or is-at
       # get mac and ip address of packet
        mac = packet.hwsrc
        ip = packet.psrc
    # comparing values of MAC Addresses macIpMap[ip] = mac
    if any(ip in dict for dict in macIpMap):
        if macIpMap[ip] != mac:
            attacked = True
        else:
            attacked = False
    else:
        macIpMap[ip] = mac
        attacked = False
    return attacked


parser = argparse.ArgumentParser()
parser.add_argument("-f", "--file", help="Path to file to be checked")
parser.parse_args()
args = parser.parse_args()

file = args.file

pkts = sniff(offline=file)


def main():
    for pkt in pkts:
        try:
            attacked = process_sniffed_packet(pkt)
            if attacked:
                print("!!! You are under ARP attack!")
                print("Ip address: " + ip)
                print("Previous mac address: " + macIpMap[ip])
                print("Current mac address: " + mac)
                return

        except:
            pass
    print("Everything is fine")
    return


if __name__ == '__main__':
    main()
