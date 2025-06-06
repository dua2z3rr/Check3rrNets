from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP
import argparse

global RHOSTS
global TimeBetweenPackets
global FULLSCAN
global PORTS

RHOSTS = []
TimeBetweenPackets = 0.2
FULLSCAN = True

conf.verb = 0

def start():
    parser = argparse.ArgumentParser(description="Options")
    parser.add_argument('-t', '--target', type=str, required=True, help="Specify target (IP, IP range or subnet)")
    groupPorts = parser.add_mutually_exclusive_group(required=False)
    groupPorts.add_argument('-p', '--ports', nargs='+', required=False, action='store', default="", help="Define ports to scan")
    groupPorts.add_argument('-n', '--top-ports', type=int, required=False, default=100, action='store', help="Scan top N common ports") #TODO: insert top common ports list
    groupScan = parser.add_mutually_exclusive_group(required=True)
    groupScan.add_argument('-S', '--syn', required=False, default=True, action='store_true', help="TCP SYN scan (stealth)")
    groupScan.add_argument('-T', '--connect', required=False, default=False, action='store_true', help="TCP Connect scan")
    parser.add_argument('-b', '--banner', required=False, default=True, help="Activate service banner grabbing")
    parser.add_argument('-j', '--threads', type=int, required=False, default=50, help="Number of parallel threads")
    parser.add_argument('-w', '--time-between-packets', type=float, required=False, default=0.2, help="TimeBetweenPackets (default: 3 seconds)")
    parser.add_argument('-x', '--exclude-ports',type=str, required=False, default="", help="Exclude specified ports") #TODO: what if i exclude the ones i include with -p?
    parser.add_argument('-O', '--only-open', required=False, help="Show only open ports")
    parser.add_argument('-o', '--output',type=str, required=False, default="IPCheck3d", help="Output results file") #specify file name
    parser.add_argument('-f', '--format',type=str, required=False, default="txt", help="Output format (json/csv/txt)") #TODO: usable only if -o used
    parser.add_argument('-v', '--verbose', required=False, default=True, help="Verbose output")
    parser.add_argument('-d', '--debug', required=False, default=True, help="Debug mode")
    parser.add_argument('-r', '--packets-per-second',type=int, required=False, help="Limit packets/second")
    args = parser.parse_args()

    PORTS = list(map(str, args.ports))

    print(PORTS)

    return 0

def scan():
    global RHOSTS, TimeBetweenPackets, FULLSCAN, PORTS

    for RHOST in RHOSTS:
        print("-------------------- connecting to %s --------------------" % RHOST)

        if(FULLSCAN):
            print("fullscan mode")
            for i in range(65545):
                ip = IP(dst=RHOST)  # Target IP
                tcp = TCP(dport=i, flags="S")
                packet = ip / tcp  # Full packet
                send(packet, count=1, inter=TimeBetweenPackets, verbose=0)
                response = sr1(packet, timeout=2)  # Send and wait for one reply
                if response and response.haslayer(TCP) and response[IP].src == RHOST and response[TCP].flags == 0x12:  # SYN-ACK ricevuto dal target
                    print(f"Port {tcp.dport} open")

        else:
            print("NOT fullscan mode")
            for i in PORTS:
                #eth = Ether(dst="?????????")  # Ethernet broadcast
                ip = IP(dst=RHOST)  # Target IP
                icmp = ICMP(type=8)  # ICMP layer TODO
                packet = ip / icmp  # Full packet

                print(packet)

                send(packet, count=10, inter=TimeBetweenPackets)

start()
#scan()
