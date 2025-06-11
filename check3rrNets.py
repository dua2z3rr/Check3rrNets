from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP
import argparse

# Variabili globali dichiarate qui
RHOSTS = []
PORTS = []
TOP_PORTS = 100
SYN_SCAN = False
CONNECT_SCAN = False
BANNER_SCAN = False
THREAD_SCAN = 50
TimeBetweenPackets = 0.2
FULLSCAN = True
EXCLUDE_PORTS = []
ONLY_OPEN = False
OUTPUT_FILE = "IPCheck3rd"
FORMAT = "txt"
VERBOSE = False
DEBUG = False
TIME_BETWEEN_PACKETS = 0.2
PACKETS_PER_SECOND = 5

conf.verb = 0

def start():
    parser = argparse.ArgumentParser(description="Options")
    parser.add_argument('-t', '--target', nargs='+', type=str, required=True, help="Specify target (IP, IP range or subnet)")
    groupPorts = parser.add_mutually_exclusive_group(required=False)
    groupPorts.add_argument('-p', '--ports', nargs='+', required=False, action='store', help="Define ports to scan")
    groupPorts.add_argument('-n', '--top-ports', type=int, required=False, default=100, action='store', help="Scan top N common ports") #TODO: insert top common ports list
    groupScan = parser.add_mutually_exclusive_group(required=True)
    groupScan.add_argument('-S', '--syn', required=False, default=True, action='store_true', help="TCP SYN scan (stealth)")
    groupScan.add_argument('-T', '--connect', required=False, default=False, action='store_true', help="TCP Connect scan")
    parser.add_argument('-b', '--banner', required=False, default=True, help="Activate service banner grabbing")
    parser.add_argument('-j', '--threads', type=int, required=False, help="Number of parallel threads")
    parser.add_argument('-x', '--exclude-ports', nargs='+', required=False, help="Exclude specified ports") #TODO: what if i exclude the ones i include with -p?
    parser.add_argument('-O', '--only-open', required=False, help="Show only open ports")
    parser.add_argument('-o', '--output',type=str, required=False, default="IPCheck3d", help="Output results file") #specify file name
    parser.add_argument('-f', '--format',type=str, required=False, default="txt", help="Output format (json/csv/txt)") #TODO: usable only if -o used
    parser.add_argument('-v', '--verbose', required=False, default=True, help="Verbose output")
    parser.add_argument('-d', '--debug', required=False, default=True, help="Debug mode")
    parser.add_argument('-w', '--time-between-packets', type=float, required=False, help="TimeBetweenPackets (default: 3 seconds)")
    parser.add_argument('-r', '--packets-per-second',type=int, required=False, help="Limit packets/second")
    args = parser.parse_args()

    if(args.target):
        global RHOSTS
        RHOSTS = list(map(str, args.target))

    if(args.ports):
        global PORTS
        PORTS = list(map(str, args.ports))

    if(args.top_ports):
        global TOP_PORTS
        TOP_PORTS = args.top_ports

    if(args.syn):
        global SYN_SCAN
        SYN_SCAN = args.syn

    if(args.connect):
        global CONNECT_SCAN
        CONNECT_SCAN = args.connect

    if(args.banner):
        global BANNER_SCAN
        BANNER_SCAN = args.banner

    if(args.threads):
        global THREAD_SCAN
        THREAD_SCAN = args.threads

    if(args.exclude_ports):
        global EXCLUDE_PORTS
        EXCLUDE_PORTS = list(map(str, args.exclude_ports))

    if(args.only_open):
        global ONLY_OPEN
        ONLY_OPEN = args.only_open

    if(args.output):
        global OUTPUT_FILE
        OUTPUT_FILE = args.output

    if(args.format):
        global FORMAT
        FORMAT = args.format

    if(args.verbose):
        global VERBOSE
        VERBOSE = args.verbose

    if(args.debug):
        global DEBUG
        DEBUG = args.debug

    if (args.time_between_packets):
        global TIME_BETWEEN_PACKETS
        TIME_BETWEEN_PACKETS = args.time_between_packets

    if(args.packets_per_second):
        global PACKETS_PER_SECOND
        PACKETS_PER_SECOND = args.packets_per_second

    return 0

def scan():
    for host in RHOSTS:
        if (("-" in host) & (host.count("-") == 1)):

            RHOSTS.remove(host)

            parts = host.split("-")
            ip1 = parts[0].split(".")
            ip2 = parts[1].split(".")

            for i in [0, 1, 2, 3]:
                ip1[i] = int(ip1[i])
                ip2[i] = int(ip2[i])

            if(ip1[0] != ip2[0]):
                print("Error: first octet of the two IPs must be the same")
                return 1

            RHOSTS.append(str(ip1[0]) + "." + str(ip1[1]) + "." + str(ip1[2]) + "." + str(ip1[3]))

            while(int(ip1[0]) != int(ip2[0]) or int(ip1[1]) != int(ip2[1]) or int(ip1[2]) != int(ip2[2]) or int(ip1[3]) != int(ip2[3])):
                ip1[3] = int(ip1[3]) + 1
                if(ip1[3] == 255):
                    ip1[3] = 0
                    ip1[2] = int(ip1[2]) + 1
                    if(ip1[2] == 256):
                        ip1[2] = 0
                        ip1[1] = int(ip1[1]) + 1
                        if(ip1[1] == 256):
                            ip1[1] = 0
                            ip1[0] = int(ip1[0]) + 1
                            if(ip1[0] == 256):
                                print("Error: first octet of the two IPs must be the same")
                                return 1

                if(ip1[3] == 0):
                    ip1[3] = int(ip1[3]) + 1

                RHOSTS.append(str(ip1[0]) + "." + str(ip1[1]) + "." + str(ip1[2]) + "." + str(ip1[3]))


    for host in RHOSTS:
        print("Scanning host: " + host)


start()
scan()