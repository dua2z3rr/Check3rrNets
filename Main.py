from scapy.all import *
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, ICMP, TCP
from sympy import false

help_message = """-t: Specify target (IP, IP range or subnet) (default: loopback)
-p: Define ports to scan (single, range or list) (default: all)
-n: Scan top N common ports (default: 100)
-S: TCP SYN scan (stealth)
-T: TCP Connect scan
-b: Activate service banner grabbing
-j: Number of parallel threads (default: 50)
-w: TimeBetweenPackets (default: 3 seconds)
-x: Exclude specified ports
-O: Show only open ports
-o: Output results file
-f: Output format (json/csv/txt)
-v: Verbose output
-d: Debug mode
-c: Load configuration from file
-s: Save current configuration
-r: Limit packets/second
-R: Random port order
-l: Preset scan list (fast/complete)"""

global RHOSTS
global TimeBetweenPackets
global FULLSCAN
global PORTS

RHOSTS = []
TimeBetweenPackets = 0.2
FULLSCAN = True
PORTS = []

conf.verb = 0

def start():
    global RHOSTS, TimeBetweenPackets, FULLSCAN, PORTS
    input_str = input("insert options for scan (-h for help):")
    options = [opt for opt in input_str.split("-") if opt.strip() != ""]
    print(options)
    return options

def optionsEvaluation(options):
    global RHOSTS, TimeBetweenPackets, FULLSCAN, PORTS
    for option in options:
        optionArray = option.split(" ")
        match optionArray[0]:
            case "h":
                print(help_message)
                return 0;
            case "t":
                for ip in optionArray[1:]:
                    if(ip != " "):
                        RHOSTS.append(ip)
            case "p":
                FULLSCAN = False
                for port in optionArray[1:]:
                    if(port != " "):
                        PORTS.append(int(port))
            case "n":
                print()
            case "S":
                print()
            case "T":
                print()
            case "b":
                print()
            case "j":
                print()
            case "w":
                if(optionArray[1].type() == int | optionArray[1].type() == float):
                    TIMEOUT = optionArray[1]
                    FULLSCAN = False
                else:
                    print("MUST BE A NUMBER!")
            case "x":
                print()
            case "O":
                print()
            case "o":
                print()
            case "f":
                print()
            case "v":
                print()
            case "d":
                print()
            case "c":
                print()
            case "s":
                print()
            case "r":
                print()
            case "R":
                print()
            case "l":
                print()

    return None

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


optionsEvaluation(start())
scan()

