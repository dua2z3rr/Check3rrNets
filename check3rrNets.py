from scapy.all import *
from scapy.layers.inet import IP, ICMP, TCP, UDP
import argparse

common_tcp_ports = [
    1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 25, 26, 30, 32, 33, 37, 42, 43,
    49, 53, 70, 79, 80, 81, 82, 83, 84, 85, 88, 89, 90, 99, 100, 106, 109, 110, 111,
    113, 119, 125, 135, 139, 143, 144, 146, 161, 163, 179, 199, 211, 212, 222, 254, 255,
    256, 259, 264, 280, 301, 306, 311, 340, 366, 389, 406, 407, 416, 417, 425, 427, 443,
    444, 445, 458, 464, 465, 481, 497, 500, 512, 513, 514, 515, 524, 541, 543, 544, 545,
    548, 554, 555, 563, 587, 593, 616, 617, 625, 631, 636, 646, 648, 666, 667, 668, 683,
    687, 691, 700, 705, 711, 714, 720, 722, 726, 749, 765, 777, 783, 787, 800, 801, 808,
    843, 873, 880, 888, 898, 900, 901, 902, 903, 911, 912, 981, 987, 990, 992, 993, 995,
    999, 1000, 1001, 1002, 1007, 1009, 1010, 1011, 1021, 1022, 1023, 1024, 1025, 1026,
    1027, 1028, 1029, 1030, 1031, 1032, 1033, 1034, 1035, 1036, 1037, 1038, 1039, 1040,
    1041, 1042, 1043, 1044, 1045, 1046, 1047, 1048, 1049, 1050, 1051, 1052, 1053, 1054,
    1055, 1056, 1057, 1058, 1059, 1060, 1061, 1062, 1063, 1064, 1065, 1066, 1067, 1068,
    1069, 1070, 1071, 1072, 1073, 1074, 1075, 1076, 1077, 1078, 1079, 1080, 1081, 1082,
    1083, 1084, 1085, 1086, 1087, 1088, 1089, 1090, 1091, 1092, 1093, 1094, 1095, 1096,
    1097, 1098, 1099, 1100, 1102, 1104, 1105, 1106, 1107, 1108, 1110, 1111, 1112, 1113,
    1114, 1117, 1119, 1121, 1122, 1123, 1124, 1126, 1130, 1131, 1132, 1137, 1138, 1141,
    1145, 1147, 1148, 1149, 1151, 1152, 1154, 1163, 1164, 1165, 1166, 1169, 1174, 1175,
    1183, 1185, 1186, 1187, 1192, 1198, 1199, 1201, 1213, 1216, 1217, 1218, 1233, 1234,
    1236, 1244, 1247, 1248, 1259, 1271, 1272, 1277, 1287, 1296, 1300, 1301, 1309, 1310,
    1311, 1322, 1328, 1334, 1352, 1417, 1433, 1434, 1443, 1455, 1461, 1494, 1500, 1501,
    1503, 1521, 1524, 1533, 1556, 1580, 1583, 1594, 1600, 1641, 1658, 1666, 1687, 1688,
    1700, 1717, 1718, 1719, 1720, 1721, 1723, 1755, 1761, 1782, 1783, 1801, 1805, 1812,
    1839, 1840, 1862, 1863, 1864, 1875, 1900, 1914, 1935, 1947, 1971, 1972, 1974, 1984,
    1998, 1999, 2000
]

common_udp_ports = [
    7, 9, 13, 17, 19, 21, 22, 23, 37, 42, 49, 53, 67, 68, 69, 80, 88, 111, 120,
    123, 135, 137, 138, 139, 143, 161, 162, 177, 389, 443, 445, 500, 514, 515, 520,
    523, 546, 547, 554, 623, 626, 631, 636, 749, 853, 902, 989, 990, 996, 997, 999,
    1001, 1010, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1043, 1060, 1068,
    1419, 1433, 1434, 1645, 1646, 1701, 1718, 1719, 1789, 1812, 1813, 1900, 2000,
    2048, 2049, 2222, 2223, 2302, 2535, 2536, 2537, 2538, 2967, 3031, 3050, 3074,
    3130, 3283, 3306, 3389, 3456, 3544, 3702, 3724, 3784, 3785, 3868, 4070, 4333,
    4444, 4500, 4569, 4662, 4672, 4899, 5000, 5001, 5004, 5005, 5050, 5060, 5190,
    5351, 5353, 5355, 5500, 5632, 5678, 5683, 6112, 6129, 6257, 6346, 6347, 6500,
    6566, 6580, 6646, 6666, 6672, 6673, 6839, 6891, 6901, 6970, 7000, 7001, 7002,
    7003, 7004, 7005, 7006, 7007, 7008, 7009, 7010, 7212, 7500, 7777, 8000, 8001,
    8010, 8080, 8081, 8082, 8222, 8443, 8888, 9000, 9001, 9002, 9009, 9010, 9020,
    9090, 9100, 9200, 9418, 9800, 9876, 9898, 9987, 9999, 10000, 10001, 10002, 10008,
    10010, 10050, 10051, 10113, 10114, 10115, 10116, 10211, 10439, 10443, 11211,
    12000, 12010, 12012, 12203, 12345, 12975, 12998, 12999, 13000, 13001, 13075,
    13400, 13720, 13721, 13722, 13724, 13782, 13783, 13818, 14000, 14238, 14444,
    14567, 14900, 15000, 15002, 15003, 15567, 16384, 17011, 17012, 18136, 18186,
    18231, 19132, 19150, 19600, 20031, 20202, 21027, 22003, 22136, 23073, 23399,
    24465, 24554, 24800, 24842, 25000, 25003, 25005, 25007, 25010, 25565, 25700,
    25826, 26000, 26001, 26214, 27000, 27015, 27031, 27374, 27500, 27910, 27960,
    28000, 28785, 29152, 29900, 29920, 30000, 30120, 30303, 30777, 31337, 31416,
    31457, 31620, 32137, 32400, 32764, 33434, 33848, 34567, 35871, 37777, 40000,
    41121, 41794, 41795, 41796, 42508, 42510, 44176, 44334, 44818, 45000, 45824,
    47001, 47808, 48010, 49152, 50000, 50002, 50012, 50020, 51413, 51972, 52869,
    54045, 54321, 55003, 55056, 55400, 56738, 57772, 60000, 60020, 64738, 65000
]

RHOSTStemp = []
PORTStemp = []

RHOSTS = []
PORTS = []
TOP_PORTS = 0
SYN_SCAN = False
CONNECT_SCAN = False
UDP_SCAN = False
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

def ip(string):
    string = string.replace(",", "")
    RealIP = 0
    try:
        if(string.count(".") == 3):
            cond1 = int(string.split(".")[0]) <= 255
            cond2 = int(string.split(".")[1]) <= 255
            cond3 = int(string.split(".")[2]) <= 255
            cond4 = int(string.split(".")[3]) <= 255
            cond5 = int(string.split(".")[0]) >= 0
            cond6 = int(string.split(".")[1]) >= 0
            cond7 = int(string.split(".")[2]) >= 0
            cond8 = int(string.split(".")[3]) >= 0
            if(cond1 and cond2 and cond3 and cond4 and cond5 and cond6 and cond7 and cond8):
                RealIP = string
            else:
                raise ValueError
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{string}' is not a valid ip")
    return RealIP

def port(string):
    string = string.replace(",", "")
    RealPort = 0
    try:
        if(string.count("-") == 1):
            cond1 = int(string.split("-")[0]) <= 65535
            cond2 = int(string.split("-")[1]) <= 65535
            cond3 = int(string.split("-")[0]) >= 0
            cond4 = int(string.split("-")[1]) >= 0
            cond5 = int(string.split("-")[0]) < int(string.split("-")[1])
            if(cond1 and cond2 and cond3 and cond4 and cond5):
                RealPort = string
            else:
                raise ValueError
        elif(string.count("-") == 0):
            cond1 = int(string) <= 65535
            cond2 = int(string) >= 0
            if(cond1 and cond2):
                RealPort = string
            else:
                raise ValueError
        else:
            raise ValueError
    except ValueError:
        raise argparse.ArgumentTypeError(f"'{string}' is not a valid port")
    return RealPort

def start():
    parser = argparse.ArgumentParser(description="Options")
    parser.add_argument('-t', '--target', nargs='+', type=ip, required=True, help="Specify target (IP, IP range or subnet)")
    groupPorts = parser.add_mutually_exclusive_group(required=False)
    groupPorts.add_argument('-p', '--ports', nargs='+', type=port, required=False, action='store', help="Define ports to scan")
    groupPorts.add_argument('-n', '--top-ports', type=int, required=False, action='store', help="Scan top N common ports (max: 300)") #TODO: insert top common ports list
    groupScan = parser.add_mutually_exclusive_group(required=True)
    groupScan.add_argument('-S', '--syn', required=False, default=False, action='store_true', help="TCP SYN scan (stealth)")
    groupScan.add_argument('-T', '--connect', required=False, default=False, action='store_true', help="TCP Connect scan")
    groupScan.add_argument('-U', '--udp', required=False, default=False, action='store_true', help="UDP scan")
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
        global RHOSTStemp
        for i in range(len(args.target)):
            args.target[i] = args.target[i].replace(" ", "")
        RHOSTStemp = map(str, args.target)

    if(args.ports):
        global PORTStemp
        for i in range(len(args.ports)):
            args.ports[i] = args.ports[i].replace(" ", "")
        PORTStemp = map(str, args.ports)

    if(args.top_ports):
        global TOP_PORTS
        TOP_PORTS = args.top_ports

    if(args.syn):
        global SYN_SCAN
        SYN_SCAN = args.syn

    if(args.connect):
        global CONNECT_SCAN
        CONNECT_SCAN = args.connect

    if (args.udp):
        global UDP_SCAN
        UDP_SCAN = args.udp

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
    for host in RHOSTStemp:
        if (("-" in host) & (host.count("-") == 1)):

            RHOSTStemp.remove(host)

            parts = host.split("-")
            ip1 = parts[0].split(".")
            ip2 = parts[1].split(".")

            for i in [0, 1, 2, 3]:
                ip1[i] = int(ip1[i])
                ip2[i] = int(ip2[i])

            if(ip1[0] != ip2[0]):
                print("Error: first octet of the two IPs must be the same")
                return 1
            elif(ip1[3] == 0 or ip1[0] == 0 or ip1[3] == 255):
                print("Error: last or first octet of the first IP must not be 0 or 255")
                return 1
            else:
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

                if(ip1 in RHOSTS):
                    print("Error: IP already in list")
                    return 1
                else:
                    RHOSTS.append(str(ip1[0]) + "." + str(ip1[1]) + "." + str(ip1[2]) + "." + str(ip1[3]))
        else:
            if(host in RHOSTS):
                print("Error: IP " + host + " already in list")
                return 1
            else:
                RHOSTS.append(host)

    # Espansione dei range di porte in PORTS
    expanded_ports = []
    global PORTStemp
    for port in PORTStemp:
        port_str = str(port)
        if "-" in port_str:
            parts = port_str.split("-")
            start_port = int(parts[0])
            end_port = int(parts[1])
            for p in range(start_port, end_port + 1):
                expanded_ports.append(p)
        else:
            expanded_ports.append(int(port))

    for expanded_port in expanded_ports:
        if expanded_port not in PORTS:
            PORTS.append(expanded_port)



    for host in RHOSTS:
        print("Scanning host: " + host)

        if(SYN_SCAN == True):
            print("TCP SYN scan")
            SYN_SCAN_FUNCTION(host)

        elif(CONNECT_SCAN == True):
            print("TCP Connect scan")
            CONNECT_SCAN_FUNCTION(host)

        elif(UDP_SCAN == True):
            print("UDP scan")
            UDP_SCAN_FUNCTION(host)

def SYN_SCAN_FUNCTION(host):
    results = {}

    global PORTS
    if not PORTS and TOP_PORTS == 0:
        PORTS = list(range(1, 1000))
    if TOP_PORTS != 0:
        for i in range(0, TOP_PORTS):
            if(common_tcp_ports[i] not in PORTS):
                PORTS.append(common_tcp_ports[i])



    for port in PORTS:
        syn_packet = IP(dst=host) / TCP(sport=RandShort(), dport=port, flags="S")

        response = sr1(syn_packet, timeout=2, verbose=0)

        if(response is None):
            results[port] = "Filtered"
        elif(response.haslayer(TCP)):
            if(response.getlayer(TCP).flags == 0x12):
                send_rst = IP(dst=host) / TCP(sport=syn_packet[TCP].sport, dport=response.dport, flags="R")
                send(send_rst, count=1, verbose=0)
                results[port] = "Open"
            elif(response.getlayer(TCP).flags == 0x14):
                results[port] = "Closed"
        else:
                results[port] = "Filtered (ICMP Error)"

    for i in results:
        print(str(i) + " " + results[i])
    return results

def CONNECT_SCAN_FUNCTION(host):
    results = {}

    global PORTS
    if not PORTS and TOP_PORTS == 0:
        PORTS = list(range(1, 1000))
    if TOP_PORTS != 0:
        for i in range(0, TOP_PORTS):
            if (common_tcp_ports[i] not in PORTS):
                PORTS.append(common_tcp_ports[i])

    for port in PORTS:
        syn_packet = IP(dst=host) / TCP(sport=RandShort(), dport=port, flags="S")

        response = sr1(syn_packet, timeout=2, verbose=0)

        if (response is None):
            results[port] = "Filtered"
        elif (response.haslayer(TCP)):
            if (response.getlayer(TCP).flags == 0x12):
                send_ack = IP(dst=host) / TCP(sport=syn_packet[TCP].sport, dport=response.dport, flags="A")
                send(send_ack, count=1, verbose=0)
                send_rst = IP(dst=host) / TCP(sport=syn_packet[TCP].sport, dport=response.dport, flags="R")
                send(send_rst, count=1, verbose=0)
                results[port] = "Open"
            elif (response.getlayer(TCP).flags == 0x14):
                results[port] = "Closed"
        else:
            results[port] = "Filtered (ICMP Error)"

    for i in results:
        print(str(i) + " " + results[i])
    return results

def UDP_SCAN_FUNCTION(host):
    results = {}

    global PORTS
    if not PORTS and TOP_PORTS == 0:
        PORTS = list(range(1, 1000))
    if TOP_PORTS != 0:
        for i in range(0, TOP_PORTS):
            if (common_udp_ports[i] not in PORTS):
                PORTS.append(common_udp_ports[i])

    for port in PORTS:
        udp_packet = IP(dst=host) / UDP(dport=port)
        response = sr1(udp_packet, timeout=2, verbose=0)

        if (response is None):
            results[port] = "Open|Filtered"
        elif (response.haslayer(ICMP) and response[ICMP].type == 3 and response[ICMP].code in [1, 2, 3, 9, 10, 13]):
            results[port] = "Closed"
        else:
            results[port] = "Open"

    for i in results:
        print(str(i) + " " + results[i])

    return results


start()
scan()


