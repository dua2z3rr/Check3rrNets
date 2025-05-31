help_message = """-t: Specify target (IP, IP range or subnet)
-p: Define ports to scan (single, range or list)
help_message = """-t: Specify target (IP, IP range or subnet) (default: loopback)
-p: Define ports to scan (single, range or list) (default: all)
-n: Scan top N common ports (default: 100)
-S: TCP SYN scan (stealth)
-T: TCP Connect scan
-b: Activate service banner grabbing
-j: Number of parallel threads (default: 50)
-w: Connection timeout (default: 3 seconds)
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

RHOSTS = ["127.0.0.1"]
TIMEOUT = 3
FULLSCAN = True
PORTS = []

def start():
    input_str = input("insert options for scan (-h for help):")
    options = [opt for opt in input_str.split("-") if opt.strip() != ""]
    print(options)
    return options

def optionsEvaluation(options):
    for option in options:
        optionArray = option.split(" ")
        match optionArray[0]:
            case "h":
                print(help_message)
                return 0;
            case "t":
                for ip in optionArray[1:]:
                    RHOSTS.append(ip)
            case "p":
                FULLSCAN = False
                for port in optionArray[1:]:
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
    socket.setdefaulttimeout(TIMEOUT)
    s = socket.socket()
    i = 0

    for RHOST in RHOSTS:
        print("-------------------- connecting to %s --------------------" % RHOST)

        if(FULLSCAN):
            for i in range(1, 65566):
                if(i == 1):
                    print("-------------------- WELL-KNOWN PORTS --------------------")
                elif(i == 1024):
                    print("-------------------- REGISTERED PORTS --------------------")
                elif(i == 49152):
                    print("-------------------- DYNAMIC PORTS --------------------")
                try:
                    s.connect((RHOST, int(i)))
                    x = s.recv(1024)
                    print(x)
                    abe = x[24:29]
                    print(abe)
                finally:
                    s.close()
        else:
            for i in PORTS:
                if(i == 1024):
                    print("-------------------- REGISTERED PORTS --------------------")
                elif(i == 49152):
                    print("-------------------- DYNAMIC PORTS --------------------")


optionsEvaluation(start())
scan()

