help_message = """-t: Specify target (IP, IP range or subnet)
-p: Define ports to scan (single, range or list)
-n: Scan top N common ports (default: 100)
-S: TCP SYN scan (stealth)
-T: TCP Connect scan
-b: Activate service banner grabbing
-j: Number of parallel threads (default: 50)
-w: Connection timeout (seconds)
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
        return None
    return None

optionsEvaluation(start())


