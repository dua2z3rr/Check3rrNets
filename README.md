# Check3rrNets: Port Scanner

**Languages:** Python  
**Framework/Tools:** Scapy, Argparse, Threading  
**License:** MIT  

## Features
1. TCP Scanning (SYN/Connect)
2. Service banner detection
3. Multithreading support
4. Customizable port filtering
5. Result export in JSON/CSV format

## Setup
```bash
git clone https://github.com/dua2z3rr/Check3rrNets.git
cd Check3rrNets
```

## Options

- **target**: list of IPs, ranges, or subnets to scan  
- **ports**: list of ports to scan  
- **top_ports**: number of common ports to scan  
- **syn**: enable SYN scan  
- **connect**: enable TCP connect scan  
- **banner**: enable banner grabbing  
- **threads**: number of parallel threads  
- **exclude_ports**: ports to exclude from scanning  
- **only_open**: show only open ports  
- **output**: results output file  
- **format**: output format (`json`/`csv`/`txt`)  
- **verbose**: detailed output  
- **debug**: debug mode  
- **time_between_packets**: time between packets  
- **packets_per_second**: packets per second limit


## Example Output
```plaintext
Port 80/tcp   OPEN   HTTP/1.1 404 Not Found
Port 22/tcp   OPEN   SSH-2.0-OpenSSH_8.4p1
Port 443/tcp  OPEN   HTTP/1.1 200 OK
```

## Ignored Files
The repository includes a preconfigured `.gitignore` for:
- Python compiled files (`*.pyc`)
- Virtual environments (`venv/`)
- Configuration files (`.env`)
- Log directories (`logs/`)

## License
Distributed under the MIT license. See the `LICENSE` file for details.
