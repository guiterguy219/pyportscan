# PyPortScan
This is a simple Python tool for scanning multiple ports on multiple machines, or just scanning a single port on a single machine!
## Dependencies
- Python3
- Scapy basic
## Usage
__Note__: *All commands must be run with __superuser__ privileges*.
```
usage: pyportscan [-h] [-p PORT] [--html] ip_range

Scan ports on local network systems

positional arguments:
  ip_range              Path to file, IP address range, or single IP address

optional arguments:
  -h, --help            show this help message and exit
  -p PORT, --port PORT  Single port (ie 80) or port range (ie 1-80)
  --html                Render output as HTML
```
Run with command:
```
python -m pyportscan [IP_RANGE] [OPTIONS]
```
### Required Arguments
- __ip_range__: Path to text file with one IP address per line, an IP range in this format (0.0.0.0/0), or a single IP address
### Optional Arguments
- __port__: Single port or range of ports seperated by a dash (i.e. 22-193). Defaults to `1-1024`.
- __html__: Renders output as HTML. Can be viewed in browser and saved or printed.