#!/bin/python3

# Project: PyPortScanner
# Description: Scan ports on local network systems
# Author: Jared Gibson
# Gitlab: https://github.com/guiterguy219/pyportscan

import argparse
import ipaddress
import sys
import datetime as dt
import webbrowser
from scapy.all import sr1, IP, TCP, Ether, ARP, srp

# Get CLI arguments
parser = argparse.ArgumentParser(description="Scan ports on local network systems")
parser.add_argument(
    "ip_range",
    nargs=1,
    help="Path to file, IP address range, or single IP address",
)
parser.add_argument(
    "-p",
    "--port",
    nargs=1,
    type=str,
    help="Single port (ie 80) or port range (ie 1-80)",
)
parser.add_argument(
    "--html",
    action="store_true",
    help="Render output as HTML"
)

args = parser.parse_args()

ip_addresses = []

# Allow for file w/ IP addresses, IP address range, or single IP address
try:
    with open(args.ip_range[0], "r") as f:
        for line in f:
            ip_addresses.append(ipaddress.ip_address(line.strip()))
except FileNotFoundError:
    if "/" in args.ip_range[0]:
        ip_addresses = [ip for ip in ipaddress.ip_network(args.ip_range[0])]
    else:
        ip_addresses = [ipaddress.ip_address(args.ip_range[0])]

# Allow for single or multiple ports
if args.port:
    dest_port_start = int(args.port[0].split("-")[0])
    dest_port_end = int(args.port[0].split("-")[-1])
else:
    dest_port_start = 1
    dest_port_end = 1024

ips_found = []

for idx, ip in enumerate(ip_addresses):
    print(f"\r\033[96mScanning host: {ip.exploded}\033[00m", end="")
    # Check to see if host is available using ARP
    try:
        ans, unans = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip.exploded),
            timeout=1,
            verbose=0,
        )
    except KeyboardInterrupt:
        sys.exit()
    if ans.res:
        print("\n\033[92mFOUND!\033[00m")
        # Check each port using TCP, looking for syn/ack flags in response
        ports_open = []
        for port in range(dest_port_start, dest_port_end + 1):
            spacer = " " * (len(str(dest_port_end)) - len(str(port)))
            print(
                f"\r...port {spacer}{port}: scanning",
                end="\r",
            )
            try:
                packet = sr1(
                    IP(dst=ip.exploded) / TCP(dport=(port), flags="S"),
                    timeout=0.5,
                    verbose=0,
                )
            except KeyboardInterrupt:
                print()
                sys.exit()
            if packet is not None:
                if packet.haslayer(TCP):
                    if packet[TCP].flags == "SA":
                        print(
                            f"\r...port {spacer}\033[93m{port}\033[00m: \033[92mopen                \033[00m"
                        )
                        ports_open.append(port)
        ips_found.append({'ip': ip.exploded, 'ports': ports_open})
        print("----------------------------------------------------------")

# Generate HTML page if requested by user
if args.html:
    filepath = f'/tmp/pyPortScan_output_{dt.datetime.now().strftime("%m-%d-%Y_%H-%M-%S")}'
    with open(filepath, 'w') as f:
        f.write('<html>')
        f.write('<head>')
        f.write('</head>')
        f.write('<body>')
        f.write('<h1>Scan Results!</h1>')
        f.write(f'<h2>{dt.datetime.now().strftime("%c")}</h2>')
        f.write('<br/>')
        f.write('<h2>Available hosts:</h2>')
        f.write(f'<p>Scanned <strong>{len(ips_found)}</strong> available hosts of <strong>{len(ip_addresses)}</strong> total</p>')
        f.write(f'<p>Scanned ports: {args.port}</p>')
        for host in ips_found:
            f.write(f'<h3>Host: {host["ip"]}</h3>')
            if host['ports']:
                f.write('<ul>')
                for port in host['ports']:
                    f.write(f'<li>Port {port}: <strong>open</strong></li>')
                f.write('</ul>')
            else:
                f.write('<p>No ports found open</p>')
            f.write('<br/>')
        f.write('</body>')
        f.write('</html>')
    # Attempt to open or print filepath
    print('Opening browser...')
    webbrowser.open(f'file://{filepath}')
    print(f'...if browser doesn\'t open, paste this in browser: file://{filepath}')

