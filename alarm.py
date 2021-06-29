#!/usr/bin/python3

from scapy.all import *
import argparse
import base64

# global variables
counter = 0
usernameFTP = ""

def packetcallback(packet):
    global counter
    global usernameFTP
    try:
        if TCP in packet:
            # NULL scan
            if packet[TCP].flags == 0:
                counter += 1
                print("ALERT #%d: %s is detected from %s (%s)!" % (counter, "NULL scan", (packet[IP].src), "TCP"))
            # FIN scan
            if packet[TCP].flags == 'F':
                counter += 1
                print("ALERT #%d: %s is detected from %s (%s)!" % (counter, "FIN scan", (packet[IP].src), "TCP"))
            # Xmas scan
            if packet[TCP].flags == 'FPU':
                counter += 1
                print("ALERT #%d: %s is detected from %s (%s)!" % (counter, "Xmas scan", (packet[IP].src), "TCP"))
            # Nikto scan
            if packet[TCP].flags == 'PA':
                # ls(packet)
                if "Nikto" in packet.load.decode("ascii").strip():
                    counter += 1
                    print("ALERT #%d: %s is detected from %s (%s)!" % (counter, "Nikto scan", (packet[IP].src), "TCP"))
            # check for credentials
            # HTTP
            if packet[TCP].dport == 80:
                if "Authorization: Basic" in packet.load.decode("ascii"):
                    for line in packet.load.splitlines():
                        if "Authorization: Basic" in line.decode("ascii"):
                            creds = line.split()
                            credentials = base64.b64decode(creds[2]).decode("ascii")
                            username = credentials.split(':')[0]
                            password = credentials.split(':')[1]
                            counter += 1
                            print("ALERT #%d: Usernames and passwords sent in-the-clear (%s) (username:%s, password:%s)" % (
                                counter, "HTTP", username, password))
            # IMAP
            if packet[TCP].dport == 143:
                payload = packet[TCP].load.decode("ascii").strip()
                if "LOGIN" in payload:
                    for lines in payload.splitlines():
                        line = lines.split()
                        if "LOGIN" == line[1]:
                            counter += 1
                            username = line[2]
                            password = line[3]
                            print("ALERT #%d: Usernames and passwords sent in-the-clear (%s) (username:%s, password:%s)" % (
                            counter, "IMAP", username, password[1:-1]))
            # FTP
            if packet[TCP].dport == 21:
                payload = packet[TCP].load.decode("ascii").strip()
                if "USER" in payload:
                    for lines in payload.splitlines():
                        line = lines.split()
                        if "USER" == line[0]:
                            usernameFTP = line[1]
                if "PASS" in payload:
                    for lines in payload.splitlines():
                        line = lines.split()
                        if "PASS" == line[0]:
                            counter += 1
                            password = line[1]
                            print("ALERT #%d: Usernames and passwords sent in-the-clear (%s) (username:%s, password:%s)" % (
                                    counter, "FTP", usernameFTP, password))
            # RDP scan
            if packet[TCP].dport == 3389:
                counter += 1
                print("ALERT #%d: %s is detected from %s (%s)!" % (counter, "RDP scan", (packet[IP].src), "TCP"))
    except Exception as e:
        pass


parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()
if args.pcapfile:
    try:
        print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
        sniff(offline=args.pcapfile, prn=packetcallback)
    except:
        print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
    print("Sniffing on %(interface)s... " % {"interface" : args.interface})
    try:
        sniff(iface=args.interface, prn=packetcallback)
    except:
        print("Sorry, can\'t read network traffic. Are you root?")
