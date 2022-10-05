from scapy.all import *
from scapy.layers.inet import IP
import argparse
from scapy.layers.http import HTTPRequest , TCP
from colorama import init,Fore

init()

r = Fore.RED
g = Fore.GREEN
y = Fore.YELLOW
b = Fore.BLUE
rt = Fore.RESET

argparse = argparse.ArgumentParser(description='Simple Packet Sniffer tool in Python',usage="sudo python3 Sniff33r.py [-d/-s/-p] PORT | tee OUTPUT.TXT")
argparse.add_argument("-d","--destination",help="destination port")
argparse.add_argument("-s","--source",help="Source port")
argparse.add_argument("-p","--port",help="either in source or destination port")

args = argparse.parse_args()
dest = args.destination
sou = args.source
po = args.port

flt=''

print(f"\n \n"+f"{r}    ______        _  ____ ____ _____ _____      \n   / ____/____   (_)/ __// __/|__  /|__  / _____\n  /___ \ / __ \ / // /_ / /_   /_ <  /_ < / ___/\n ____/ // / / // // __// __/ ___/ /___/ // /    \n/_____//_/ /_//_//_/  /_/   /____//____//_/   {rt}"+f"{y} \n \n \t \t https://github.com/REDSXGHT \n \n {rt}")

out_write=''
def sniff_packets(iface):
    global flt

    if dest is not None:
        flt = f"dst port {dest}"
    elif sou is not None:
        flt = f"src port {sou}"
    elif po is not None:
        flt = f"port {po}"

    if iface:
        sniff(filter = flt ,prn=process_packets, iface=iface,store=False)
    else:
        sniff(prn=process_packets, store=False)

def process_packets(packet):

    if packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport

        print(f'{b}[+]{src_ip} is using port {src_port} to connect to {dst_ip} at port {dst_port}{rt}')

    if packet.haslayer(HTTPRequest):
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        method = packet[HTTPRequest].Method.decode()

        print(f'{g}[+]{src_ip} is making a HTTP Request to url :{url} with method : {method}{rt}')
        print(f'[+]HTTP DATA:')
        print(f'{y}{packet[HTTPRequest].show()}{rt}')

        try:
            if packet.haslayer(Raw):
                print(f'{r}[+]Useful info : {packet.getlayer(Raw).load.decode()}{rt}')
        except:
            pass

sniff_packets('eth0')




