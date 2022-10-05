import socket,sys
import time,queue
import threading
import requests

from colorama import init,Fore
init()

r = Fore.RED
g = Fore.GREEN
y = Fore.YELLOW
b = Fore.BLUE
reset = Fore.RESET

usage="python3 sscan3r.py TARGET START_PORT END_PORT THREAD"

print(f"{r}                          _____       {reset}")
print(f"{r}  ___ ___  ___ __ _ _ __ |___ / _ __  {reset}")
print(f"{r} / __/ __|/ __/ _` | '_ \  |_ \| '__| {reset}")
print(f"{r} \__ \__ \ (_| (_| | | | |___) | |    {reset}")
print(f"{r} |___/___/\___\__,_|_| |_|____/|_|    {reset}")
print(f"{y} \t https://github.com/REDSXGHT \n {reset}")


target = sys.argv[1]
stp = int(sys.argv[2])
edp = int(sys.argv[3])
thread_no=int(sys.argv[4])
try:
    target = socket.gethostbyname(target)
except:
    print("[-]Host resolution failed.")
    exit()

print("[+]Scanning Target: {}".format(target))



if not target or not str(stp) or not edp or not thread_no:
    print(usage)
    exit()

def get_banner(port,s):
    if(port == 80):
        response = requests.get("http://"+target)
        return response.headers['Server']

    try:
        return s.recv(1024).decode()
    except:
        return 'Not Found'

res = ''

def scan_port(t_no):
    global res
    while not q.empty():
        port = q.get()
        print("Scanning Ports {}..".format(port),end='\r')
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            conn = s.connect_ex((target, port))
            if not conn:
                banner = get_banner(port,s)
                banner = ''.join(banner.splitlines())
                res += f"\t|{port}\t|OPEN\t|{banner}\n"

            s.close()

        except:
            pass

        q.task_done()

q = queue.Queue()

start_time=time.time()

for j in range(stp,edp+1):
    q.put(j)

for i in range(thread_no):
    t = threading.Thread(target=scan_port,args=(i,))
    t.start()

q.join()

end_time = time.time()
print(f"{b}\n[+]RESULTS:\n\t|PORT\t|STATE\t|SERVICE{reset}")
print(res)
print("[+]Time taken: {}".format(end_time-start_time))

with open("logfile.txt",'w') as file:
    file.write(f"[+]Port Scan result for {target} ...\n")
    file.write("\t|PORT\t|STATE\t|SERVICE\n")
    file.write(res)

print("[+]Written to file logfile.txt")
