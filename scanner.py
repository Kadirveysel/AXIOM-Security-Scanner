import socket
import threading
from queue import Queue
from datetime import datetime
import sys
import time
import os

# AXIOM SECURITY SCANNER v1.1
# Author: Plansmight (Kadir Veysel Sayar)
# Description: Mathematical Precision Security Scanner with Enhanced UI.

# --- RENK KODLARI (ANSI) ---
os.system('color') 

class Colors:
    GREEN = '\033[92m'
    GREY = '\033[90m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    RED = '\033[91m'
    CYAN = '\033[96m'
    YELLOW = '\033[93m'
    MAGENTA = '\033[95m'
    BLUE = '\033[94m'

# --- CONFIGURATION & BANNER ---
def print_banner():
    banner = f"""{Colors.CYAN}
     █████╗ ██╗  ██╗██╗ ██████╗ ███╗   ███╗
    ██╔══██╗╚██╗██╔╝██║██╔═══██╗████╗ ████║
    ███████║ ╚███╔╝ ██║██║   ██║██╔████╔██║
    ██╔══██║ ██╔██╗ ██║██║   ██║██║╚██╔╝██║
    ██║  ██║██╔╝ ██╗██║╚██████╔╝██║ ╚═╝ ██║
    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝ ╚═════╝ ╚═╝     ╚═╝ v1.0
    {Colors.RESET}{Colors.GREY}Mathematical Precision Security Scanner{Colors.RESET}
    {Colors.GREY}Authored by: Plansmight{Colors.RESET}
    """
    print(banner)

print_banner()

# --- GELISTIRILMIS GIRIS EKRANI (INPUT UI) ---
try:
    # Kali Linux Tarzi Giris Ekrani
    print(f"{Colors.CYAN}┌──( {Colors.BOLD}SET TARGET{Colors.RESET}{Colors.CYAN} )─[ {Colors.GREY}Press Enter for 'scanme.nmap.org'{Colors.RESET}{Colors.CYAN} ]")
    user_input = input(f"└─► {Colors.RESET}")
except KeyboardInterrupt:
    sys.exit()

if len(user_input) == 0:
    TARGET = "scanme.nmap.org"
    # Varsayilan secildigini belirtmek icin
    print(f"{Colors.YELLOW}    └──> Default target selected.{Colors.RESET}")
else:
    TARGET = user_input

# Hedefin IP'sini coz ve onayla
try:
    target_ip = socket.gethostbyname(TARGET)
    print(f"{Colors.GREEN}    └──> Target Locked: {Colors.BOLD}{TARGET}{Colors.RESET} ({target_ip})")
except socket.gaierror:
    print(f"\n{Colors.RED}[!] Error: Hostname could not be resolved.{Colors.RESET}")
    sys.exit()

# --- TARAMA AYARLARI ---
PORT_RANGE = 1000  
THREAD_COUNT = 100 
# -----------------------

print_lock = threading.Lock()
q = Queue()
scanned_count = 0 
open_ports = 0 
is_scanning = True
start_time = datetime.now()

def get_banner(s):
    try:
        return s.recv(1024).decode().strip()
    except:
        return "Unknown Service"

def ui_monitor():
    global scanned_count
    bar_length = 30
    
    while is_scanning:
        with print_lock:
            percent = (scanned_count / PORT_RANGE) * 100
            if percent > 100: percent = 100
            
            filled_length = int(bar_length * scanned_count // PORT_RANGE)
            bar = (Colors.CYAN + '█' * filled_length + 
                   Colors.GREY + '-' * (bar_length - filled_length) + 
                   Colors.RESET)
            
            sys.stdout.write(f"\r{Colors.YELLOW}[*] Calculating:{Colors.RESET} |{bar}| {scanned_count}/{PORT_RANGE} ({percent:.0f}%)")
            sys.stdout.flush()
        
        if scanned_count >= PORT_RANGE:
            break
        time.sleep(0.1)

def port_scan(port):
    global scanned_count, open_ports
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5) 
        result = s.connect_ex((TARGET, port))
        
        if result == 0:
            try:
                banner = get_banner(s)
            except:
                banner = "N/A"
            
            with print_lock:
                open_ports += 1
                sys.stdout.write(f"\r" + " "*80 + "\r") 
                print(f"{Colors.GREEN} [+] {str(port):<8} | {Colors.BOLD}OPEN{Colors.RESET}{Colors.GREEN} | {banner}{Colors.RESET}")
        
        s.close()
    except:
        pass
    finally:
        scanned_count += 1

def threader():
    while True:
        worker = q.get()
        port_scan(worker)
        q.task_done()

# --- ANA PROGRAM ---
if __name__ == "__main__":
    
    # Baslangic cizgisi
    print(f"\n{Colors.GREY}Computation Started: {start_time.strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}")
    print("-" * 65)
    print(f"{Colors.BOLD} PORT     | STATUS | SERVICE BANNER{Colors.RESET}")
    print("-" * 65)

    for x in range(THREAD_COUNT):
        t = threading.Thread(target=threader)
        t.daemon = True
        t.start()

    monitor_thread = threading.Thread(target=ui_monitor)
    monitor_thread.daemon = True
    monitor_thread.start()

    for worker in range(1, PORT_RANGE + 1):
        q.put(worker)

    try:
        q.join()
        is_scanning = False 
        monitor_thread.join() 
    except KeyboardInterrupt:
        is_scanning = False
        print(f"\n\n{Colors.RED}[!] Process Interrupted.{Colors.RESET}")
        sys.exit()

    # --- OZET RAPORU ---
    end_time = datetime.now()
    duration = end_time - start_time
    
    sys.stdout.write(f"\r" + " "*80 + "\r")
    print("-" * 65)
    print(f"{Colors.CYAN}AXIOM ANALYSIS COMPLETE{Colors.RESET}")
    print(f"Total Open Ports : {Colors.GREEN}{open_ports}{Colors.RESET}")
    print(f"Time Elapsed     : {duration}")
    print("-" * 65 + "\n")