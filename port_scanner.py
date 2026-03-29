"""
██████╗  ██████╗ ██████╗ ████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗
██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
██████╔╝██║   ██║██████╔╝   ██║       ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
██╔═══╝ ██║   ██║██╔══██╗   ██║       ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
██║     ╚██████╔╝██║  ██║   ██║       ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
                                                                    by Sabir Qadar
"""

import socket
import threading
import argparse
import sys
import time
from datetime import datetime
from queue import Queue
from concurrent.futures import ThreadPoolExecutor, as_completed

# ─── ANSI Color Codes ────────────────────────────────────────────────────────
class Color:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"
    BG_RED  = "\033[41m"
    BG_GREEN= "\033[42m"

# ─── Common Port Service Names ────────────────────────────────────────────────
COMMON_SERVICES = {
    20: "FTP-DATA",    21: "FTP",         22: "SSH",          23: "TELNET",
    25: "SMTP",        53: "DNS",          67: "DHCP",         68: "DHCP",
    69: "TFTP",        80: "HTTP",         110: "POP3",        119: "NNTP",
    123: "NTP",        135: "MSRPC",       137: "NETBIOS",     138: "NETBIOS",
    139: "NETBIOS",    143: "IMAP",        161: "SNMP",        162: "SNMP",
    179: "BGP",        194: "IRC",         389: "LDAP",        443: "HTTPS",
    445: "SMB",        465: "SMTPS",       514: "SYSLOG",      515: "LPD",
    587: "SMTP",       631: "IPP",         636: "LDAPS",       993: "IMAPS",
    995: "POP3S",      1080: "SOCKS",      1194: "OpenVPN",    1433: "MSSQL",
    1521: "Oracle",    1723: "PPTP",       2049: "NFS",        2181: "ZooKeeper",
    3000: "Node.js",   3306: "MySQL",      3389: "RDP",        4444: "Metasploit",
    5000: "Flask",     5432: "PostgreSQL", 5900: "VNC",        5984: "CouchDB",
    6379: "Redis",     6443: "Kubernetes", 7001: "WebLogic",   8000: "HTTP-Alt",
    8080: "HTTP-Proxy",8081: "HTTP-Alt",   8443: "HTTPS-Alt",  8888: "Jupyter",
    9000: "PHP-FPM",   9090: "Prometheus", 9200: "Elasticsearch",9300: "Elasticsearch",
    11211: "Memcached",27017: "MongoDB",   27018: "MongoDB",   50000: "SAP",
}

# ─── Banner Grab ─────────────────────────────────────────────────────────────
def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Attempt to grab a service banner from an open port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            try:
                # Send a generic probe for HTTP
                if port in (80, 8080, 8000, 8081, 8888, 8443, 443):
                    s.send(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
                else:
                    s.send(b"\r\n")
                banner = s.recv(1024).decode("utf-8", errors="ignore").strip()
                return banner[:80] if banner else ""
            except Exception:
                return ""
    except Exception:
        return ""

# ─── Port Scan Worker ─────────────────────────────────────────────────────────
def scan_port(ip: str, port: int, timeout: float, grab_banners: bool) -> dict | None:
    """Scan a single port and return result dict if open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                service = COMMON_SERVICES.get(port, "Unknown")
                try:
                    service = socket.getservbyport(port) if service == "Unknown" else service
                except Exception:
                    pass
                banner = ""
                if grab_banners:
                    banner = grab_banner(ip, port, timeout)
                return {"port": port, "service": service, "banner": banner}
    except Exception:
        pass
    return None

# ─── Progress Bar ─────────────────────────────────────────────────────────────
def render_progress(done: int, total: int, width: int = 40) -> str:
    pct = done / total if total else 0
    filled = int(width * pct)
    bar = "█" * filled + "░" * (width - filled)
    return f"[{Color.CYAN}{bar}{Color.RESET}] {Color.YELLOW}{pct*100:5.1f}%{Color.RESET} ({done}/{total})"

# ─── Print Header ─────────────────────────────────────────────────────────────
def print_header(target: str, ip: str, port_range: tuple, threads: int):
    print(f"\n{Color.CYAN}{'═'*65}{Color.RESET}")
    print(f"  {Color.BOLD}{Color.GREEN}▶ TARGET   {Color.RESET}{Color.WHITE}{target}{Color.RESET}  {Color.GRAY}({ip}){Color.RESET}")
    print(f"  {Color.BOLD}{Color.GREEN}▶ PORTS    {Color.RESET}{Color.WHITE}{port_range[0]} - {port_range[1]}{Color.RESET}  {Color.GRAY}({port_range[1]-port_range[0]+1:,} ports){Color.RESET}")
    print(f"  {Color.BOLD}{Color.GREEN}▶ THREADS  {Color.RESET}{Color.WHITE}{threads}{Color.RESET}")
    print(f"  {Color.BOLD}{Color.GREEN}▶ STARTED  {Color.RESET}{Color.WHITE}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Color.RESET}")
    print(f"{Color.CYAN}{'═'*65}{Color.RESET}\n")

# ─── Print Results Table ──────────────────────────────────────────────────────
def print_results(open_ports: list[dict], elapsed: float):
    print(f"\n{Color.CYAN}{'═'*65}{Color.RESET}")
    print(f"  {Color.BOLD}{Color.GREEN}OPEN PORTS  {Color.RESET}— {Color.YELLOW}{len(open_ports)} found{Color.RESET}")
    print(f"{Color.CYAN}{'─'*65}{Color.RESET}")

    if not open_ports:
        print(f"  {Color.GRAY}No open ports found.{Color.RESET}")
    else:
        print(f"  {Color.BOLD}{Color.CYAN}{'PORT':<8}{'SERVICE':<16}{'BANNER/INFO'}{Color.RESET}")
        print(f"  {Color.GRAY}{'─'*8}{'─'*16}{'─'*35}{Color.RESET}")
        for entry in sorted(open_ports, key=lambda x: x["port"]):
            port_str = f"{Color.GREEN}{entry['port']}/tcp{Color.RESET}"
            svc_str  = f"{Color.YELLOW}{entry['service']:<16}{Color.RESET}"
            banner   = entry.get("banner", "")
            banner_str = f"{Color.GRAY}{banner[:35]}{Color.RESET}" if banner else ""
            print(f"  {port_str:<20}{svc_str}{banner_str}")

    print(f"{Color.CYAN}{'─'*65}{Color.RESET}")
    print(f"  {Color.BOLD}Scan completed in {Color.MAGENTA}{elapsed:.2f}s{Color.RESET}")
    print(f"{Color.CYAN}{'═'*65}{Color.RESET}\n")

# ─── Main Scanner ─────────────────────────────────────────────────────────────
def run_scan(target: str, start_port: int, end_port: int,
             threads: int, timeout: float, grab_banners: bool, verbose: bool):
    # Resolve hostname
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"\n{Color.RED}[ERROR] Cannot resolve host: {target}{Color.RESET}\n")
        sys.exit(1)

    ports = list(range(start_port, end_port + 1))
    total = len(ports)
    open_ports = []
    done = 0
    lock = threading.Lock()
    start_time = time.time()

    print_header(target, ip, (start_port, end_port), threads)
    print(f"  {Color.BOLD}Scanning...{Color.RESET}\n")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, ip, p, timeout, grab_banners): p for p in ports}
        for future in as_completed(futures):
            with lock:
                done += 1
                result = future.result()
                if result:
                    open_ports.append(result)
                    if verbose:
                        svc = result["service"]
                        print(f"\r  {Color.GREEN}[OPEN]{Color.RESET} {Color.WHITE}{result['port']}/tcp{Color.RESET}  {Color.YELLOW}{svc}{Color.RESET}          ")

                # Refresh progress bar
                bar = render_progress(done, total)
                print(f"\r  {bar}", end="", flush=True)

    elapsed = time.time() - start_time
    print()  # newline after progress
    print_results(open_ports, elapsed)
    return open_ports

# ─── CLI Entry Point ──────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="⚡ Fast Python Port Scanner",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="""
Examples:
  python port_scanner.py scanme.nmap.org
  python port_scanner.py 192.168.1.1 -p 1-1024
  python port_scanner.py example.com -p 80,443,8080
  python port_scanner.py 10.0.0.1 -p 1-65535 -t 500 --timeout 0.5
  python port_scanner.py 192.168.1.1 -p 1-1000 -b -v
        """
    )
    parser.add_argument("target", nargs="?", default="scanme.nmap.org",
                        help="Target IP address or hostname (default: scanme.nmap.org)")
    parser.add_argument("-p", "--ports", default="1-1024",
                        help="Port range or list: '1-1024' or '22,80,443' (default: 1-1024)")
    parser.add_argument("-t", "--threads", type=int, default=200,
                        help="Number of concurrent threads (default: 200)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="Socket timeout in seconds (default: 1.0)")
    parser.add_argument("-b", "--banners", action="store_true",
                        help="Attempt to grab service banners")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Print open ports as they are discovered")

    args = parser.parse_args()

    # Parse port specification
    if "," in args.ports:
        ports_list = [int(p.strip()) for p in args.ports.split(",")]
        start_port, end_port = min(ports_list), max(ports_list)
        # Override to use exact list — simple approach: set range to cover list
    elif "-" in args.ports:
        parts = args.ports.split("-")
        start_port, end_port = int(parts[0]), int(parts[1])
    else:
        start_port = end_port = int(args.ports)

    # Validate
    if not (1 <= start_port <= 65535) or not (1 <= end_port <= 65535):
        print(f"{Color.RED}[ERROR] Ports must be between 1 and 65535.{Color.RESET}")
        sys.exit(1)
    if start_port > end_port:
        print(f"{Color.RED}[ERROR] Start port must be <= end port.{Color.RESET}")
        sys.exit(1)

    # Print ASCII banner
    print(f"{Color.CYAN}{Color.BOLD}")
    print("  ██████╗  ██████╗ ██████╗ ████████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗")
    print("  ██╔══██╗██╔═══██╗██╔══██╗╚══██╔══╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║")
    print("  ██████╔╝██║   ██║██████╔╝   ██║       ███████╗██║     ███████║██╔██╗ ██║")
    print("  ██╔═══╝ ██║   ██║██╔══██╗   ██║       ╚════██║██║     ██╔══██║██║╚██╗██║")
    print("  ██║     ╚██████╔╝██║  ██║   ██║       ███████║╚██████╗██║  ██║██║ ╚████║")
    print("  ╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝       ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝")
    print(f"{Color.RESET}{Color.GRAY}                                  Python Port Scanner {Color.RESET}")

    run_scan(
        target=args.target,
        start_port=start_port,
        end_port=end_port,
        threads=args.threads,
        timeout=args.timeout,
        grab_banners=args.banners,
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()