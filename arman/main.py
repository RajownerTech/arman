#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import socket
import threading
import requests
import urllib3
import asyncio
import ipaddress
import signal
import ssl
import re
from queue import Queue
from datetime import datetime, timezone

from rich.console import Console
from rich.progress import Progress, BarColumn, TimeRemainingColumn, TextColumn, MofNCompleteColumn
from rich.panel import Panel
from rich.prompt import IntPrompt
from rich.table import Table

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()
shutdown = False

# ================= SIGNAL =================
def handle_exit(sig, frame):
    global shutdown
    shutdown = True
    console.print("\n[red]🛑 Stopping scan...[/red]")

signal.signal(signal.SIGINT, handle_exit)

# ================= UI =================
def clear():
    os.system("cls" if os.name == "nt" else "clear")

def banner():
    console.print("""
[bold red]
 █████╗ ██████╗ ███╗   ███╗ █████╗ ███╗   ██╗
██╔══██╗██╔══██╗████╗ ████║██╔══██╗████╗  ██║
███████║██████╔╝██╔████╔██║███████║██╔██╗ ██║
██╔══██║██╔══██╗██║╚██╔╝██║██╔══██║██║╚██╗██║
██║  ██║██║  ██║██║ ╚═╝ ██║██║  ██║██║ ╚████║
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝
[/bold red]
""")

def main_menu():
    console.print(Panel.fit(
        "⚡ ARMAN Multi-Scanner\n[dim]Option 1: Domain Scanner | Option 2: Advanced TCP/HTTP Scanner | Option 3: Extract Domains by Word | Option 4: Clean & Filter Domains[/dim]",
        style="bold red",
        title="v3.0"
    ))
    
    console.print("\n[bold cyan]╔════════════════════════════════╗[/bold cyan]")
    console.print("[bold cyan]║        SELECT OPTION           ║[/bold cyan]")
    console.print("[bold cyan]╠════════════════════════════════╣[/bold cyan]")
    console.print("[bold cyan]║  [1] Domain File Scanner       ║[/bold cyan]")
    console.print("[bold cyan]║  [2] Advanced TCP/HTTP Scanner ║[/bold cyan]")
    console.print("[bold cyan]║  [3] Extract Domains by Word   ║[/bold cyan]")
    console.print("[bold cyan]║  [4] Clean & Filter Domains    ║[/bold cyan]")
    console.print("[bold cyan]║  [5] Exit                      ║[/bold cyan]")
    console.print("[bold cyan]╚════════════════════════════════╝[/bold cyan]")
    return console.input("[bold yellow]➤ Choose option: [/bold yellow]").strip()

# ================= TOOL 1: DOMAIN SCANNER =================
class DomainScanner:
    def __init__(self):
        self.THREADS = 150
        self.TIMEOUT = 2
        self.CHUNK_SIZE = 500
        self.q = Queue()
        self.lock = threading.Lock()
        self.blocked_ips = set()

    def block_ip(self, ip):
        """Add IP to blocklist"""
        self.blocked_ips.add(ip)

    def resolve_ip(self, host):
        try:
            return socket.gethostbyname(host)
        except:
            return "-"

    def scan(self, host, ports, outfile):
        ip = self.resolve_ip(host)
        
        # Skip if IP is blocked
        if ip in self.blocked_ips:
            return

        for port in ports:
            if port == 443:
                url = f"https://{host}"
            else:
                url = f"http://{host}:{port}"

            try:
                r = requests.get(
                    url,
                    timeout=self.TIMEOUT,
                    verify=False,
                    allow_redirects=False,
                    headers={"User-Agent": "Mozilla/5.0"}
                )

                if r.status_code == 302:
                    return

                server = r.headers.get("Server", "Unknown")
                result = f"{r.status_code} | {ip} | {server} | {host}:{port}"

                with self.lock:
                    console.print(
                        f"[green]{r.status_code:<5}[/green] │ "
                        f"[cyan]{ip:<15}[/cyan] │ "
                        f"[magenta]{server:<22}[/magenta] │ "
                        f"[yellow]{host}:{port}[/yellow]"
                    )
                    outfile.write(result + "\n")
                    outfile.flush()
            except:
                pass

    def worker(self, ports, outfile, progress, task):
        while True:
            host = self.q.get()
            if host is None:
                break
            self.scan(host, ports, outfile)
            progress.update(task, advance=1)
            self.q.task_done()

    def run(self):
        clear()
        console.print(Panel.fit("[bold green]DOMAIN FILE SCANNER[/bold green]", style="bold green"))
        
        domain_file = input("\n[?] Domain file: ").strip()

        if not os.path.isfile(domain_file):
            console.print("[red]✗ File not found![/red]")
            input("\n[?] Press Enter to continue...")
            return

        ports_input = input("[?] Ports (default 443): ").strip()

        if ports_input == "":
            ports = [443]
        else:
            ports = [int(x) for x in ports_input.split(",")]

        resume_line = input("[?] Resume from line (0=start): ").strip()

        try:
            resume_line = int(resume_line)
        except:
            resume_line = 0

        # Ask for IPs to block
        block_ips_input = input("[?] IPs to block (comma separated, e.g., 141.193.213.20,141.193.213.21): ").strip()
        
        output_file = "results.txt"
        domains = []

        with open(domain_file) as f:
            for line in f:
                d = line.strip()
                if d:
                    domains.append(d)

        total_domains = len(domains)

        if resume_line > total_domains:
            console.print("[red]✗ Resume line exceeds file length![/red]")
            input("\n[?] Press Enter to continue...")
            return

        domains = domains[resume_line:]
        total = len(domains)

        # Add blocked IPs
        if block_ips_input:
            for ip in block_ips_input.split(","):
                ip = ip.strip()
                if ip:
                    self.block_ip(ip)
            console.print(f"[yellow]⚠ Blocked {len(self.blocked_ips)} IP(s)[/yellow]")

        console.print("\n[bold]Code │ IP │ Server │ Host[/bold]\n")

        with open(output_file, "a") as outfile:
            with Progress(
                TextColumn("[bold cyan]SCANNING"),
                BarColumn(),
                MofNCompleteColumn(),
                TimeRemainingColumn(),
                console=console
            ) as progress:
                task = progress.add_task("scan", total=total)
                threads = []

                for _ in range(self.THREADS):
                    t = threading.Thread(
                        target=self.worker,
                        args=(ports, outfile, progress, task),
                        daemon=True
                    )
                    t.start()
                    threads.append(t)

                for i in range(0, total, self.CHUNK_SIZE):
                    chunk = domains[i:i + self.CHUNK_SIZE]
                    for domain in chunk:
                        self.q.put(domain)

                self.q.join()

                for _ in range(self.THREADS):
                    self.q.put(None)

                for t in threads:
                    t.join()

        console.print(f"\n[green]✓ Results saved to {output_file}[/green]")
        input("\n[?] Press Enter to return to menu...")

# ================= TOOL 2: ADVANCED TCP/HTTP SCANNER =================
class AdvancedScanner:
    def __init__(self):
        self.output = "result.txt"

    def get_config(self):
        ports_str = console.input("[bold cyan]Ports (default 80,443) > [/bold cyan]").strip()
        try:
            ports = [int(x.strip()) for x in ports_str.split(",") if x.strip()]
            if not ports:
                ports = [80, 443]
        except:
            ports = [80, 443]

        threads = IntPrompt.ask("TCP Threads", default=500)
        timeout = IntPrompt.ask("TCP Timeout", default=2)

        return ports, threads, timeout

    async def run_async(self):
        clear()
        banner()
        console.print(Panel.fit(
            "⚡ ARMAN Advanced Scanner\n[dim]TCP + HTTP/HTTPS HEAD + Fingerprint[/dim]",
            style="bold red",
            title="v3.3"
        ))
        
        console.print("\n[1] CIDR Scan")
        console.print("[2] IP File")
        console.print("[3] Back to Menu")
        choice = console.input("[bold cyan]Select > [/bold cyan]").strip()

        if choice == "3":
            return

        ports, threads, timeout = self.get_config()
        scanner = AdvancedScannerCore(ports, threads, timeout)

        progress = Progress(
            TextColumn("{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TimeRemainingColumn(),
            console=console,
        )

        if choice == "1":
            while True:
                cidr = console.input("[bold cyan]CIDR > [/bold cyan]").strip()
                try:
                    net = ipaddress.ip_network(cidr, strict=False)
                    break
                except:
                    console.print("[red]Invalid CIDR[/red]")

            async def run():
                task_id = progress.add_task(
                    f"[cyan]{cidr} ({net.num_addresses:,} IPs)",
                    total=net.num_addresses
                )

                batch = []
                for ip in net:
                    if shutdown:
                        break

                    batch.append(str(ip))

                    if len(batch) >= 5000:
                        await asyncio.gather(*[
                            scanner.scan_ip(i, progress, task_id) for i in batch
                        ])
                        batch.clear()

                if batch:
                    await asyncio.gather(*[
                        scanner.scan_ip(i, progress, task_id) for i in batch
                    ])

            with progress:
                await run()

        elif choice == "2":
            file = console.input("[bold cyan]File > [/bold cyan]").strip()

            with progress:
                await scanner.scan_file(file, progress)

        table = Table(title="Summary")
        table.add_row("Found", str(scanner.found))
        table.add_row("Output", scanner.output)
        console.print(table)
        
        input("\n[?] Press Enter to return to menu...")

class AdvancedScannerCore:
    def __init__(self, ports, threads, timeout):
        self.ports = ports
        self.timeout = timeout
        self.sem = asyncio.Semaphore(threads)
        self.http_sem = asyncio.Semaphore(100)
        self.output = "result.txt"
        self.seen = set()
        self.found = 0
        open(self.output, "w").close()

    async def tcp_check(self, ip, port):
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False

    async def http_head(self, ip, port):
        async with self.http_sem:
            try:
                ssl_ctx = None
                if port == 443:
                    ssl_ctx = ssl.create_default_context()
                    ssl_ctx.check_hostname = False
                    ssl_ctx.verify_mode = ssl.CERT_NONE

                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port, ssl=ssl_ctx),
                    timeout=3
                )

                req = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"
                writer.write(req.encode())
                await writer.drain()

                data = await asyncio.wait_for(reader.read(2048), timeout=3)
                text = data.decode(errors="ignore")

                lines = text.splitlines()
                code = None
                location = ""

                if lines and "HTTP" in lines[0]:
                    parts = lines[0].split()
                    if len(parts) > 1 and parts[1].isdigit():
                        code = parts[1]

                server = "Unknown"

                for line in lines:
                    low = line.lower()
                    if low.startswith("server:"):
                        server = line.split(":", 1)[1].strip()
                    elif low.startswith("location:"):
                        location = line.split(":", 1)[1].strip().lower()

                if code and code.startswith("30") and location:
                    if "jio.com/balanceexhaust" in location:
                        writer.close()
                        await writer.wait_closed()
                        return None, None

                low_text = text.lower()
                if server == "Unknown":
                    if "cloudfront" in low_text:
                        server = "CloudFront"
                    elif "gws" in low_text or "google" in low_text:
                        server = "Google"
                    elif "vercel" in low_text:
                        server = "Vercel"
                    elif "caddy" in low_text:
                        server = "Caddy"

                writer.close()
                await writer.wait_closed()
                return code, server
            except:
                return None, None

    def save(self, line):
        ts = datetime.now(timezone.utc).astimezone().strftime("%H:%M:%S")
        with open(self.output, "a") as f:
            f.write(f"[{ts}] {line}\n")

    async def scan_ip(self, ip, progress, task_id):
        if ip in self.seen:
            progress.update(task_id, advance=1)
            return

        self.seen.add(ip)

        async with self.sem:
            for port in self.ports:
                if shutdown:
                    return

                if not await self.tcp_check(ip, port):
                    continue

                code, server = await self.http_head(ip, port)

                if code is None:
                    continue

                console.print(
                    f"[green]✓[/green] [cyan]{ip}[/cyan]:[yellow]{port}[/yellow] "
                    f"[magenta][{code}][/magenta] [blue]{server}[/blue]"
                )

                self.save(f"{ip}:{port} [{code}] {server}")
                self.found += 1
                break

        progress.update(task_id, advance=1)

    async def scan_file(self, filename, progress):
        if not os.path.isfile(filename):
            console.print(f"[red]✗ File {filename} not found![/red]")
            return
            
        total = sum(1 for _ in open(filename))
        task_id = progress.add_task(f"[cyan]{filename}", total=total)

        batch = []
        with open(filename) as f:
            for line in f:
                if shutdown:
                    break

                ip = line.strip()
                if not ip:
                    progress.update(task_id, advance=1)
                    continue

                batch.append(ip)

                if len(batch) >= 5000:
                    await asyncio.gather(*[
                        self.scan_ip(i, progress, task_id) for i in batch
                    ])
                    batch.clear()

        if batch:
            await asyncio.gather(*[
                self.scan_ip(i, progress, task_id) for i in batch
            ])

# ================= TOOL 3: EXTRACT DOMAINS BY WORD =================
class DomainExtractor:
    def __init__(self):
        pass

    def extract_domains(self, filename, search_word):
        """Extract domains containing the search word, excluding subdomains like www."""
        extracted = []
        
        try:
            with open(filename, 'r') as f:
                for line in f:
                    domain = line.strip()
                    if not domain:
                        continue
                    
                    # Remove protocol if exists
                    if '://' in domain:
                        domain = domain.split('://', 1)[1]
                    
                    # Remove path if exists
                    if '/' in domain:
                        domain = domain.split('/', 1)[0]
                    
                    # Remove port if exists
                    if ':' in domain:
                        domain = domain.split(':', 1)[0]
                    
                    # Check if domain contains the search word
                    if search_word.lower() in domain.lower():
                        # Split by dots to check subdomain levels
                        parts = domain.split('.')
                        
                        # Check if it's not a subdomain with www or other common subdomains
                        # Allow domains like example.com, but exclude www.example.com, api.example.com, etc.
                        # Also exclude domains with more than 2 parts (e.g., subdomain.example.com)
                        if len(parts) == 2:
                            extracted.append(domain)
                        elif len(parts) > 2:
                            # Check if the first part is a common subdomain prefix
                            # Exclude if it's www, api, mail, ftp, etc.
                            first_part = parts[0].lower()
                            common_subdomains = ['www', 'api', 'mail', 'ftp', 'blog', 'webmail', 'admin', 'test', 'dev', 'staging']
                            
                            if first_part not in common_subdomains:
                                # If it's not a common subdomain, it might be a country domain or something
                                # But we still want to exclude multi-level subdomains for accuracy
                                pass
                            # For accuracy, only take exact 2-level domains
                            # Uncomment below if you want to allow non-www subdomains
                            # extracted.append(domain)
            
            return extracted
            
        except Exception as e:
            console.print(f"[red]Error reading file: {e}[/red]")
            return []

    def run(self):
        clear()
        console.print(Panel.fit("[bold green]EXTRACT DOMAINS BY WORD[/bold green]", style="bold green"))
        
        filename = input("\n[?] Filename to extract from: ").strip()
        
        if not os.path.isfile(filename):
            console.print("[red]✗ File not found![/red]")
            input("\n[?] Press Enter to continue...")
            return
        
        search_word = input("[?] Word to search in domains: ").strip()
        
        if not search_word:
            console.print("[red]✗ Please enter a word to search![/red]")
            input("\n[?] Press Enter to continue...")
            return
        
        console.print(f"\n[cyan]🔍 Searching for domains containing '{search_word}'...[/cyan]\n")
        
        extracted = self.extract_domains(filename, search_word)
        
        if not extracted:
            console.print(f"[yellow]⚠ No domains found containing '{search_word}'[/yellow]")
        else:
            output_file = f"extracted_{search_word}_domains.txt"
            
            with open(output_file, 'w') as f:
                for domain in extracted:
                    f.write(domain + '\n')
            
            console.print(f"\n[green]✓ Found {len(extracted)} domain(s)![/green]")
            console.print(f"[green]✓ Results saved to: {output_file}[/green]")
            
            # Display first 20 domains as preview
            console.print("\n[bold cyan]Preview (first 20 domains):[/bold cyan]")
            for i, domain in enumerate(extracted[:20], 1):
                console.print(f"  {i}. [yellow]{domain}[/yellow]")
            
            if len(extracted) > 20:
                console.print(f"  ... and {len(extracted) - 20} more")
        
        input("\n[?] Press Enter to return to menu...")

# ================= TOOL 4: CLEAN & FILTER DOMAINS =================
class DomainCleaner:
    def __init__(self):
        pass
    
    def is_valid_domain(self, domain):
        """Validate if a string is a proper domain format"""
        # Domain regex pattern (simplified but effective)
        pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return re.match(pattern, domain) is not None
    
    def clean_domain(self, raw_domain):
        """Extract and clean domain from various formats"""
        domain = raw_domain.strip().lower()
        
        # Remove protocol
        if '://' in domain:
            domain = domain.split('://', 1)[1]
        
        # Remove path
        if '/' in domain:
            domain = domain.split('/', 1)[0]
        
        # Remove port
        if ':' in domain:
            domain = domain.split(':', 1)[0]
        
        # Remove trailing dots
        domain = domain.rstrip('.')
        
        return domain
    
    def filter_domains(self, input_file, output_file, min_length=3, max_length=253, remove_duplicates=True, remove_invalid=True):
        """Filter and clean domains from input file"""
        domains = []
        seen = set()
        valid_count = 0
        invalid_count = 0
        duplicate_count = 0
        
        try:
            with open(input_file, 'r') as f:
                for line_num, line in enumerate(f, 1):
                    raw_domain = line.strip()
                    if not raw_domain:
                        continue
                    
                    # Clean the domain
                    cleaned = self.clean_domain(raw_domain)
                    
                    # Check length
                    if len(cleaned) < min_length or len(cleaned) > max_length:
                        invalid_count += 1
                        continue
                    
                    # Validate domain format
                    if remove_invalid and not self.is_valid_domain(cleaned):
                        invalid_count += 1
                        continue
                    
                    # Remove duplicates
                    if remove_duplicates:
                        if cleaned in seen:
                            duplicate_count += 1
                            continue
                        seen.add(cleaned)
                    
                    domains.append(cleaned)
                    valid_count += 1
            
            # Write to output file
            with open(output_file, 'w') as f:
                for domain in domains:
                    f.write(domain + '\n')
            
            return valid_count, invalid_count, duplicate_count
            
        except Exception as e:
            console.print(f"[red]Error processing file: {e}[/red]")
            return 0, 0, 0
    
    def run(self):
        clear()
        console.print(Panel.fit("[bold green]CLEAN & FILTER DOMAINS[/bold green]", style="bold green"))
        
        input_file = input("\n[?] Input filename: ").strip()
        
        if not os.path.isfile(input_file):
            console.print("[red]✗ File not found![/red]")
            input("\n[?] Press Enter to continue...")
            return
        
        output_file = input(f"[?] Output filename (default: cleaned_{input_file}): ").strip()
        if not output_file:
            output_file = f"cleaned_{input_file}"
        
        console.print("\n[bold cyan]Filtering Options:[/bold cyan]")
        remove_duplicates = input("[?] Remove duplicates? (y/n, default: y): ").strip().lower() != 'n'
        remove_invalid = input("[?] Remove invalid domains? (y/n, default: y): ").strip().lower() != 'n'
        
        min_length = input("[?] Minimum domain length (default: 3): ").strip()
        min_length = int(min_length) if min_length else 3
        
        console.print("\n[cyan]🔄 Processing domains...[/cyan]\n")
        
        valid, invalid, duplicates = self.filter_domains(
            input_file, 
            output_file, 
            min_length=min_length,
            remove_duplicates=remove_duplicates,
            remove_invalid=remove_invalid
        )
        
        console.print(f"\n[green]✓ Processing complete![/green]")
        console.print(f"[green]✓ Valid domains: {valid}[/green]")
        if invalid > 0:
            console.print(f"[yellow]⚠ Invalid domains removed: {invalid}[/yellow]")
        if duplicates > 0:
            console.print(f"[yellow]⚠ Duplicates removed: {duplicates}[/yellow]")
        console.print(f"[green]✓ Output saved to: {output_file}[/green]")
        
        input("\n[?] Press Enter to return to menu...")

# ================= MAIN =================
async def main():
    while True:
        choice = main_menu()
        
        if choice == "1":
            scanner = DomainScanner()
            scanner.run()
        elif choice == "2":
            scanner = AdvancedScanner()
            await scanner.run_async()
        elif choice == "3":
            extractor = DomainExtractor()
            extractor.run()
        elif choice == "4":
            cleaner = DomainCleaner()
            cleaner.run()
        elif choice == "5":
            console.print("[bold red]Exiting...[/bold red]")
            break
        else:
            console.print("[red]Invalid option![/red]")
            input("\n[?] Press Enter to continue...")

def start():
    import asyncio
    asyncio.run(main())