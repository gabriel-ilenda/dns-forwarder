#!/usr/bin/env python

import socket
import threading
import requests
import base64
import argparse
import dnslib
from datetime import datetime

# Default DoH server (Cloudflare)
DEFAULT_DOH_SERVER = "https://1.1.1.1/dns-query"

# DNS Server settings
LISTEN_IP = "0.0.0.0"  
LISTEN_PORT = 5353       

class DNSForwarder:
    def __init__(self, dst_ip=None, deny_list_file=None, log_file=None, use_doh=False, doh_server=None):
        self.dst_ip = dst_ip
        self.use_doh = use_doh
        self.doh_server = doh_server or DEFAULT_DOH_SERVER
        self.log_file = log_file
        self.deny_list = self.load_deny_list(deny_list_file)

    def load_deny_list(self, file_path):
        """Load blocked domains from a file."""
        if not file_path:
            return set()
        try:
            with open(file_path, "r") as f:
                return set(line.strip().lower() for line in f if line.strip())
        except FileNotFoundError:
            print(f"Warning: Deny list file '{file_path}' not found.")
            return set()

    def log_query(self, domain, qtype, action):
        """Log the DNS query outcome."""
        if not self.log_file:
            return
        with open(self.log_file, "a") as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{timestamp} {domain} {qtype} {action}\n")

    def create_nxdomain_response(self, query):
        """Create an NXDOMAIN response for blocked domains."""
        response = dnslib.DNSRecord(dnslib.DNSHeader(id=query.header.id, qr=1, aa=1, ra=1, rcode=3))
        response.add_question(query.q)
        return response.pack()

    def forward_udp_query(self, data):
        """Forward the DNS query via UDP to the specified resolver."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(data, (self.dst_ip, 53))
            response, _ = sock.recvfrom(512)
        return response

    def forward_doh_query(self, data):
        """Forward the DNS query using DoH (GET request)."""
        dns_query_base64 = base64.urlsafe_b64encode(data).decode().rstrip("=")
        doh_url = f"{self.doh_server}?dns={dns_query_base64}"
        headers = {"Accept": "application/dns-message"}

        try:
            response = requests.get(doh_url, headers=headers, timeout=5)
            if response.status_code == 200:
                return response.content
        except requests.RequestException as e:
            print(f"Error: DoH request failed - {e}")
        return None

    def handle_request(self, data, addr, sock):
        """Process incoming DNS queries."""
        try:
            query = dnslib.DNSRecord.parse(data)
            domain = str(query.q.qname).rstrip(".").lower()
            qtype = dnslib.QTYPE[query.q.qtype]

            # Check if the domain is blocked
            if domain in self.deny_list:
                print(f"Blocked: {domain}")
                self.log_query(domain, qtype, "DENY")
                response = self.create_nxdomain_response(query)
                sock.sendto(response, addr)
                return

            # Forward to upstream DNS resolver (DoH or standard UDP)
            if self.use_doh:
                response = self.forward_doh_query(data)
            else:
                response = self.forward_udp_query(data)

            if response:
                sock.sendto(response, addr)
                self.log_query(domain, qtype, "ALLOW")
            else:
                print(f"Error: No response received for {domain}")

        except Exception as e:
            print(f"Error processing DNS request: {e}")

    def start(self):
        """Start the DNS forwarder."""
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_sock:
            server_sock.bind((LISTEN_IP, LISTEN_PORT))
            print(f"DNS Forwarder running on {LISTEN_IP}:{LISTEN_PORT}")

            while True:
                data, addr = server_sock.recvfrom(512)
                threading.Thread(target=self.handle_request, args=(data, addr, server_sock)).start()

# Argument Parsing
def parse_arguments():
    parser = argparse.ArgumentParser(description="DoH-Capable DNS Forwarder")
    parser.add_argument("-d", "--dst_ip", help="Destination DNS server IP (for UDP forwarding)")
    parser.add_argument("-f", "--deny_list_file", required=True, help="File containing domains to block")
    parser.add_argument("-l", "--log_file", help="Log file for recording queries")
    parser.add_argument("--doh", action="store_true", help="Use the default upstream DoH server")
    parser.add_argument("--doh_server", help="Specify a custom DoH server")

    args = parser.parse_args()

    if not args.doh and not args.doh_server and not args.dst_ip:
        parser.error("Either --doh, --doh_server, or -d must be specified.")

    return args

if __name__ == "__main__":
    args = parse_arguments()
    forwarder = DNSForwarder(
        dst_ip=args.dst_ip,
        deny_list_file=args.deny_list_file,
        log_file=args.log_file,
        use_doh=args.doh or bool(args.doh_server),
        doh_server=args.doh_server
    )
    forwarder.start()
