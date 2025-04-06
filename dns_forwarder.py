#!/usr/bin/env python

import socket
import threading
import requests

import base64
import argparse

import dnslib
from datetime import datetime

DEFAULT_DOH_SERVER = "https://1.1.1.1/dns-query"
LISTEN_IP = "0.0.0.0"  
LISTEN_PORT = 5353       

class DNSForwarder:

    def __init__(self, dst_ip=None, deny_list_file=None, log_file=None, use_doh=False, doh_server=None):
        self.dst_ip = dst_ip
        self.use_doh = use_doh
        self.doh_server = doh_server or DEFAULT_DOH_SERVER
        self.log_file = log_file
        self.deny_list = self.block_domains(deny_list_file)

    def run(self):

        # sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # while sock:
        #     sock.bind(LISTEN_IP, LISTEN_PORT)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as server_sock:
            server_sock.bind((LISTEN_IP, LISTEN_PORT))
            print(f"RUNNING ON {LISTEN_IP}:{LISTEN_PORT}\n")

            # can only be stopped with ctrl+c???? 
            while True:
                data, addr = server_sock.recvfrom(1024)
                threading.Thread(target=self.handle_request, args=(data, addr, server_sock)).run()

    def block_domains(self, file_path):
        blocked_domains = set()
        try:
            with open(file_path, "r") as f:
                for line in f:
                    if line.strip():
                        # no real error checking here, could block a random collection of stuff if you want
                        blocked_domains.add(line.strip())
            print(f"\nBlocked domain include: {blocked_domains}\n")
            return blocked_domains
        except FileNotFoundError:
            print(f"Warning: Deny list file '{file_path}' not found.")
            print("No domains will be blocked.")
            return set()

    def handle_request(self, data, addr, sock):
        
        try:
            query = dnslib.DNSRecord.parse(data)
            
            domain = str(query.q.qname).rstrip(".").lower()
            
            qtype = dnslib.QTYPE[query.q.qtype]

            # print(f"query = {query}")
            # print(f"domain = {domain}")
            # print(f"qtype = {qtype}")

            if domain in self.deny_list:
                print(f"Error! The following domain is blocked: {domain}")
                self.log(domain, qtype, "DENY")
                response = self.create_nxdomain_response(query)
                sock.sendto(response, addr)
                return

            if self.use_doh:
                response = self.forward_doh_query(data)
            else:
                response = self.forward_udp_query(data)

            if response:
                sock.sendto(response, addr)
                print(f"Success! The following domain was queried: {domain}")
                self.log(domain, qtype, "ALLOW")
            else:
                print(f"Error! The following domain was queried but no response was received: {domain}")

        except Exception as e:
            print(f"Error! {e}")

    def create_nxdomain_response(self, query):
        
        # chat recommended dnslib instead of scapy, works the same i think
        # we already nx response is thrown if we're in this method so we just copy output here 
        response = dnslib.DNSRecord(dnslib.DNSHeader(id=query.header.id, qr=1, aa=1, ra=1, rcode=3))
       
        response.add_question(query.q)

        # no method for opt psuedosection so this manually adds it, don't really need it but whatever
        for rr in query.ar:
            if rr.rtype == dnslib.QTYPE.OPT:
                response.add_ar(rr)

        return response.pack()

    def forward_udp_query(self, data):

        # basically professor's code, send to port 53
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(data, (self.dst_ip, 53))
            response, _ = sock.recvfrom(1024)
        return response

    def forward_doh_query(self, data):
        
        # makes the query safe for http
        dns_query_base64 = base64.urlsafe_b64encode(data).decode().rstrip("=")
        

        # ex: for google it was:
        # https://1.1.1.1/dns-query?dns=xwkBIAABAAAAAAABA3d3dwZnb29nbGUDY29tAAABAAEAACkE0AAAAAAADAAKAAjc-DuOI4Qjmw
        doh_url = f"https://{self.doh_server}/dns-query?dns={dns_query_base64}"
        headers = {"Accept": "application/dns-message"}
        print(f"VERIFY THE ADDRESS IS https://1.1.1.1/dns-query?dns= OR https://user_server/dns-query?dns=")
        print(f"{doh_url}\n")
              

        try:
            response = requests.get(doh_url, headers=headers, timeout=5)
            if response.status_code == 200:
                return response.content
        except requests.RequestException as e:
            print(f"Error: DoH request failed - {e}")
        return None
        
    def log(self, domain, qtype, action):
        if not self.log_file:
            return
        with open(self.log_file, "a") as f:
            # from chat, not sure if this is what he wants but it's a timestamp!!!!
            # qtype is carried over correctly but domain might still be buggy
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            f.write(f"{timestamp} {domain} {qtype} {action}\n")


def parse_arguments():


    parser = argparse.ArgumentParser(description="DoH-Capable DNS Forwarder")


    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", help="Destination DNS server IP (for UDP forwarding)")
    group.add_argument("--doh", action="store_true", help="Use the default upstream DoH server")
    group.add_argument("--doh_server", help="Specify a custom DoH server")

    # parser.add_argument("-d", "--dst_ip", help="Destination DNS server IP (for UDP forwarding)")
    # parser.add_argument("--doh", action="store_true", help="Use the default upstream DoH server")
    # parser.add_argument("--doh_server", help="Specify a custom DoH server")
    parser.add_argument("-f", "--deny_list_file", required=True, help="File containing domains to block")
    parser.add_argument("-l", "--log_file", help="Log file for recording queries")

    args = parser.parse_args()

    # if (not args.doh and not args.doh_server and not args.dst_ip):
    #     parser.error("Either --doh, --doh_server, or -d must be specified.")
    
    
    return args

if __name__ == "__main__":
    args = parse_arguments()
    forwarder = DNSForwarder(
        dst_ip=args.d,
        deny_list_file=args.deny_list_file,
        log_file=args.log_file,
        use_doh=args.doh or bool(args.doh_server),
        doh_server=args.doh_server
    )
    forwarder.run()
