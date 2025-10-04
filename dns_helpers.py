"""
Holds all the helper functions to resolve the DNS query
"""

from socket import socket, SOCK_DGRAM, AF_INET, timeout
from dnslib import DNSRecord, DNSHeader, DNSBuffer, DNSQuestion, RR, QTYPE, RCODE
import cache_manager

ROOT_SERVER = "199.7.83.42" 
DNS_PORT = 53
def get_dns_record(udp_socket, domain:str, parent_server: str, record_type):
   try:
        q = DNSRecord.question(domain, qtype = record_type)
        q.header.rd = 0   # Recursion Desired?  NO
        #print("DNS query", repr(q))

        udp_socket.sendto(q.pack(), (parent_server, DNS_PORT))
        pkt, _ = udp_socket.recvfrom(8192)
        buff = DNSBuffer(pkt) 
  
        """
        RFC1035 Section 4.1 Format
  
        The top level format of DNS message is divided into five sections:
        1. Header
        2. Question
        3. Answer
        4. Authority
        5. Additional
        """
  
        header = DNSHeader.parse(buff)
        #print("DNS header", repr(header))
        if q.header.id != header.id:
            print("Unmatched transaction")
            return False, None, "Unmatched Transaction"

        if header.rcode != RCODE.NOERROR:
            print("Query failed")
            return False, None, f"Query Failed: {header.rcode}"

        # Parse the question section #2
        questions = []
        for k in range(header.q):
            q = DNSQuestion.parse(buff)
            #print(f"Question-{k} {repr(q)}")
            questions.append(q)
       
        # Parse the answer section #3
        answers = [] 
        for k in range(header.a):
            a = RR.parse(buff)
            #print(f"Answer-{k} {repr(a)}")
            answers.append(a)
            if a.rtype == QTYPE.A:
                print("IP address Resolved")
      
        # Parse the authority section #4
        authority = []
        for k in range(header.auth):
            auth = RR.parse(buff)
            #print(f"Authority-{k} {repr(auth)}")
            authority.append(auth)
      
        # Parse the additional section #5
        additional = []
        for k in range(header.ar):
            adr = RR.parse(buff)
            #print(f"Additional-{k} {repr(adr)} Name: {adr.rname}")
            additional.append(adr)

        return True, {
            'answers': answers, 
            'authority': authority,
            'additional': additional
            }, None
   except timeout: 
        print(f"Timeout: No response from {parent_server}")
        return False, None, f"Timeout: No response from {parent_server}"
   except Exception as e: 
        print(f"Error from {parent_server}: {e}")
        return False, None, f"Error: {e}"


def get_tld_from_domain(domain):
    parts = domain.split('.')
    return parts[-1]


def extract_server_ip(response):
    
    servers = []
    ns_names = []
    
    # Get NS record names from authority section
    for record in response['authority']:
        if record.rtype == QTYPE.NS:
            ns_names.append(str(record.rdata).rstrip('.'))
    
    # Get corresponding IP addresses from additional section
    for record in response['additional']:
        if record.rtype == QTYPE.A:
            ns_name = str(record.rname).rstrip('.')
            if ns_name in ns_names:
                servers.append(str(record.rdata))
    
    return servers


def get_tld_servers(sock, tld, cache):
    
    # Check cache first
    cached_servers = cache_manager.check_cache_for_ns(cache, tld)
    if cached_servers:
        print(f"Using cached TLD servers for {tld}")
        return cached_servers
    
    # Query root server
    #print(f"Querying root server for {tld} TLD servers")
    
    success, response, error = get_dns_record(sock, tld, ROOT_SERVER, "NS")
    
    if not success:
        print(f"Root server query failed: {error}")
        return None
    
    # Extract NS records and their IP addresses
    tld_servers = extract_server_ip(response)
    
    if tld_servers:
        cache_manager.cache_ns(cache, tld, tld_servers)
        print(f"Found {len(tld_servers)} TLD servers for {tld}")
        return tld_servers
    
    return None


def get_authoritative_servers(sock, domain, tld_servers, cache):
    
    # Check cache first
    cached_servers = cache_manager.check_cache_for_ns(cache, domain)
    if cached_servers:
        print(f"Using cached authoritative servers for {domain}")
        return cached_servers
    
    # Query TLD servers
    for server_ip in tld_servers:
       #print(f"Querying TLD server {server_ip} for {domain}")
        success, response, error = get_dns_record(sock, domain, server_ip, "NS")
        
        if success:
            auth_servers = extract_server_ip(response)

            #incase auth_server doesn't return IP address in the 'additional' section
            if not auth_servers: 
                auth_servers = [] 
                print("auth_server returned incorrect format")
                for record in response['authority']:
                    if record.rtype == QTYPE.NS:
                        ns_name = str(record.rdata).rstrip('.')
                        # Resolve NS name to IP
                        ns_ip = resolve_to_ip(sock, ns_name, tld_servers)
                        if ns_ip:
                            auth_servers.append(ns_ip)


            if auth_servers:
                cache_manager.cache_ns(cache, domain, auth_servers)
                print(f"Found {len(auth_servers)} authoritative servers for {domain}")
                return auth_servers
    
    return None

def resolve_to_ip(sock, ns_name, tld_servers):
    for server_ip in tld_servers:
        success, response, error = get_dns_record(sock, ns_name, server_ip, "A")

        #checks both the answers and additional sections for an A record to resolve to.
        if success: 
            for record in response['answers']:
                if record.rtype == QTYPE.A:
                    ip = str(record.rdata)
                    print(f"Resolved {ns_name} to IP: {ip}")
                    return ip

            for record in response['additional']:
                if record.rtype == QTYPE.A:
                    ip = str(record.rdata)
                    print(f"Resolved {ns_name} to IP: {ip}")
                    return ip



    return None
                    


def get_ip_from_authoritative(sock, domain, auth_servers, cache):
    
    for server_ip in auth_servers:
        #print(f"Querying authoritative server {server_ip} for {domain}")
        success, response, error = get_dns_record(sock, domain, server_ip, "A")
        
        if success:
            # Check for A records first
            for record in response['answers']:
                if record.rtype == QTYPE.A:
                    return {'type': 'A', 'data': str(record.rdata)}
                elif record.rtype == QTYPE.CNAME:
                    return {'type': 'CNAME', 'data': str(record.rdata).rstrip('.')}
    
    return {'type': 'ERROR', 'data': 'No response from authoritative servers'}
