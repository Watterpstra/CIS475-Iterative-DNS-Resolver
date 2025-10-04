from dnslib import DNSRecord, DNSHeader, DNSBuffer, DNSQuestion, RR, QTYPE, RCODE
from socket import socket, SOCK_DGRAM, AF_INET
import dns_helpers
import cache_manager

ROOT_SERVER = "199.7.83.42"

def resolve_domain(sock, domain, cache):
    
    print(f"\nResolving: {domain}")
    original_domain = domain
    
    # Handle potential CNAME chains
    max_redirects = 10  # Prevent infinite loops
    redirect_count = 0
    
    while redirect_count < max_redirects:
        # Check cache first
        cached_ip = cache_manager.check_cache_for_ip(cache, domain)
        if cached_ip:
            print(f"Found {domain} in cache: {cached_ip}")
            if domain != original_domain:
                print(f"Resolved {original_domain} to: {cached_ip}")
            return
        
        # Step 1: Get TLD servers for domain
        tld = dns_helpers.get_tld_from_domain(domain)
        tld_servers = dns_helpers.get_tld_servers(sock, tld, cache)
        
        if not tld_servers:
            print(f"Failed to get TLD servers for {tld}")
            return
        
        # Step 2: Get authoritative servers for domain
        auth_servers = dns_helpers.get_authoritative_servers(sock, domain, tld_servers, cache)
        
        if not auth_servers:
            print(f"Failed to get authoritative servers for {domain}")
            return
        
        # Step 3: Get IP address from authoritative server
        result = dns_helpers.get_ip_from_authoritative(sock, domain, auth_servers, cache)
        
        if result['type'] == 'A':
            print(f"Resolved {original_domain} to: {result['data']}")
            cache_manager.cache_ip(cache, domain, result['data'])
            return
        elif result['type'] == 'CNAME':
            print(f"{domain} is an alias for {result['data']}")
            domain = result['data']  # Follow the alias
            redirect_count += 1
        else:
            print(f"Failed to resolve {domain}: {result['data']}")
            return
    
    print(f"Too many redirects for {original_domain}")
        
    
def main():
    """
    Main Program input
    """
    sock = socket(AF_INET, SOCK_DGRAM)
    sock.settimeout(5) #internet at home was slow so had to increase timeout
    cache = {}  # Dictionary to store cached results
    
    print("DNS Resolver Client")
    
    while True:
        domain_name = input("Enter a domain name or command > ").strip()
        
        if not domain_name:
            continue
        elif domain_name == '.exit':
            print("Goodbye!")
            break
        elif domain_name == '.list':
            cache_manager.show_cache(cache)
        elif domain_name == '.clear':
            cache_manager.clear_cache(cache)
        elif domain_name.startswith('.remove '):
            cache_manager.remove_cache_entry(cache, domain_name)
        else:
            resolve_domain(sock, domain_name, cache)
    
    sock.close()


if __name__ == '__main__':
    main()