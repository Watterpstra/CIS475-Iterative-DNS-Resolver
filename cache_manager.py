"""
Helps to manipulate the cache for DNS resolver
"""

def check_cache_for_ip(cache, domain): 
    return cache.get('ip', {}).get(domain)


def check_cache_for_ns(cache, domain):
    return cache.get('ns', {}).get(domain)


def cache_ip(cache, domain, ip):
    if 'ip' not in cache:
        cache['ip'] = {}
    cache['ip'][domain] = ip


def cache_ns(cache, domain, servers):
    if 'ns' not in cache:
        cache['ns'] = {}
    cache['ns'][domain] = servers


def show_cache(cache):
    count = 1
    entries = []
    print("\nCache contents:")
    
    # Show IP cache
    for domain, ip in cache.get('ip', {}).items():
        print(f"{count}. IP: {domain} -> {ip}")
        entries.append(('ip', domain))
        count += 1
    
    # Show NS cache
    for domain, servers in cache.get('ns', {}).items():
        print(f"{count}. NS: {domain} -> {servers}")
        entries.append(('ns', domain))
        count += 1
    
    if count == 1:
        print("Cache is empty")
    
    return entries  # Return for use in remove function


def clear_cache(cache):
    cache.clear()
    print("Cache cleared")


def remove_cache_entry(cache, command):
    try:
        # Parse the index from command
        index = int(command.split()[1])
        
        if index < 1:
            print("Error: Index must be positive")
            return
        
        # Get all entries in order
        entries = []
        for domain in cache.get('ip', {}).keys():
            entries.append(('ip', domain))
        for domain in cache.get('ns', {}).keys():
            entries.append(('ns', domain))
        
        # Check if index is valid
        if index > len(entries):
            print(f"Error: Index {index} out of range (max: {len(entries)})")
            return
        
        # Remove the entry (index is 1-based, list is 0-based)
        entry_type, domain = entries[index - 1]
        
        if entry_type == 'ip':
            del cache['ip'][domain]
            print(f"Removed IP cache entry for {domain}")
        else:  # 'ns'
            del cache['ns'][domain]
            print(f"Removed NS cache entry for {domain}")
            
    except (ValueError, IndexError):
        print("Invalid remove command. Use: .remove N (where N is a number)")
    except KeyError:
        print("Error: Cache entry not found")