import ipaddress
import subprocess
import argparse
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

def run_command(command):
    try:
        print(f"Running command: {command}")
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout.strip()
    except Exception as e:
        print(f"Error running command {command}: {e}")
        return ""

def ssh_command(host, command, username="root", password=None):
    """Execute command on a remote host via SSH using subprocess"""
    ssh_command = f"ssh -o ConnectTimeout=5 {username}@{host} '{command}'"
    return run_command(ssh_command)

def get_host_name(host):
    """Get hostname of a remote host"""
    debian_hostname = ssh_command(host, "hostname")
    if debian_hostname == "":
        return ssh_command(host, "uci get system.@system[0].hostname")
    return debian_hostname

def get_ip_address_per_interface(host):
    """Get IP address per interface on a remote host"""
    result = ssh_command(host, "ip -4 addr show")
    interfaces = {}
    for line in result.splitlines():
        if "inet " in line:
            parts = line.split()
            interface = parts[-1]
            ip = parts[1].split('/')[0]  # Extract only the IP address without the subnet mask
            if interface != "lo":
                interfaces[interface] = ip
    return interfaces

def get_mac_address_per_interface(host):
    """Get MAC address per interface on a remote host"""
    result = ssh_command(host, "ip link show")
    interfaces = {}
    current_interface = None
    
    for line in result.splitlines():
        if ": " in line:
            parts = line.split(": ")
            if len(parts) > 1:
                current_interface = parts[1].split()[0]
        if "link/ether" in line:
            parts = line.split()
            mac_address = parts[1]
            if current_interface and mac_address != "00:00:00:00:00:00":
                interfaces[current_interface] = mac_address

    return interfaces

def get_hosts_from_ip_route(host):
    """Get hosts from the output of 'ip route' command"""
    result = ssh_command(host, "ip route")
    hosts = {}
    for line in result.splitlines():
        parts = line.split()
        if "via" in parts:
            ip = parts[2]
            interface = parts[-1]
            hosts[interface] = ip
    return hosts

def get_hosts_from_arp_scan(host, interface):
    """Perform ARP scanning on a remote host"""
    result = ssh_command(host, f"arp-scan --interface={interface} --localnet")
    hosts = {}
    for line in result.splitlines():
        parts = line.split()
        if len(parts) > 1 and parts[0].count('.') == 3:
            hosts.setdefault(interface, []).append(parts[0])
    return hosts

def get_hosts_from_traceroute(host, interface, target):
    """Get hosts from the output of traceroute command"""
    hosts = {}
    result = ssh_command(host, f"traceroute -n -i {interface} {target}")
    print(f"Traceroute from {host} to {target} via {interface}: {result}")
    for line in result.splitlines():
        parts = line.split()
        if parts[0].isdigit():
            ip = parts[1]
            hosts.setdefault(interface, []).append(ip)
    return hosts

def get_first_traceroute_hop(host, interface, target):
    """Get the first hop from the output of traceroute command"""
    result = ssh_command(host, f"traceroute -n -m 1 -i {interface} {target}")
    for line in result.splitlines():
        parts = line.split()
        if parts[0].isdigit() and parts[1] != "*":
            return parts[1]
    return None

def test_ping(host, interface, target):
    """Test ping to a remote host"""
    result = ssh_command(host, f"ping -c 1 -W 1 -I {interface} {target}")
    return "1 packets transmitted, 1 received" in result

def ping_sweep(subnet):
    """Ping sweep to discover live hosts in the network"""
    discovered_hosts = []
    network = ipaddress.ip_network(subnet)
    for ip in network.hosts():
        result = run_command(f"ping -c 1 -W 1 {ip} | grep 'bytes from'")
        if result:
            discovered_hosts.append(str(ip))
    return discovered_hosts

def process_host(host, exclude_hosts, exclude_ips, exclude_interfaces, exclude_ipv6, all_ips):
    if host in exclude_hosts:
        return None
    if host in exclude_ips:
        return None
    if exclude_ipv6 and ":" in host:
        return None
    host_info = {
        "name": get_host_name(host),
        "interfaces": get_ip_address_per_interface(host),
        "mac_addresses": get_mac_address_per_interface(host),
        "ip_route_hosts": get_hosts_from_ip_route(host),
    }
    for interface, ip in host_info["interfaces"].items():
        if interface not in exclude_interfaces:
            host_info["arp_scan_hosts"] = get_hosts_from_arp_scan(host, interface)

    # Collect all IP addresses from all hosts
    all_ips.update(host_info["interfaces"].values())
    for interface, ip in host_info["arp_scan_hosts"].items():
        all_ips.update(ip)
    all_ips.update(host_info["ip_route_hosts"].values())

    return host, host_info

def collect_topology(subnets, exclude_hosts, exclude_ips, exclude_interfaces, exclude_ipv6):
    all_ips = set()
    hosts = {}
    with ThreadPoolExecutor() as executor:
        futures = []
        for subnet in subnets:
            discovered_hosts = ping_sweep(subnet)
            for host in discovered_hosts:
                futures.append(executor.submit(process_host, host, exclude_hosts, exclude_ips, exclude_interfaces, exclude_ipv6, all_ips))

        for future in as_completed(futures):
            result = future.result()
            if result:
                host, host_info = result
                hosts[host] = host_info

    # Traceroute to all ips for every interface. Stop searching on an interface if a first hop is found.
    # Mark the first hop as a connection and continue to the next interface.
    with ThreadPoolExecutor() as executor:
        futures = []
        for host in hosts:
            for interface, ip in hosts[host]["interfaces"].items():
                futures.append(executor.submit(traceroute_for_interface, host, interface, all_ips, hosts))

        for future in as_completed(futures):
            future.result()

    print(f"Discovered hosts: {hosts}")
    print(json.dumps(hosts, indent=4))
    return hosts

def traceroute_for_interface(host, interface, all_ips, hosts):
    host_ips = hosts[host]["interfaces"].values()
    host_ips_list = list(host_ips)
    for target in all_ips:
        if target in host_ips_list:
            print(f"Skipping traceroute because {target} is {host}")
            continue
        first_hop = get_first_traceroute_hop(host, interface, target)
        if first_hop:
            print(f"Found first hop {first_hop} from {host} to {target} via {interface}")
            hosts[host].setdefault("connections", {})[interface] = first_hop
            break  # Break out of the inner loop and continue with the next interface

def main():
    parser = argparse.ArgumentParser(description="Network Topology Discovery")
    parser.add_argument("--subnets", nargs="*", default=["192.168.0.0/27"], help="Subnets to scan using ping sweep")
    parser.add_argument("--exclude-hosts", nargs="*", default=["s1", "s2", "s3"], help="Hosts to exclude")
    parser.add_argument("--exclude-ips", nargs="*", default=["127.0.0.1", "127.0.1.1"], help="IPs to exclude")
    parser.add_argument("--exclude-interfaces", nargs="*", default=["lo"], help="Interfaces to exclude")
    parser.add_argument("--exclude-ipv6", action="store_true", help="Exclude IPv6 addresses")
    parser.add_argument("--output-dot", default="topology.dot", help="Export topology to .dot file")
    parser.add_argument("--verbose", action="store_false", help="Enable verbose output")
    args = parser.parse_args()
    
    topology = collect_topology(
        subnets=args.subnets,
        exclude_hosts=args.exclude_hosts,
        exclude_ips=args.exclude_ips,
        exclude_interfaces=args.exclude_interfaces,
        exclude_ipv6=args.exclude_ipv6,
    )

    #generate_dot_file(topology)
    
    #export_to_dot(topology, args.output_dot)
    #print(json.dumps(topology, indent=4))
    
if __name__ == "__main__":
    main()