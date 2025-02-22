import ipaddress
import subprocess
import argparse
import json

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

def get_ip_address_per_interface(host):
    """Get IP address per interface on a remote host"""
    result = ssh_command(host, "ip -4 addr show")
    interfaces = {}
    for line in result.splitlines():
        if "inet " in line:
            parts = line.split()
            interface = parts[-1]
            ip = parts[1]
            interfaces[interface] = ip
    return interfaces

def get_hosts_from_ip_route(host):
    """Get hosts from the output of 'ip route' command"""
    result = ssh_command(host, "ip route")
    hosts = []
    for line in result.splitlines():
        parts = line.split()
        if "via" in parts:
            ip = parts[2]
            hosts.append(ip)
    return hosts

def get_hosts_from_arp_scan(host, interface):
    """Perform ARP scanning on a remote host"""
    result = ssh_command(host, f"arp-scan --interface={interface} --localnet")
    hosts = []
    for line in result.splitlines():
        parts = line.split()
        if len(parts) > 1 and parts[0].count('.') == 3:  # Basic IP validation
            hosts.append(parts[0])
    return hosts

def get_hosts_from_traceroute(host, targets):
    """Get hosts from the output of traceroute command"""
    hosts = []
    for target in targets:
        if target != host:
            result = ssh_command(host, f"traceroute -n {target}")
            for line in result.splitlines():
                parts = line.split()
                if parts[0].isdigit():
                    ip = parts[1]
                    hosts.append(ip)
    return hosts

def initial_ping_sweep(subnet):
    """Ping sweep to discover live hosts in the network"""
    discovered_hosts = []
    network = ipaddress.ip_network(subnet)
    for ip in network.hosts():
        result = run_command(f"ping -c 1 -W 1 {ip} | grep 'bytes from'")
        if result:
            print(f"===================== Found host: {ip} =====================")
            discovered_hosts.append(str(ip))
    return discovered_hosts

def collect_topology(subnets, exclude_hosts, exclude_ips, exclude_interfaces, exclude_ipv6):
    topology = {}
    hosts = []

    for subnet in subnets:
        hosts.extend(initial_ping_sweep(subnet))

    print(f"Discovered hosts: {hosts}")
    
    for host in hosts:
        if host in exclude_ips or host in exclude_hosts:
            continue
        print(f"Processing host {host}")

        interfaces = get_ip_address_per_interface(host)
        print(f"Interfaces on {host}: {interfaces}")

        ip_route_hosts = get_hosts_from_ip_route(host)
        print(f"Hosts from 'ip route' on {host}: {ip_route_hosts}")

        arp_table_hosts = []
        for interface in interfaces:
            arp_table_hosts.extend(get_hosts_from_arp_scan(host, interface))
            print(f"Hosts from ARP table on {host} {interface}: {arp_table_hosts}")

        traceroute_hosts = get_hosts_from_traceroute(host, hosts)
        print(f"Hosts from traceroute on {host}: {traceroute_hosts}")
        
        topology[host] = {
            "interfaces": interfaces,
            "ip_route_hosts": ip_route_hosts,
            "arp_table_hosts": arp_table_hosts,
            "traceroute_hosts": traceroute_hosts,
        }
    
    return topology

def export_to_dot(topology, filename="topology.dot"):
    with open(filename, "w") as f:
        f.write("digraph topology {\n")
        for host, data in topology.items():
            for neighbor in data.get("ip_route_hosts", []):
                interface = next((iface for iface, ip in data["interfaces"].items() if ip == neighbor), None)
                if interface:
                    f.write(f'    "{host}" -> "{neighbor}" [label="{interface} ({neighbor})"];\n')
            for neighbor in data.get("arp_table_hosts", []):
                interface = next((iface for iface, ip in data["interfaces"].items() if ip == neighbor), None)
                if interface:
                    f.write(f'    "{host}" -> "{neighbor}" [label="{interface} ({neighbor})"];\n')
            for neighbor in data.get("traceroute_hosts", []):
                interface = next((iface for iface, ip in data["interfaces"].items() if ip == neighbor), None)
                if interface:
                    f.write(f'    "{host}" -> "{neighbor}" [label="{interface} ({neighbor})"];\n')
        f.write("}\n")
    print(f"Topology exported to {filename}")

def main():
    parser = argparse.ArgumentParser(description="Network Topology Discovery")
    parser.add_argument("--subnets", nargs="*", default=["192.168.0.0/27"], help="Subnets to scan using ping sweep")
    parser.add_argument("--exclude-hosts", nargs="*", default=["s1", "s2", "s3"], help="Hosts to exclude")
    parser.add_argument("--exclude-ips", nargs="*", default=["127.0.0.1", "127.0.1.1"], help="IPs to exclude")
    parser.add_argument("--exclude-interfaces", nargs="*", default=["lo"], help="Interfaces to exclude")
    parser.add_argument("--exclude-ipv6", action="store_true", help="Exclude IPv6 addresses")
    parser.add_argument("--output-dot", default="topology.dot", help="Export topology to .dot file")
    args = parser.parse_args()
    
    topology = collect_topology(
        subnets=args.subnets,
        exclude_hosts=args.exclude_hosts,
        exclude_ips=args.exclude_ips,
        exclude_interfaces=args.exclude_interfaces,
        exclude_ipv6=args.exclude_ipv6,
    )
    
    export_to_dot(topology, args.output_dot)
    print(json.dumps(topology, indent=4))
    
if __name__ == "__main__":
    main()