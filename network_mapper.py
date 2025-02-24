import ipaddress
import subprocess
import argparse
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
import graphviz

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
        # OpenWRT hostname is stored in UCI system config
        return ssh_command(host, "uci get system.@system[0].hostname")
    return debian_hostname

def get_ip_address_per_interface(host, exclude_interfaces):
    """Get IP address per interface on a remote host"""
    result = ssh_command(host, "ip -4 addr show")
    interfaces = {}
    for line in result.splitlines():
        if "inet " in line:
            parts = line.split()
            interface = parts[-1]
            # Extract only the IP address, without the subnet mask
            ip = parts[1].split('/')[0]  
            if interface not in exclude_interfaces:
                interfaces[interface] = ip
    return interfaces

def get_mac_address_per_interface(host, exclude_interfaces):
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
            if current_interface and current_interface not in exclude_interfaces and mac_address != "00:00:00:00:00:00":
                interfaces[current_interface] = mac_address

    return interfaces

def get_hosts_from_ip_route(host, exclude_interfaces):
    """Get hosts from the output of 'ip route' command"""
    result = ssh_command(host, "ip route")
    hosts = {}
    for line in result.splitlines():
        parts = line.split()
        if "via" in parts:
            ip = parts[2]
            interface = parts[-1]
            if interface not in exclude_interfaces:
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

def get_hosts_from_ip_neigh(host, interface):
    """Get hosts from the output of 'ip neigh' command"""
    result = ssh_command(host, f"ip neigh show dev {interface}")
    hosts = {}
    for line in result.splitlines():
        parts = line.split()
        if len(parts) > 3 and (parts[3] == "REACHABLE" or parts[3] == "STALE"):
            ip = parts[0]
            if ":" not in ip:
                hosts.setdefault(interface, []).append(ip)
    return hosts

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
    print(f"Processing host {host}")
    print(f"Getting local info for host {host}")
    host_info = {
        "name": get_host_name(host),
        "interfaces": get_ip_address_per_interface(host, exclude_interfaces),
        "mac_addresses": get_mac_address_per_interface(host, exclude_interfaces),
        "ip_route_hosts": get_hosts_from_ip_route(host, exclude_interfaces),
    }
    print(f"ARP scanning for host {host}")
    for interface, ip in host_info["interfaces"].items():
        if interface not in exclude_interfaces:
            host_info["arp_scan_hosts"] = get_hosts_from_arp_scan(host, interface)
            host_info["ip_neigh_hosts"] =  get_hosts_from_ip_neigh(host, interface)

    all_ips.update(host_info["interfaces"].values())
    for interface, ip in host_info["arp_scan_hosts"].items():
        all_ips.update(ip)
    for interface, ip in host_info["ip_neigh_hosts"].items():
        all_ips.update(ip)
    all_ips.update(host_info["ip_route_hosts"].values())

    return host, host_info


def traceroute_for_host(host, exclude_interfaces, all_ips, hosts):
    """ 
    Traceroute to all ips for every interface. Stop searching on an interface if a first hop is found. 
    Mark the first hop as a connection and continue to the next interface. 
    """
    with ThreadPoolExecutor() as executor:
        futures = []
        for interface, ip in hosts[host]["interfaces"].items():
            if interface not in exclude_interfaces:
                futures.append(executor.submit(traceroute_for_interface, host, interface, all_ips, hosts))

        for future in as_completed(futures):
            future.result()

def traceroute_for_interface(host, interface, all_ips, hosts):
    host_ips = hosts[host]["interfaces"].values()
    host_ips_list = list(host_ips)
    for target in all_ips:
        if target in host_ips_list:
            print(f"Skipping traceroute because {target} is {host}")
            continue
        first_hop = get_first_traceroute_hop(host, interface, target)
        if first_hop and first_hop not in host_ips:
            print(f"Found first hop {first_hop} from {host} to {target} via {interface}")
            hosts[host].setdefault("connections", {})[interface] = first_hop
            break  

def collect_topology(subnets, exclude_hosts, exclude_ips, exclude_interfaces, exclude_ipv6, output_json):
    all_ips = set()
    hosts = {}
    with ThreadPoolExecutor() as executor:
        futures = []
        for subnet in subnets:
            print(f"Scanning subnet {subnet}")
            discovered_hosts = ping_sweep(subnet)
            for host in discovered_hosts:
                # Process each host in parallel
                futures.append(executor.submit(process_host, host, exclude_hosts, exclude_ips, exclude_interfaces, exclude_ipv6, all_ips))

        for future in as_completed(futures):
            result = future.result()
            if result:
                host, host_info = result
                hosts[host] = host_info

    with ThreadPoolExecutor() as executor:
        futures = []
        for host in hosts:
            # Traceroute to all IPs for every interface in parallel
            futures.append(executor.submit(traceroute_for_host, host, exclude_interfaces, all_ips, hosts))

        for future in as_completed(futures):
            future.result()

    print(json.dumps(hosts, indent=4))
    print(f"Saving topology to {output_json}")
    with open(output_json, "w") as f:
        json.dump(hosts, f, indent=4)
    return hosts

def reduce_network_data(network_data):
    # Create a mapping from hostname to its interface IP addresses
    host_to_ips = {data["name"]: list(data["interfaces"].values()) for data in network_data.values()}
    # Create a mapping from IP address to its hostname
    ips_to_host = {ip: host for host, ips in host_to_ips.items() for ip in ips}
    reduced_data = {}
    for ip, data in network_data.items():
        connections = {}
        for interface, connection_ip in data.get("connections", {}).items():
            connections[interface] = ips_to_host.get(connection_ip, connection_ip)
        reduced_data[data["name"]] = {
            "connections": connections
        }
    return reduced_data

def remove_interfaces_from_graph(network_data, interfaces_to_drop):
    for data in network_data.values():
        for interface in interfaces_to_drop:
            data["mac_addresses"].pop(interface, None)
            data["ip_route_hosts"].pop(interface, None)
            data["arp_scan_hosts"].pop(interface, None)
            data["connections"].pop(interface, None)
            data["ip_neigh_hosts"].pop(interface, None)

def generate_dot_graph(network_data, output_dot, output_png):
    dot = graphviz.Digraph(format="png")
    dot.attr(rankdir="LR", bgcolor="gray", overlap="false")
    edges = set()
    
    with dot.subgraph() as s:
        s.attr(rank="same")
        for node, data in network_data.items():
            if "pc" in node:
                s.node(node, shape="ellipse", style="filled", fillcolor="lightyellow", fontname="Arial")
    
    for node, data in network_data.items():
        if "router" in node:
            dot.node(node, shape="box", style="filled", fillcolor="steelblue", fontname="Arial")
        for interface, connection in data["connections"].items():
            if (node, connection) not in edges:
                dot.edge(node, connection, label=interface, fontsize="10", color="black", arrowhead="normal", minlen="2")
                edges.add((node, connection))
    
    print(dot.source)
    print(f"Saving graph to {output_dot}")
    with open(output_dot, "w") as f:
        f.write(dot.source)
    print(f"Saving graph as PNG to {output_png}")
    if (output_png.endswith(".png")):
        output_png= output_png.replace(".png", "")
    dot.render(output_png, format="png", cleanup=True)

def main():
    parser = argparse.ArgumentParser(description="Network Topology Discovery")
    parser.add_argument("--subnets", nargs="*", default=["192.168.0.0/27"], help="Subnets to scan using ping sweep")
    parser.add_argument("--exclude-hosts", nargs="*", default=["s1", "s2", "s3"], help="Hosts to exclude")
    parser.add_argument("--exclude-ips", nargs="*", default=["127.0.0.1", "127.0.1.1"], help="IPs to exclude")
    parser.add_argument("--exclude-interfaces-scan", nargs="*", default=["lo"], help="Interfaces to exclude from scanning")
    parser.add_argument("--exclude-interfaces-graph", nargs="*", default=["lo", "eth0"], help="Interfaces to exclude from graph")
    parser.add_argument("--exclude-ipv6", action="store_true", help="Exclude IPv6 addresses")
    parser.add_argument("--output-json", default="topology.json", help="Export topology to JSON file")
    parser.add_argument("--output-dot", default="topology.dot", help="Export topology to .dot file")
    parser.add_argument("--output-png", default="network_graph.png", help="Export topology to PNG file")
    parser.add_argument("--verbose", action="store_false", help="Enable verbose output")
    args = parser.parse_args()
    
    topology = collect_topology(
        subnets=args.subnets,
        exclude_hosts=args.exclude_hosts,
        exclude_ips=args.exclude_ips,
        exclude_interfaces=args.exclude_interfaces_scan,
        exclude_ipv6=args.exclude_ipv6,
        output_json=args.output_json
    )

    remove_interfaces_from_graph(
        network_data=topology, 
        interfaces_to_drop=args.exclude_interfaces_graph
    )

    generate_dot_graph(
        network_data=reduce_network_data(topology), 
        output_dot=args.output_dot, 
        output_png=args.output_png
    )
    
if __name__ == "__main__":
    main()