#!/bin/bash

EXCLUDED_HOSTS=$1
EXCLUDED_IPS=$2
EXCLUDE_IPV6=$3

DOT_FILE="network_topology.dot"
INTERFACES_FILE="network_interfaces.txt"
TMP_FILE="edges.tmp"
OUTPUT_FILE="new_topology.dot"
OUTPUT_FINAL="sorted_topology.dot"

# Clean previous output files
echo "graph topology {" > "$DOT_FILE"
> "$INTERFACES_FILE"
> "$TMP_FILE"
> "$OUTPUT_FILE"
> "$OUTPUT_FINAL"

# Function to get neighbor information and write connections to the DOT file
get_neighbors() {
    local ip=$1
    local hostname=$2

    echo "Connecting to $hostname ($ip)..."

    local routes
    routes=$(ssh -n -o ConnectTimeout=5 -o BatchMode=yes -o StrictHostKeyChecking=no root@"$ip" "ip route show" 2>/dev/null)
    if [ $? -ne 0 ]; then
        echo "Failed to connect to $hostname ($ip). Skipping..."
        return 1
    fi

    # Extract connections: for each line containing "via", get the neighbor IP and interface
    echo "$routes" | grep "via" | while read -r route_line; do
        neighbor=$(echo "$route_line" | grep -oP 'via \K[0-9.]+')
        iface=$(echo "$route_line" | grep -oP 'dev \K\S+')
        # Form the DOT file entry
        connection="  \"$hostname\" -- \"$neighbor\" [label=\"$iface\"];"
        echo "$connection" >> "$TMP_FILE"
    done

    echo ""
}

# Function to get interface information and write to the file
get_interfaces() {
    local ip=$1
    local hostname=$2

    echo "Connecting to $hostname ($ip)..."

    # Run ip addr command on the remote machine
    interfaces=$(ssh -n -o ConnectTimeout=5 -o BatchMode=yes -o StrictHostKeyChecking=no root@"$ip" "ip addr" 2>/dev/null)

    if [ $? -ne 0 ]; then
        echo "Failed to connect to $hostname ($ip). Skipping..."
        return 1
    fi

    # Extract interfaces and their IP addresses
    echo "$interfaces" | grep -E 'inet ' | while read -r line; do
        # Get the interface name (remove extra info)
        iface=$(echo "$line" | awk -F' ' '{print $NF}')

        # Get the IP address
        ip_addr=$(echo "$line" | awk '{print $2}' | cut -d '/' -f 1)

        # Skip the local interface
        if [[ "$ip_addr" == "127.0.0.1" ]]; then
            continue
        fi

        # Save to interfaces file
        echo "$hostname ($ip) - Interface: $iface, IP Address: $ip_addr" >> "$INTERFACES_FILE"
    done

    echo ""
}

# Main loop through /etc/hosts file
while read -r line; do
    # Skip comments and empty lines
    [[ $line =~ ^# ]] && continue
    [[ -z $line ]] && continue

    ip=$(echo $line | awk '{print $1}')
    hostname=$(echo $line | awk '{print $2}')

    # Skip certain hosts
    if [[ $EXCLUDED_HOSTS == *"$hostname"* ]] || [[ $EXCLUDED_IPS == *"$ip"* ]]; then
        echo "Skipping $hostname ($ip)"
        continue
    fi

    # Skip IPv6 addresses
    if [[ $EXCLUDE_IPV6 == true ]] && [[ $ip == *:* ]]; then
        echo "Skipping $hostname ($ip)"
        continue
    fi

    # Get neighbor and interface information
    get_neighbors "$ip" "$hostname"
    get_interfaces "$ip" "$hostname"
done < /etc/hosts

# Sort temporary file, remove duplicates, and append to the final DOT file
sort -u "$TMP_FILE" >> "$DOT_FILE"

# Close the graph in the DOT file
echo "}" >> "$DOT_FILE"

# Remove the temporary file
rm -f "$TMP_FILE"

echo "Topology saved to $DOT_FILE"
echo "Network interfaces saved to $INTERFACES_FILE"

# Call the dot file generator script
./generate_dot_file.sh "$DOT_FILE" "$INTERFACES_FILE" "$OUTPUT_FILE" "$OUTPUT_FINAL"