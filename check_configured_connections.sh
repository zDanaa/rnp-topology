#!/bin/bash

# Output file names
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
    if [[ $ip == "127.0.0.1" || $ip == "127.0.1.1" || $hostname == "s1" || $hostname == "s2" || $hostname == "s3" ]]; then
        continue
    fi

    # Skip IPv6 addresses
    if [[ $ip == *:* ]]; then
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

# Create associative arrays for IP-device mappings
declare -A ip_to_device
declare -A device_to_ip

# Parse interfaces.txt file
while IFS= read -r line; do
    # Extract device name from first part
    device=$(echo "$line" | awk -F' - ' '{print $1}' | awk '{print $1}')
    # Extract IP address using regex
    ip=$(echo "$line" | grep -oP 'IP Address: \K[0-9.]+')
    # Extract interface name using regex
    interface=$(echo "$line" | grep -oP 'Interface: \K[^,]+')
    # Store mappings in arrays
    ip_to_device["$ip"]="$device $interface"
    device_to_ip["$device"]="$ip"
done < "$INTERFACES_FILE"

# Process topology.dot file
declare -A visited
while IFS= read -r line; do
    # Skip header and closing bracket lines
    [[ "$line" == *"}"* ]] && continue
    [[ "$line" == graph* ]] && continue

    # Parse topology line components
    device1=$(echo "$line" | awk -F' -- ' '{print $1}' | tr -d '"' | xargs)
    ip_part=$(echo "$line" | awk -F' -- ' '{print $2}')
    ip=$(echo "$ip_part" | awk '{print $1}' | tr -d '"' | xargs)
    interface_label=$(echo "$ip_part" | grep -oP 'label=\K[^]]+' | tr -d '[]";' | xargs)

    # Get corresponding device information
    device_info="${ip_to_device[$ip]}"
    [ -z "$device_info" ] && echo "No device for IP: $ip" && continue

    # Split device info into components
    device2=$(echo "$device_info" | awk '{print $1}')
    interface2=$(echo "$device_info" | awk '{print $2}')
    ip1="${device_to_ip[$device1]}"

    # Generate connection strings
    conn1="\"$device1\" -> \"$device2\" [label=\"$interface_label $ip1\", dir=forward];"
    conn2="\"$device2\" -> \"$device1\" [label=\"$interface2 $ip\", dir=forward];"

    # Check connection uniqueness
    key1="$device1-$device2"
    key2="$device2-$device1"
    if [ -z "${visited[$key1]}" ] && [ -z "${visited[$key2]}" ]; then
        echo "$conn1" >> "$OUTPUT_FILE"
        echo "$conn2" >> "$OUTPUT_FILE"
        visited["$key1"]=1
        visited["$key2"]=1
    fi
done < <(tail -n +2 "$DOT_FILE")

# Generate final sorted topology file
{
    # Write graph header and styles
    echo 'digraph topology {'
    echo '  bgcolor="lightgray"'
    echo '  rankdir=LR'
    echo '  node [fontname="Arial", fontsize=14]'
    echo '  edge [color=dark, fontname="Arial", fontsize=12]'
    echo

    # Extract all unique nodes
    declare -A nodes
    while read -r line; do
        src=$(echo "$line" | awk -F'->' '{print $1}' | tr -d '"' | xargs)
        dst=$(echo "$line" | awk -F'->' '{print $2}' | awk -F'[' '{print $1}' | tr -d '"' | xargs)
        nodes["$src"]=1
        nodes["$dst"]=1
    done < "$OUTPUT_FILE"

    # Generate node definitions with styles
    for node in "${!nodes[@]}"; do
        # Determine node style based on type
        if [[ "$node" == router* ]]; then
            style="style=filled, fillcolor=steelblue, shape=rect"
        elif [[ "$node" == pc* ]]; then
            style="style=filled, fillcolor=lightyellow, shape=ellipse"
        else
            style="style=filled, fillcolor=white, shape=ellipse"
        fi
        label=$"$node"
        echo "  \"$node\" [label=\"$label\", $style];"
    done | sort

    echo

    # Sort connections by device type priority
    sort -t'"' -k2,2 -k4,4 "$OUTPUT_FILE" | awk '{
        # Assign sorting priority: PCs first, then routers, then others
        if ($2 ~ /^pc/) priority = 0;
        else if ($2 ~ /^router/) priority = 1;
        else priority = 2;
        print priority, $0
    }' | sort -n | cut -d' ' -f2-

    echo '}'
} > "$OUTPUT_FINAL"

echo "SORTED $OUTPUT_FINAL created successfully"