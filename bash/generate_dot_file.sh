#!/bin/bash

# Parameters
DOT_FILE=$1
INTERFACES_FILE=$2
OUTPUT_FILE=$3
OUTPUT_FINAL=$4

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