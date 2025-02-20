sorted_file="sorted_topology.dot"
network_file="network_structure.dot"
temp_file="sorted_topology_updated.dot"

declare -A sorted_edges
declare -A network_edges

declare -A nodes  # Associative array for storing nodes

# Function to extract the key from an edge line
extract_key() {
    local line="$1"
    local regex='"([^"]+)"[[:space:]]*->[[:space:]]*"([^"]+)"'
    if [[ $line =~ $regex ]]; then
        echo "${BASH_REMATCH[1]}->${BASH_REMATCH[2]}"
    fi
}

# Read network_structure.dot and extract nodes and edges
while IFS= read -r line; do
    if [[ $line == *"->"* ]]; then
        key=$(extract_key "$line")
        if [ -n "$key" ]; then
            network_edges["$key"]="$line"
        fi
    elif [[ $line == *"["* ]]; then  # If the line contains a node description
        node_name=$(echo "$line" | awk -F ' ' '{print $1}')
        nodes[$node_name]="$line"
    fi
done < "$network_file"

# Read sorted_topology.dot and extract edges
while IFS= read -r line; do
    if [[ $line == *"->"* ]]; then
        key=$(extract_key "$line")
        if [ -n "$key" ]; then
            sorted_edges["$key"]="$line"
        fi
    fi
done < "$sorted_file"

# Determine missing edges (edges in network_structure.dot that are not in sorted_topology.dot)
missing_edges=()
for key in "${!network_edges[@]}"; do
    if [[ -z "${sorted_edges[$key]}" ]]; then
        missing_edges+=("${network_edges[$key]}")
    fi
done

# If there are missing edges or nodes, create the updated file
if [ ${#missing_edges[@]} -gt 0 ] || [ ${#nodes[@]} -gt 0 ]; then
    # Write the header to the new file
    echo "digraph topology {" > "$temp_file"
    echo "  bgcolor=\"lightgray\"" >> "$temp_file"
    echo "  rankdir=LR" >> "$temp_file"
    echo "  node [fontname=\"Arial\", fontsize=14]" >> "$temp_file"
    echo "  edge [color=dark, fontname=\"Arial\", fontsize=12]" >> "$temp_file"
    echo "" >> "$temp_file"

    # Write the nodes
    for node in "${!nodes[@]}"; do
        echo "  ${nodes[$node]}" >> "$temp_file"
    done

    echo "" >> "$temp_file"

    # Write the existing edges
    for edge in "${!sorted_edges[@]}"; do
        echo "  ${sorted_edges[$edge]}" >> "$temp_file"
    done

    # Add the missing edges
    for edge in "${missing_edges[@]}"; do
        echo "  $edge" >> "$temp_file"
    done

    # Close the graph
    echo "}" >> "$temp_file"

    # Replace the original file
    mv "$temp_file" "$sorted_file"
fi