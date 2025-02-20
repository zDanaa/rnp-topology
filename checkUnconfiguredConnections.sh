#!/bin/bash

echo "Started collecting network information."

# Arrays for managing IP addresses and device names
declare -A last_ips
declare -A device_ips
declare -A all_devices    # to store all hostnames that were not skipped

# Function to configure the interface on the host
activate_interface() {
    local host=$1
    local interface=$2
    local x=$3
    local y=$4
    local new_ip="10.6.${x}.${y}/24"
    local new_ip_raw="10.6.${x}.${y}"

    ssh -n -o ConnectTimeout=10 "$host" "
        ip link set dev $interface down >/dev/null 2>&1
        ip addr flush dev $interface >/dev/null 2>&1
        ip link set dev $interface up
        if ! ip addr add $new_ip dev $interface; then
            echo 'INTERFACE_CONFIGURATION_ERROR'
            exit 1
        fi
        exit 0
    " 2>/dev/null
    device_ips["$host"]+="$new_ip_raw "
}

#Configure Interfaces
while read -r line; do
    # Skip comments and empty lines
    [[ $line =~ ^# ]] && continue
    [[ -z $line ]] && continue

    ip=$(awk '{print $1}' <<< "$line")
    hostname=$(awk '{print $2}' <<< "$line")

    # Skip loopback, switches (s1, s2, s3) and IPv6 addresses
    if [[ $ip == "127.0.0.1" || $ip == "127.0.1.1" ]] || \
       [[ $hostname == "s1" || $hostname == "s2" || $hostname == "s3" ]] || \
       [[ $ip == *:* ]]; then
        continue
    fi

    # Save the device for subsequent node determination
    all_devices["$hostname"]=1

    # Get all interfaces except eth0
    interfaces=$(ssh -n -o ConnectTimeout=10 "$hostname" \
        "ip -o link show 2>/dev/null | awk -F': ' '{print \$2}' | grep -E '^eth[1-9][0-9]*$'")

    for interface in $interfaces; do
        if [[ $interface =~ ^eth([1-9][0-9]*)$ ]]; then
            x=${BASH_REMATCH[1]}
            last_ips[$x]=$(( ${last_ips[$x]:-0} + 1 ))
            activate_interface "$hostname" "$interface" "$x" "${last_ips[$x]}"
        fi
    done
done < /etc/hosts

#Check Connectivity
for host in "${!device_ips[@]}"; do
    targets=()
    for other_host in "${!device_ips[@]}"; do
        [ "$other_host" == "$host" ] && continue
        targets+=(${device_ips["$other_host"]})
    done

    [ ${#targets[@]} -eq 0 ] && continue

    ssh -n -o ConnectTimeout=10 "$host" "
        total=0
        success=0
        for ip in ${targets[@]}; do
            total=\$((total + 1))
            if ping -c 1 -W 1 \"\$ip\" >/dev/null 2>&1; then
                success=\$((success + 1))
            fi
        done
    " 2>/dev/null &
done
wait

#Clear ARP Cache
for host in "${!device_ips[@]}"; do
    ssh -n -o ConnectTimeout=5 "$host" "ip neigh flush nud failed 2>/dev/null" 2>/dev/null
done

#Collect MAC Addresses
declare -A mac_db
while read -r line; do
    [[ $line =~ ^# ]] && continue
    [[ -z $line ]] && continue

    ip=$(awk '{print $1}' <<< "$line")
    hostname=$(awk '{print $2}' <<< "$line")

    if [[ $ip == "127.0.0.1" || $ip == "127.0.1.1" ]] || \
       [[ $hostname == "s1" || $hostname == "s2" || $hostname == "s3" ]] || \
       [[ $ip == *:* ]]; then
        continue
    fi

    macs=$(ssh -n -o ConnectTimeout=10 "$hostname" \
        "ip -o link show 2>/dev/null | awk '{gsub(/:/, \"\", \$2); print \$2, \$(NF-2)}'")
    while read -r entry; do
        iface=$(echo "$entry" | awk '{print $1}')
        mac=$(echo "$entry" | awk '{print $2}')
        if [[ -n $iface && -n $mac ]]; then
            mac_db["${hostname}:${iface}"]="$mac"
        fi
    done <<< "$macs"
done < /etc/hosts

#Analyze Network Connections
declare -A connections
while read -r line; do
    [[ $line =~ ^# ]] && continue
    [[ -z $line ]] && continue

    ip=$(awk '{print $1}' <<< "$line")
    hostname=$(awk '{print $2}' <<< "$line")

    if [[ $ip == "127.0.0.1" || $ip == "127.0.1.1" ]] || \
       [[ $hostname == "s1" || $hostname == "s2" || $hostname == "s3" ]] || \
       [[ $ip == *:* ]]; then
        continue
    fi

    neigh_entries=$(ssh -n -o ConnectTimeout=10 "$hostname" "ip neigh 2>/dev/null")
    while read -r entry; do
        if [[ $entry == *FAILED* ]] || [[ -z $entry ]]; then
            continue
        fi

        fields=($entry)
        iface=${fields[2]}
        mac=${fields[4]}

        for key in "${!mac_db[@]}"; do
            if [[ "${mac_db[$key]}" == "$mac" ]]; then
                remote_host=${key%%:*}
                remote_iface=${key#*:}
                if [[ "$remote_host" != "$hostname" ]]; then
                    key_conn="$hostname:$remote_host"
                    if [ -z "${connections["$key_conn"]}" ]; then
                        connections["$key_conn"]="$iface->$remote_iface"
                    else
                        connections["$key_conn"]+=", $iface->$remote_iface"
                    fi
                fi
            fi
        done
    done <<< "$neigh_entries"
done < /etc/hosts

#Generate Final Network Structure
result_file="network_structure.dot"

# Collect edges into a variable (so that they can be output in the desired order)
edges_output=""

declare -A processed
for key in "${!connections[@]}"; do
    # Format key: "A:B"
    A=${key%%:*}
    B=${key#*:}
    if [[ "$A" > "$B" ]]; then
        sorted_key="$B:$A"
    else
        sorted_key="$A:$B"
    fi
    if [[ -n "${processed[$sorted_key]}" ]]; then
        continue
    fi
    processed[$sorted_key]=1

    forward="${connections["$A:$B"]}"
    backward="${connections["$B:$A"]}"

    forward_conn=""
    if [[ -n "$forward" ]]; then
         IFS=',' read -ra fparts <<< "$forward"
         for conn in "${fparts[@]}"; do
              conn=$(echo "$conn" | sed 's/^[ \t]*//;s/[ \t]*$//')
              f_local=${conn%%->*}
              f_remote=${conn#*->}
              if [[ "$f_local" == "eth0" || "$f_remote" == "eth0" ]]; then
                 continue
              fi
              forward_conn="$conn"
              break
         done
    fi

    backward_conn=""
    if [[ -n "$backward" ]]; then
         IFS=',' read -ra bparts <<< "$backward"
         for conn in "${bparts[@]}"; do
              conn=$(echo "$conn" | sed 's/^[ \t]*//;s/[ \t]*$//')
              b_local=${conn%%->*}
              b_remote=${conn#*->}
              if [[ "$b_local" == "eth0" || "$b_remote" == "eth0" ]]; then
                 continue
              fi
              backward_conn="$conn"
              break
         done
    fi

    if [[ -n "$forward_conn" && -n "$backward_conn" ]]; then
         A_iface=${forward_conn%%->*}
         B_iface=${backward_conn%%->*}
         edges_output+="  \"$A\" -> \"$B\" [label=\"$A_iface\", dir=forward];"$'\n'
         edges_output+="  \"$B\" -> \"$A\" [label=\"$B_iface\", dir=forward];"$'\n'
    elif [[ -n "$forward_conn" ]]; then
         A_iface=${forward_conn%%->*}
         B_iface=${forward_conn#*->}
         edges_output+="  \"$A\" -> \"$B\" [label=\"$A_iface\", dir=forward];"$'\n'
         edges_output+="  \"$B\" -> \"$A\" [label=\"$B_iface\", dir=forward];"$'\n'
    elif [[ -n "$backward_conn" ]]; then
         B_iface=${backward_conn%%->*}
         A_iface=${backward_conn#*->}
         edges_output+="  \"$B\" -> \"$A\" [label=\"$B_iface\", dir=forward];"$'\n'
         edges_output+="  \"$A\" -> \"$B\" [label=\"$A_iface\", dir=forward];"$'\n'
    fi
done

# Generate the final DOT file with header, node definitions, and edges
{
  echo "digraph network {"
  echo "  bgcolor=\"lightgray\""
  echo "  rankdir=LR"
  echo "  node [fontname=\"Arial\", fontsize=14]"
  echo "  edge [color=dark, fontname=\"Arial\", fontsize=12]"
  echo ""

  # Output the node definitions. Take all devices collected from /etc/hosts.
  for device in "${!all_devices[@]}"; do
    if [[ "$device" == router* ]]; then
      style="style=filled, fillcolor=steelblue, shape=rect"
    elif [[ "$device" == pc* ]]; then
      style="style=filled, fillcolor=lightyellow, shape=ellipse"
    else
      style="style=filled, fillcolor=white, shape=ellipse"
    fi
    echo "  \"$device\" [label=\"$device\", $style];"
  done | sort

  echo ""
  # Output the edges
  echo "$edges_output"
  echo "}"
} > "$result_file"

echo "Finished collecting network information."