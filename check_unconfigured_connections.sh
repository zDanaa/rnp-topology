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

# Configure Interfaces
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

# Check Connectivity
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

# Clear ARP Cache
for host in "${!device_ips[@]}"; do
    ssh -n -o ConnectTimeout=5 "$host" "ip neigh flush nud failed 2>/dev/null" 2>/dev/null
done

# Collect MAC Addresses
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

# Analyze Network Connections
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

# Call the dot file generator script
./generate_dot_file.sh "network_topology.dot" "network_interfaces.txt" "new_topology.dot" "sorted_topology.dot"

echo "Finished collecting network information."