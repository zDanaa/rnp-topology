# Network Topology Discovery

## Dependencies

- `graphviz`
- `iproute2`
- `arp-scan`
- `argparse`
- `concurrent.futures`
- `python3`

## Execution

To run the network topology discovery script, use the following command:

```sh
python3 network_mapper.py
```

## Parameters

### General Options

- `-h, --help`  
    Show this help message and exit.

- `--verbose`  
    Enable verbose output (default: False).

### Exclusion Options

- `--exclude-hosts HOST [HOST ...]`  
    Exclude specific hosts (default: `['s1', 's2', 's3']`).

- `--exclude-ips IP [IP ...]`  
    Exclude specific IPs (default: `['127.0.0.1', '127.0.1.1', '192.168.27.2', '10.153.211.254']`).

- `--exclude-interfaces-scan INTERFACE [INTERFACE ...]`  
    Exclude interfaces from scanning (default: `['lo']`).

- `--exclude-interfaces-graph INTERFACE [INTERFACE ...]`  
    Exclude interfaces from the generated graph (default: `['lo', 'eth0']`).

- `--exclude-ipv6`  
    Exclude IPv6 addresses (default: False).

### Output Options

- `--output-json FILE`  
    Export topology to a JSON file (default: `topology.json`).

- `--output-dot FILE`  
    Export topology to a DOT file (default: `topology.dot`).

- `--output-png FILE`  
    Export topology to a PNG file (default: `network_graph.png`).