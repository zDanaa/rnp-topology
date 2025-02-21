#!/bin/bash

# echo "Starting scan_neighbors.sh..."
# ./scan_neighbors.sh

# if [ $? -eq 0 ]; then
#     echo "scan_neighbors.sh started successfully."
# else
#     echo "ERROR: can not start scan_neighbors.sh."
#     exit 1
# fi

# echo "Sorting and customizing topology..."
# ./create_sorted_topology.sh

# if [ $? -eq 0 ]; then
#     echo "Topology created successfully."
# else
#     echo "ERROR: could not sort and customize topology!"
#     exit 1
# fi

echo "Checking configured connections..."
./check_configured_connections.sh
if [ $? -eq 0 ]; then
    echo "Checked configured connections!"
else
    echo "ERROR: could not check configured connections!"
    exit 1
fi

echo "Checking unconfigured connections..."
./check_unconfigured_connections.sh
if [ $? -eq 0 ]; then
    echo "Added unconfigured connections!"
else
    echo "ERROR: could not add unconfigured Connections!"
    exit 1
fi

echo "Merging configured and unconfigured connections..."
./merge_graphs.sh
if [ $? -eq 0 ]; then
    echo "Merged configured and unconfigured connections!"
else
    echo "ERROR: could not merge configured and unconfigured connections!"
    exit 1
fi