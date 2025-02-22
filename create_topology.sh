EXCLUDED_HOSTS = "s1, s2, s3"
EXCLUDED_IPS = ("127.0.0.1", "127.0.1.1")
EXCLUDE_IPV6 = true
EXCLUDED_INTERFACE_ON_ALL_HOSTS = ("eth0")

echo "Checking configured connections..."
./check_configured_connections.sh EXCLUDED_HOSTS EXCLUDED_IPS EXCLUDE_IPV6
if [ $? -eq 0 ]; then
    echo "Finished checking configured connections."
else
    echo "ERROR: could not check configured connections!"
    exit 1
fi

echo "Checking unconfigured connections..."
./check_unconfigured_connections.sh EXCLUDED_HOSTS EXCLUDED_IPS EXCLUDE_IPV6 EXCLUDED_INTERFACE_ON_ALL_HOSTS
if [ $? -eq 0 ]; then
    echo "Finished checking unconfigured connections."
else
    echo "ERROR: could not add unconfigured connections!"
    exit 1
fi

echo "Merging configured and unconfigured connections..."
./merge_graphs.sh
if [ $? -eq 0 ]; then
    echo "Finished merging configured and unconfigured connections."
else
    echo "ERROR: could not merge configured and unconfigured connections!"
    exit 1
fi