set -e

# Set up environment for end-to-end tests in a dedicated namespace
echo "Setting up e2e test environment..."
ip link set lo up

./fippf serve --config_dir ./core --sock ./fippf.sock &
pid_fippf=$!
cleanup_fippf() {
    kill $pid_fippf
    rm ./fippf.sock
}
trap "cleanup_fippf" EXIT SIGINT SIGTERM

python test/mock_socks5_server.py --listen 0.0.0.0:8001 &
pid_socks5=$!
cleanup_socks5() {
    kill $pid_socks5
}
trap "cleanup_socks5; cleanup_fippf" EXIT SIGINT SIGTERM

sleep 1

# E2E test
if ! ip addr | grep tun; then
    echo "No tun interface found, something might be wrong"
    exit 1
fi
# Let traffic goes though fake-ip dns and tunnel interface
python test/test_with_curl.py --dns-servers 127.0.0.52:53

echo "E2E test completed successfully."
