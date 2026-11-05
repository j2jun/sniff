# Runs INSIDE the sandbox in CI. Prints ISOLATED only if every escape route is closed.
set -u
touch /src/x 2>/dev/null && { echo "FAIL: source is writable"; exit 1; }
touch /etc/x 2>/dev/null && { echo "FAIL: root fs is writable"; exit 1; }
[ "$(id -u)" = 65534 ] || { echo "FAIL: not running as nobody"; exit 1; }
python -c 'import socket; socket.create_connection(("1.1.1.1", 53), 3)' 2>/dev/null && { echo "FAIL: network reachable"; exit 1; }
touch /work/ok || { echo "FAIL: workdir not writable"; exit 1; }
echo ISOLATED
