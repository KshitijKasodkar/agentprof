#!/bin/sh
# WSL2 (Ubuntu 24.04) setup for agentprof.   sudo ./scripts/setup_wsl.sh
# Needs a WSL kernel >= 6.3 for the socket tracepoints: in Windows PowerShell run
#   wsl --update ; wsl --shutdown
# and enable systemd + cgroup v2 in /etc/wsl.conf:  [boot] systemd=true
set -e
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
HERE="$(cd "$(dirname "$0")/.." && pwd)"
KV=$(uname -r | cut -d. -f1-2)
case "$KV" in
  5.*|6.0|6.1|6.2) echo "WARNING: kernel $KV < 6.3: socket byte counts will be missing. Run 'wsl --update' in Windows." ;;
esac
apt-get update
apt-get install -y python3 libbpf1 libbpf-dev clang make iproute2 git curl ca-certificates
mountpoint -q /sys/kernel/tracing || mount -t tracefs nodev /sys/kernel/tracing || true
make -C "$HERE/agentprof/bpf" clean all 2>/dev/null || make -C "$HERE/agentprof/bpf"
cd "$HERE" && PYTHONPATH="$HERE" python3 -m agentprof doctor --load
echo
echo "Note: agents must run INSIDE WSL to be traced (Windows apps are invisible to Linux eBPF)."
echo "tc netem is usually missing from the WSL kernel: delay experiments need the Pi."
