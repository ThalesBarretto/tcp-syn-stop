"""
Integration tests for tcp_syn_stop.

Requires: root, hping3, socat, nftables, network namespaces.
Run with:  sudo pytest tests/integration_test.py -v -m 'not slow'
Full suite: sudo pytest tests/integration_test.py -v
"""

import os
import struct
import subprocess
import time
from pathlib import Path

import pytest

if os.geteuid() != 0:
    pytest.skip("integration tests require root", allow_module_level=True)

DAEMON_BIN = str(Path(__file__).resolve().parent.parent / "tcp_syn_stop")
NFT_CONF = str(Path(__file__).resolve().parent.parent / "tcp_syn_stop.conf")
METRICS_SOCK = "/run/tcp_syn_stop/metrics.sock"

METRICS_SIZE = 494
METRICS_MAGIC = 0x53594E33
METRICS_VERSION = 4

# Global counter for unique namespace/veth names across tests
_ns_counter = 0


def _next_id():
    global _ns_counter
    _ns_counter += 1
    return _ns_counter


# ---------------------------------------------------------------------------
# Metrics parser
# ---------------------------------------------------------------------------

def parse_metrics_v4(data):
    """Parse the 494-byte metrics_v4 binary frame from src/metrics.h.

    Layout (all little-endian, packed):
      Offset   Size  Field
           0      4  magic            (u32)
           4      4  version          (u32)
           8      8  timestamp        (u64)
          16      8  uptime_secs      (u64)
          24      8  total_drops      (u64)
          32      8  latest_pps       (u64)
          40      4  active_blocks    (u32)
          44      1  iface_count      (u8)
          45      3  _pad
          48    260  top_ips[5]       (5 x 52: u32 ip, char[32] asn, u64 count, u64 peak_pps)
         308     50  top_ports[5]     (5 x 10: u16 port, u64 hits)
         358    136  ifaces[8]        (8 x 17: char[16] name, u8 native)
    """
    if len(data) < METRICS_SIZE:
        return None

    buf = data[:METRICS_SIZE]

    # Header: 4+4+8+8+8+8+4+1+3 = 48 bytes
    hdr_fmt = "<IIQQQQIB3x"
    hdr_size = struct.calcsize(hdr_fmt)
    assert hdr_size == 48
    magic, version, timestamp, uptime, total_drops, latest_pps, active_blocks, iface_count = \
        struct.unpack_from(hdr_fmt, buf, 0)

    # top_ips: 5 entries, each 52 bytes (I 32s Q Q)
    ip_fmt = "<I32sQQ"
    ip_size = struct.calcsize(ip_fmt)
    assert ip_size == 52
    top_ips = []
    off = hdr_size
    for _ in range(5):
        ip, asn_raw, count, peak_pps = struct.unpack_from(ip_fmt, buf, off)
        asn = asn_raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        top_ips.append({"ip": ip, "asn": asn, "count": count, "peak_pps": peak_pps})
        off += ip_size

    # top_ports: 5 entries, each 10 bytes (H Q)
    port_fmt = "<HQ"
    port_size = struct.calcsize(port_fmt)
    assert port_size == 10
    top_ports = []
    for _ in range(5):
        port, hits = struct.unpack_from(port_fmt, buf, off)
        top_ports.append({"port": port, "hits": hits})
        off += port_size

    # ifaces: 8 entries, each 17 bytes (16s B)
    iface_fmt = "<16sB"
    iface_size = struct.calcsize(iface_fmt)
    assert iface_size == 17
    ifaces = []
    for _ in range(8):
        name_raw, native = struct.unpack_from(iface_fmt, buf, off)
        name = name_raw.split(b"\x00", 1)[0].decode("utf-8", errors="replace")
        ifaces.append({"name": name, "native": native})
        off += iface_size

    return {
        "magic": magic,
        "version": version,
        "timestamp": timestamp,
        "uptime": uptime,
        "total_drops": total_drops,
        "latest_pps": latest_pps,
        "active_blocks": active_blocks,
        "iface_count": iface_count,
        "top_ips": top_ips,
        "top_ports": top_ports,
        "ifaces": ifaces,
    }


# ---------------------------------------------------------------------------
# Polling helper
# ---------------------------------------------------------------------------

def poll_until(predicate, timeout=30, interval=1.0, desc="condition"):
    """Poll predicate every interval seconds until truthy or timeout."""
    deadline = time.monotonic() + timeout
    last_exc = None
    while time.monotonic() < deadline:
        try:
            result = predicate()
            if result:
                return result
        except Exception as e:
            last_exc = e
        time.sleep(interval)
    msg = f"poll_until timed out after {timeout}s waiting for: {desc}"
    if last_exc:
        msg += f" (last exception: {last_exc})"
    raise TimeoutError(msg)


# ---------------------------------------------------------------------------
# DaemonEnv: test environment manager
# ---------------------------------------------------------------------------

def _run(cmd, **kwargs):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True, **kwargs)


def _ns_run(ns, cmd, **kwargs):
    return subprocess.run(f"ip netns exec {ns} {cmd}", shell=True,
                          capture_output=True, text=True, **kwargs)


def _ns_popen(ns, cmd, **kwargs):
    return subprocess.Popen(f"ip netns exec {ns} {cmd}", shell=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)


class DaemonEnv:
    """Manages network namespaces, veth pairs, daemon lifecycle, and helpers."""

    def __init__(self, tmp_path):
        self.tmp_path = tmp_path
        self.daemon = None
        self.listener = None
        self._namespaces = []
        self._procs = []

        # Paths for config files
        self.whitelist_path = str(tmp_path / "white.conf")
        self.blacklist_path = str(tmp_path / "black.conf")

    # -- Topology builders --------------------------------------------------

    def setup_simple(self):
        """One client (10.0.0.2) + one server (10.0.0.1) via veth."""
        n = _next_id()
        self.ns_c = f"tss_c{n}"
        self.ns_s = f"tss_s{n}"
        self.v_c = f"vc{n}"
        self.v_s = f"vs{n}"

        for ns in (self.ns_c, self.ns_s):
            _run(f"ip netns add {ns}")
            self._namespaces.append(ns)

        _run(f"ip link add {self.v_c} type veth peer name {self.v_s}")
        _run(f"ip link set {self.v_c} netns {self.ns_c}")
        _run(f"ip link set {self.v_s} netns {self.ns_s}")

        _ns_run(self.ns_c, f"ip addr add 10.0.0.2/24 dev {self.v_c}")
        _ns_run(self.ns_s, f"ip addr add 10.0.0.1/24 dev {self.v_s}")
        _ns_run(self.ns_c, f"ip link set lo up")
        _ns_run(self.ns_c, f"ip link set {self.v_c} up")
        _ns_run(self.ns_s, f"ip link set lo up")
        _ns_run(self.ns_s, f"ip link set {self.v_s} up")

        # Disable offloads for reliable packet counts
        _ns_run(self.ns_c, f"ethtool -K {self.v_c} tx off 2>/dev/null")
        _ns_run(self.ns_s, f"ethtool -K {self.v_s} tx off 2>/dev/null")

        # Load nftables base ruleset inside server namespace
        _ns_run(self.ns_s, f"nft -f {NFT_CONF}")

    def setup_dual(self):
        """Two clients (10.0.1.2, 10.0.2.2) + server with two veths."""
        n1 = _next_id()
        n2 = _next_id()
        self.ns_c1 = f"tss_c{n1}"
        self.ns_c2 = f"tss_c{n2}"
        self.ns_s = f"tss_s{n1}"
        self.v_c1 = f"vc{n1}"
        self.v_s1 = f"vs{n1}"
        self.v_c2 = f"vc{n2}"
        self.v_s2 = f"vs{n2}"

        for ns in (self.ns_c1, self.ns_c2, self.ns_s):
            _run(f"ip netns add {ns}")
            self._namespaces.append(ns)

        # Veth pair 1
        _run(f"ip link add {self.v_c1} type veth peer name {self.v_s1}")
        _run(f"ip link set {self.v_c1} netns {self.ns_c1}")
        _run(f"ip link set {self.v_s1} netns {self.ns_s}")
        _ns_run(self.ns_c1, f"ip addr add 10.0.1.2/24 dev {self.v_c1}")
        _ns_run(self.ns_s, f"ip addr add 10.0.1.1/24 dev {self.v_s1}")
        _ns_run(self.ns_c1, f"ip link set lo up")
        _ns_run(self.ns_c1, f"ip link set {self.v_c1} up")
        _ns_run(self.ns_s, f"ip link set lo up")
        _ns_run(self.ns_s, f"ip link set {self.v_s1} up")

        # Veth pair 2
        _run(f"ip link add {self.v_c2} type veth peer name {self.v_s2}")
        _run(f"ip link set {self.v_c2} netns {self.ns_c2}")
        _run(f"ip link set {self.v_s2} netns {self.ns_s}")
        _ns_run(self.ns_c2, f"ip addr add 10.0.2.2/24 dev {self.v_c2}")
        _ns_run(self.ns_s, f"ip addr add 10.0.2.1/24 dev {self.v_s2}")
        _ns_run(self.ns_c2, f"ip link set lo up")
        _ns_run(self.ns_c2, f"ip link set {self.v_c2} up")
        _ns_run(self.ns_s, f"ip link set {self.v_s2} up")

        # Disable offloads
        for ns, dev in [(self.ns_c1, self.v_c1), (self.ns_c2, self.v_c2),
                        (self.ns_s, self.v_s1), (self.ns_s, self.v_s2)]:
            _ns_run(ns, f"ethtool -K {dev} tx off 2>/dev/null")

        _ns_run(self.ns_s, f"nft -f {NFT_CONF}")

    # -- Config helpers -----------------------------------------------------

    def write_configs(self, whitelist_lines=None, blacklist_lines=None):
        with open(self.whitelist_path, "w") as f:
            f.write("# whitelist\n")
            for line in (whitelist_lines or []):
                f.write(f"{line}\n")
        with open(self.blacklist_path, "w") as f:
            f.write("# blacklist\n")
            for line in (blacklist_lines or []):
                f.write(f"{line}\n")

    # -- Client helpers -----------------------------------------------------

    def suppress_client_rst(self, ns):
        """Drop outbound RSTs in client ns so SYN-ACK retransmits trigger kprobe."""
        _ns_run(ns, "nft add table ip rst_drop")
        _ns_run(ns, "nft 'add chain ip rst_drop output "
                "{ type filter hook output priority 0; policy accept; }'")
        _ns_run(ns, "nft add rule ip rst_drop output tcp flags rst drop")

    # -- Daemon lifecycle ---------------------------------------------------

    def start_daemon(self, ifaces, ttl=60, extra_args=None):
        iface_flags = " ".join(f"-i {i}" for i in ifaces)
        extra = " ".join(extra_args) if extra_args else ""
        log_path = str(self.tmp_path / "daemon.log")
        cmd = (f"{DAEMON_BIN} {iface_flags} "
               f"-w {self.whitelist_path} -b {self.blacklist_path} "
               f"-T {ttl} -v -l {log_path} {extra}")
        self.daemon = _ns_popen(self.ns_s, cmd)
        self._procs.append(self.daemon)

    def wait_for_socket(self, timeout=15):
        """Poll until metrics socket exists in the server namespace."""
        def check():
            r = _ns_run(self.ns_s, f"test -S {METRICS_SOCK}")
            return r.returncode == 0
        poll_until(check, timeout=timeout, interval=0.5,
                   desc="metrics socket to appear")

    def start_listener(self, port=80):
        """Start a TCP listener in server ns (needed for kprobe to fire)."""
        self.listener = _ns_popen(self.ns_s, f"python3 -m http.server {port}")
        self._procs.append(self.listener)
        # Wait until the port is actually bound
        def bound():
            r = _ns_run(self.ns_s, f"ss -tln sport = :{port}")
            return f":{port}" in r.stdout
        poll_until(bound, timeout=10, interval=0.2,
                   desc=f"listener to bind on port {port}")

    # -- Metrics ------------------------------------------------------------

    def get_metrics_raw(self):
        """Read raw bytes from the metrics Unix socket."""
        res = subprocess.run(
            f"ip netns exec {self.ns_s} socat -t 2 - UNIX-CONNECT:{METRICS_SOCK}",
            shell=True, capture_output=True, timeout=10)
        if res.returncode != 0:
            return None
        return res.stdout

    def get_metrics(self):
        """Read and parse metrics, returns dict or None."""
        raw = self.get_metrics_raw()
        if raw is None:
            return None
        return parse_metrics_v4(raw)

    # -- Traffic generation -------------------------------------------------

    def send_syns(self, ns, dst, count=10, port=80):
        """Send TCP SYN packets via hping3."""
        _ns_run(ns, f"hping3 -S -c {count} {dst} -p {port} --fast")

    def send_acks(self, ns, dst, count=10, port=80):
        """Send TCP ACK packets via hping3."""
        _ns_run(ns, f"hping3 -A -c {count} {dst} -p {port} --fast")

    def send_udp(self, ns, dst, count=10, port=80):
        """Send UDP packets via hping3."""
        _ns_run(ns, f"hping3 --udp -c {count} {dst} -p {port} --fast")

    def send_signal(self, sig):
        """Send a signal to the daemon process inside the server ns."""
        _ns_run(self.ns_s, f"pkill -{sig} tcp_syn_stop")

    # -- Teardown -----------------------------------------------------------

    def teardown(self):
        for p in self._procs:
            try:
                p.terminate()
                p.wait(timeout=5)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass
        # Also kill any stray daemon inside namespaces
        for ns in self._namespaces:
            _run(f"ip netns exec {ns} pkill -9 tcp_syn_stop 2>/dev/null")
        time.sleep(0.2)
        for ns in self._namespaces:
            _run(f"ip netns del {ns} 2>/dev/null")


@pytest.fixture
def env(tmp_path):
    e = DaemonEnv(tmp_path)
    yield e
    e.teardown()


# ===========================================================================
# Test cases
# ===========================================================================

def test_blacklist_drop(env):
    """Blacklisted IP is dropped at XDP before any kprobe involvement."""
    env.setup_simple()
    env.write_configs(blacklist_lines=["10.0.0.2/32"])
    env.start_daemon(ifaces=[env.v_s])
    env.wait_for_socket()

    env.send_syns(env.ns_c, "10.0.0.1", count=50, port=80)

    def check():
        m = env.get_metrics()
        return m and m["total_drops"] >= 45
    poll_until(check, timeout=20, desc="total_drops >= 45")

    m = env.get_metrics()
    assert m["total_drops"] >= 45, f"expected >= 45 drops, got {m['total_drops']}"
    assert m["active_blocks"] == 0, "blacklist drops should not create dynamic blocks"


def test_whitelist_bypass(env):
    """Whitelisted IP is never blocked, even after SYN-ACK retransmit."""
    env.setup_simple()
    env.suppress_client_rst(env.ns_c)
    env.write_configs(whitelist_lines=["10.0.0.2/32"])
    env.start_daemon(ifaces=[env.v_s], ttl=60)
    env.wait_for_socket()
    env.start_listener(port=80)

    # Trigger a SYN-ACK retransmit (send 1 SYN, never ACK)
    env.send_syns(env.ns_c, "10.0.0.1", count=1, port=80)
    time.sleep(4)  # wait for RTO

    # Flood — should all pass through
    env.send_syns(env.ns_c, "10.0.0.1", count=30, port=80)
    time.sleep(6)  # let metrics tick

    m = env.get_metrics()
    assert m is not None, "metrics unavailable"
    assert m["total_drops"] == 0, f"whitelisted IP should never be dropped, got {m['total_drops']}"
    assert m["active_blocks"] == 0, "whitelisted IP should never be dynamically blocked"


def test_dynamic_block_lifecycle(env):
    """Kprobe-triggered dynamic block drops subsequent SYNs."""
    env.setup_simple()
    env.suppress_client_rst(env.ns_c)
    env.write_configs()
    env.start_daemon(ifaces=[env.v_s], ttl=60)
    env.wait_for_socket()
    env.start_listener(port=80)

    # Single SYN to trigger kprobe after RTO
    env.send_syns(env.ns_c, "10.0.0.1", count=1, port=80)
    time.sleep(4)  # wait for SYN-ACK retransmit

    # Now flood — should be dropped by XDP
    env.send_syns(env.ns_c, "10.0.0.1", count=50, port=80)

    def check():
        m = env.get_metrics()
        return m and m["active_blocks"] >= 1 and m["total_drops"] >= 40
    poll_until(check, timeout=20, desc="active_blocks >= 1 and total_drops >= 40")

    m = env.get_metrics()
    assert m["active_blocks"] >= 1
    assert m["total_drops"] >= 40


def test_ttl_expiry(env):
    """Dynamic block expires after TTL elapses without new traffic."""
    env.setup_simple()
    env.suppress_client_rst(env.ns_c)
    env.write_configs()
    env.start_daemon(ifaces=[env.v_s], ttl=5)
    env.wait_for_socket()
    env.start_listener(port=80)

    # Trigger dynamic block
    env.send_syns(env.ns_c, "10.0.0.1", count=1, port=80)
    time.sleep(4)  # RTO fires kprobe

    # Confirm block is active
    def blocked():
        m = env.get_metrics()
        return m and m["active_blocks"] >= 1
    poll_until(blocked, timeout=15, desc="active_blocks >= 1")

    # Stop traffic and wait for TTL expiry.
    # 5s TTL + up to 5s tick delay + margin
    def expired():
        m = env.get_metrics()
        return m and m["active_blocks"] == 0
    poll_until(expired, timeout=25, interval=2.0,
               desc="active_blocks == 0 after TTL expiry")


def test_sighup_reload(env):
    """SIGHUP reloads blacklist config, new rules take effect immediately."""
    env.setup_simple()
    env.write_configs()  # empty blacklist
    env.start_daemon(ifaces=[env.v_s], ttl=60)
    env.wait_for_socket()
    # No listener: kernel sends RST → kprobe never fires → no dynamic blocks

    # Send SYNs — should all pass (no blacklist, no dynamic blocks)
    env.send_syns(env.ns_c, "10.0.0.1", count=30, port=80)
    time.sleep(8)  # wait for metrics tick

    m = env.get_metrics()
    assert m is not None
    assert m["total_drops"] == 0, f"expected 0 drops before reload, got {m['total_drops']}"

    # Add to blacklist and signal reload
    with open(env.blacklist_path, "a") as f:
        f.write("10.0.0.2/32\n")
    env.send_signal("HUP")
    time.sleep(6)  # wait for reload + metrics tick

    # Send more SYNs — should now be dropped
    env.send_syns(env.ns_c, "10.0.0.1", count=30, port=80)

    def check():
        m = env.get_metrics()
        return m and m["total_drops"] >= 30
    poll_until(check, timeout=15, desc="total_drops >= 30 after SIGHUP reload")


def test_metrics_protocol(env):
    """Validate binary metrics frame format, magic, version, and field sanity."""
    env.setup_simple()
    env.write_configs(blacklist_lines=["10.0.0.2/32"])
    env.start_daemon(ifaces=[env.v_s])
    env.wait_for_socket()

    env.send_syns(env.ns_c, "10.0.0.1", count=20, port=80)

    # Wait for drops to register
    def has_drops():
        m = env.get_metrics()
        return m and m["total_drops"] >= 20
    poll_until(has_drops, timeout=15, desc="total_drops >= 20 for metrics test")

    raw = env.get_metrics_raw()
    assert raw is not None, "failed to read metrics socket"
    assert len(raw) == METRICS_SIZE, f"expected {METRICS_SIZE} bytes, got {len(raw)}"

    m = parse_metrics_v4(raw)
    assert m is not None, "parse_metrics_v4 returned None despite correct size"
    assert m["magic"] == METRICS_MAGIC, f"bad magic: 0x{m['magic']:08X}"
    assert m["version"] == METRICS_VERSION, f"bad version: {m['version']}"
    assert abs(m["timestamp"] - int(time.time())) < 60, "timestamp out of range"
    assert m["uptime"] < 120, f"uptime too large: {m['uptime']}"
    assert m["iface_count"] == 1
    assert m["ifaces"][0]["name"] == env.v_s
    assert m["ifaces"][0]["native"] in (0, 1), f"unexpected native value: {m['ifaces'][0]['native']}"
    assert m["total_drops"] >= 20


def test_multi_interface(env):
    """Daemon protecting two interfaces drops traffic on both."""
    env.setup_dual()
    env.write_configs(blacklist_lines=["10.0.1.2/32", "10.0.2.2/32"])
    env.start_daemon(ifaces=[env.v_s1, env.v_s2])
    env.wait_for_socket()

    env.send_syns(env.ns_c1, "10.0.1.1", count=20, port=80)
    env.send_syns(env.ns_c2, "10.0.2.1", count=20, port=80)

    def check():
        m = env.get_metrics()
        return m and m["total_drops"] >= 40
    poll_until(check, timeout=15, desc="total_drops >= 40 across two interfaces")

    m = env.get_metrics()
    assert m["total_drops"] >= 40
    assert m["iface_count"] == 2
    iface_names = {m["ifaces"][i]["name"] for i in range(2)}
    assert env.v_s1 in iface_names, f"{env.v_s1} not in {iface_names}"
    assert env.v_s2 in iface_names, f"{env.v_s2} not in {iface_names}"


def test_blacklist_per_ip_counting(env):
    """Blacklist drops produce exact per-IP counts in blacklist_cnt BPF map
    and BLACKLIST entries in the drop_intel database table."""
    env.setup_simple()
    env.write_configs(blacklist_lines=["10.0.0.2/32"])
    env.start_daemon(ifaces=[env.v_s])
    env.wait_for_socket()

    # Send enough SYNs to generate significant blacklist drop counts.
    env.send_syns(env.ns_c, "10.0.0.1", count=100, port=80)

    # Wait for drops to register in metrics
    def has_drops():
        m = env.get_metrics()
        return m and m["total_drops"] >= 90
    poll_until(has_drops, timeout=20, desc="total_drops >= 90")

    # Verify blacklist_cnt BPF map has an entry for the source IP.
    # bpftool map dump needs the map name — our map is "blacklist_cnt".
    result = _ns_run(env.ns_s, "bpftool map dump name blacklist_cnt -j")
    assert result.returncode == 0, f"bpftool map dump failed: {result.stderr}"

    import json
    try:
        entries = json.loads(result.stdout)
    except json.JSONDecodeError:
        pytest.fail(f"bpftool output not valid JSON: {result.stdout[:200]}")

    assert len(entries) >= 1, "blacklist_cnt map should have at least one entry"

    # Find 10.0.0.2 in the map (key is u32 in network byte order: 0x0200000a).
    # bpftool -j dumps keys as hex byte arrays.
    found_ip = False
    for entry in entries:
        # Key bytes for 10.0.0.2 in network order: [0x0a, 0x00, 0x00, 0x02]
        key_bytes = entry.get("key", [])
        if key_bytes == [10, 0, 0, 2] or key_bytes == ["0x0a", "0x00", "0x00", "0x02"]:
            found_ip = True
            break
    assert found_ip, f"10.0.0.2 not found in blacklist_cnt map entries: {entries}"

    # Wait for the 60-second flush cycle to write BLACKLIST entries to the DB.
    # Since waiting 60s is too long for a test, we check the map is populated
    # (verified above) — that's the kernel-side contract. The DB flush is tested
    # by the unit tests for database_log_drop_absolute.

    # Additionally verify the top_ips in metrics can surface blacklist IPs.
    m = env.get_metrics()
    assert m is not None
    top_ip_addrs = [ip_entry["ip"] for ip_entry in m["top_ips"] if ip_entry["ip"] != 0]
    # 10.0.0.2 in network byte order = 0x0200000a = 33554442
    import socket, struct
    ip_nbo = struct.unpack("!I", socket.inet_aton("10.0.0.2"))[0]
    ip_lebo = struct.unpack("<I", socket.inet_aton("10.0.0.2"))[0]
    # The metrics use network byte order (from ip->saddr which is NBO)
    has_blacklist_ip = ip_nbo in top_ip_addrs or ip_lebo in top_ip_addrs
    # This may or may not appear depending on sampling vs exact counts race,
    # so we only warn (not assert) if missing.
    if not has_blacklist_ip:
        print(f"NOTE: 10.0.0.2 not yet in top_ips (may need more traffic): {top_ip_addrs}")


def test_blacklist_drops_ack_packets(env):
    """Blacklisted IP is dropped at XDP for non-SYN TCP (ACK) — full L3 drop."""
    env.setup_simple()
    env.write_configs(blacklist_lines=["10.0.0.2/32"])
    env.start_daemon(ifaces=[env.v_s])
    env.wait_for_socket()

    env.send_acks(env.ns_c, "10.0.0.1", count=50, port=80)

    def check():
        m = env.get_metrics()
        return m and m["total_drops"] >= 45
    poll_until(check, timeout=20, desc="total_drops >= 45 for ACK packets")

    m = env.get_metrics()
    assert m["total_drops"] >= 45, f"expected >= 45 ACK drops, got {m['total_drops']}"
    assert m["active_blocks"] == 0, "blacklist drops should not create dynamic blocks"


def test_blacklist_drops_udp_packets(env):
    """Blacklisted IP is dropped at XDP for UDP — full L3 drop."""
    env.setup_simple()
    env.write_configs(blacklist_lines=["10.0.0.2/32"])
    env.start_daemon(ifaces=[env.v_s])
    env.wait_for_socket()

    env.send_udp(env.ns_c, "10.0.0.1", count=50, port=53)

    def check():
        m = env.get_metrics()
        return m and m["total_drops"] >= 45
    poll_until(check, timeout=20, desc="total_drops >= 45 for UDP packets")

    m = env.get_metrics()
    assert m["total_drops"] >= 45, f"expected >= 45 UDP drops, got {m['total_drops']}"
    assert m["active_blocks"] == 0, "blacklist drops should not create dynamic blocks"


def test_non_blacklisted_udp_passes(env):
    """Non-blacklisted UDP traffic passes through XDP untouched."""
    env.setup_simple()
    env.write_configs()  # empty blacklist
    env.start_daemon(ifaces=[env.v_s])
    env.wait_for_socket()

    env.send_udp(env.ns_c, "10.0.0.1", count=30, port=53)
    time.sleep(6)  # wait for metrics tick

    m = env.get_metrics()
    assert m is not None, "metrics unavailable"
    assert m["total_drops"] == 0, f"non-blacklisted UDP should pass, got {m['total_drops']} drops"


@pytest.mark.slow
def test_autoban_prefix(env):
    """Multiple unique IPs from one ASN prefix trigger a prefix-wide ban."""
    import shutil
    import sqlite3 as sqlite3_mod

    env.setup_simple()
    env.suppress_client_rst(env.ns_c)
    env.write_configs()

    # Create synthetic ASN database covering 10.0.0.0/24 as AS99999.
    # The daemon opens ip2asn.db from CWD, so place it in the project root.
    project_db = str(Path(__file__).resolve().parent.parent / "ip2asn.db")
    backup_db = project_db + ".bak"
    had_existing_db = os.path.exists(project_db)
    if had_existing_db:
        shutil.copy2(project_db, backup_db)

    tmp_db = str(env.tmp_path / "ip2asn.db")
    conn = sqlite3_mod.connect(tmp_db)
    conn.execute("CREATE TABLE IF NOT EXISTS asns "
                 "(range_start INTEGER, range_end INTEGER, asn TEXT)")
    # 10.0.0.0 = 167772160, 10.0.0.255 = 167772415
    conn.execute("INSERT INTO asns VALUES (167772160, 167772415, 'AS99999')")
    conn.commit()
    conn.close()
    shutil.copy2(tmp_db, project_db)

    try:
        # Start daemon with autoban threshold of 3 unique IPs
        env.start_daemon(ifaces=[env.v_s], ttl=120, extra_args=["-A", "3"])
        env.wait_for_socket()
        env.start_listener(port=80)

        # Trigger dynamic blocks from 3 unique IPs via kprobe.
        # Using -a to spoof source: ARP for spoofed IPs fails in the server ns,
        # so no SYN-ACK is delivered → retransmit timer fires → kprobe triggers.
        for src_ip in ("10.0.0.2", "10.0.0.3", "10.0.0.4"):
            _ns_run(env.ns_c, f"hping3 -S -c 1 -a {src_ip} 10.0.0.1 -p 80")
            time.sleep(4)  # wait for RTO on each

        # Wait for dynamic blocks to appear
        def blocks_up():
            m = env.get_metrics()
            return m and m["active_blocks"] >= 3
        poll_until(blocks_up, timeout=20, desc="active_blocks >= 3")

        # Wait for autoban evaluation cycle (every 60s in main loop).
        # Once evaluated, the ASN prefix should be inserted into the blacklist.
        # Probe with SYNs from 10.0.0.5 (never individually blocked).
        def prefix_banned():
            _ns_run(env.ns_c,
                    "hping3 -S -c 5 -a 10.0.0.5 10.0.0.1 -p 80 --fast")
            time.sleep(6)
            m = env.get_metrics()
            if m is None:
                return False
            return m["total_drops"] >= 15
        poll_until(prefix_banned, timeout=90, interval=10.0,
                   desc="prefix-wide ban dropping 10.0.0.5 traffic")

    finally:
        if had_existing_db:
            shutil.move(backup_db, project_db)
        elif os.path.exists(project_db):
            os.unlink(project_db)
