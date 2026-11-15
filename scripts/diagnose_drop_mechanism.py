#!/usr/bin/env python3
"""
Deep diagnostic script to investigate:
1. Socket buffer drop mechanics (cumulative drops in /proc/net/udp and nstat UdpRcvbufErrors/UdpInErrors/UdpSndbufErrors).
2. Idle tunnel wakeups (pidstat -wt per-thread, perf stat over 10s, exact Tokio worker thread count).
3. Fixed speed anomaly (UDP@20 vs TCP@20 vs UDP@50: pps, datagram size, pacing, CPU breakdown).
"""

import os
import sys
import time
import json
import subprocess
import shutil
from pathlib import Path

TEST_DIR = "/tmp/wdtt_diag_drop"
TURN_PORT = 34795
TURN_USER = "diaguser"
TURN_PASS = "diagpass"
TURN_REALM = "wdtt-diag"
PSK = "diagmechanismofbufferdrops2026v2"

CPU_COTURN = "2"   # P-core 1
CPU_SERVER = "4"   # P-core 2
CPU_CLIENT = "6"   # P-core 3
CPU_IPERF_S = "8"  # E-core 4
CPU_IPERF_C = "10" # E-core 6

procs = []

def run_cmd(cmd, check=True, capture=True):
    shell = isinstance(cmd, str)
    res = subprocess.run(cmd, shell=shell, text=True, capture_output=capture)
    if check and res.returncode != 0:
        err = res.stderr.strip() or res.stdout.strip()
        raise RuntimeError(f"Command failed (code {res.returncode}): {cmd}\nError: {err}")
    return res

def cleanup():
    for p in reversed(procs):
        try:
            p.terminate()
            p.wait(timeout=1)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
    procs.clear()

    run_cmd("sudo iptables -D INPUT -i veth-diag-host -j ACCEPT 2>/dev/null || true", check=False)
    run_cmd("sudo iptables -D INPUT -i wg-diag-srv -j ACCEPT 2>/dev/null || true", check=False)
    run_cmd("sudo pkill -9 -f 'turnserver.*34795' 2>/dev/null || true", check=False)
    run_cmd("sudo pkill -9 -f 'target/profiling/wdtt' 2>/dev/null || true", check=False)
    run_cmd("sudo ip link del wg-diag-srv 2>/dev/null || true", check=False)
    run_cmd("sudo ip link del veth-diag-host 2>/dev/null || true", check=False)
    run_cmd("sudo ip netns del wdtt-diag-ns 2>/dev/null || true", check=False)
    shutil.rmtree(TEST_DIR, ignore_errors=True)

def parse_proc_net_udp(netns=None):
    """
    Parse /proc/net/udp returning a dict of inode -> dict of info.
    """
    cmd = f"sudo ip netns exec {netns} cat /proc/net/udp" if netns else "cat /proc/net/udp"
    out = run_cmd(cmd, check=False).stdout.strip().split("\n")
    if len(out) <= 1:
        return {}
    
    entries = {}
    for line in out[1:]:
        parts = line.strip().split()
        if len(parts) >= 13:
            local_addr = parts[1]
            rem_addr = parts[2]
            tx_rx = parts[4].split(":")
            tx_q = int(tx_rx[0], 16)
            rx_q = int(tx_rx[1], 16)
            inode = parts[9]
            drops = int(parts[12])
            entries[inode] = {
                "local": local_addr,
                "rem": rem_addr,
                "tx_q": tx_q,
                "rx_q": rx_q,
                "drops": drops,
                "raw": line.strip()
            }
    return entries

def get_process_udp_inodes(pid):
    """Get all socket inodes for a given PID."""
    cmd = f"ls -l /proc/{pid}/fd 2>/dev/null | grep socket"
    out = run_cmd(cmd, check=False).stdout.strip().split("\n")
    inodes = []
    for line in out:
        if "[" in line and "]" in line:
            inode = line.split("[")[1].split("]")[0]
            inodes.append(inode)
    return inodes

def read_nstat(netns=None):
    cmd = f"sudo ip netns exec {netns} nstat -z 'Udp*'" if netns else "nstat -z 'Udp*'"
    out = run_cmd(cmd, check=False).stdout.strip().split("\n")
    res = {}
    for line in out:
        parts = line.strip().split()
        if len(parts) >= 2 and parts[0].startswith("Udp"):
            try:
                res[parts[0]] = int(parts[1])
            except ValueError:
                pass
    return res

def diff_nstat(before, after):
    diff = {}
    for k, v in after.items():
        b = before.get(k, 0)
        delta = v - b
        if delta != 0:
            diff[k] = delta
    return diff

class DiagFixture:
    def __init__(self, rcvbuf=None, sndbuf=None, disable_sock_tune=False):
        self.rcvbuf = rcvbuf
        self.sndbuf = sndbuf
        self.disable_sock_tune = disable_sock_tune
        self.server_pid = None
        self.client_pid = None
        self.coturn_pid = None

    def __enter__(self):
        cleanup()
        os.makedirs(TEST_DIR, exist_ok=True)

        # 1. Netns & veth
        run_cmd("sudo ip netns add wdtt-diag-ns")
        run_cmd("sudo ip link add veth-diag-host type veth peer name veth-diag-cl")
        run_cmd("sudo ip link set veth-diag-cl netns wdtt-diag-ns")
        run_cmd("sudo ip addr add 192.168.131.1/24 dev veth-diag-host")
        run_cmd("sudo ip link set veth-diag-host up")
        run_cmd("sudo ip -n wdtt-diag-ns addr add 192.168.131.2/24 dev veth-diag-cl")
        run_cmd("sudo ip -n wdtt-diag-ns link set veth-diag-cl up")
        run_cmd("sudo ip -n wdtt-diag-ns link set lo up")
        run_cmd("sudo iptables -I INPUT 1 -i veth-diag-host -j ACCEPT")

        # 2. Coturn
        turn_cmd = [
            "taskset", "-c", CPU_COTURN,
            "turnserver",
            "-a", "-o", "-v",
            "-u", f"{TURN_USER}:{TURN_PASS}",
            "-r", TURN_REALM,
            "-p", str(TURN_PORT),
            "-L", "192.168.131.1",
            "-E", "192.168.131.1",
            "--min-port", "49480",
            "--max-port", "49520",
            "--no-tls",
            "--no-stdout-log",
        ]
        cp = subprocess.Popen(turn_cmd)
        procs.append(cp)
        self.coturn_pid = str(cp.pid)
        time.sleep(0.5)

        # 3. Server WG
        srv_key = run_cmd("wg genkey").stdout.strip()
        srv_pub = run_cmd(f"echo {srv_key} | wg pubkey").stdout.strip()
        cl_key = run_cmd("wg genkey").stdout.strip()
        cl_pub = run_cmd(f"echo {cl_key} | wg pubkey").stdout.strip()

        with open(f"{TEST_DIR}/srv_key", "w") as f:
            f.write(srv_key)
        with open(f"{TEST_DIR}/cl_key", "w") as f:
            f.write(cl_key)

        run_cmd("sudo ip link add wg-diag-srv type wireguard")
        run_cmd(f"sudo wg set wg-diag-srv private-key {TEST_DIR}/srv_key listen-port 51830 peer {cl_pub} allowed-ips 10.151.0.2/32")
        run_cmd("sudo ip addr add 10.151.0.1/24 dev wg-diag-srv")
        run_cmd("sudo ip link set mtu 1200 dev wg-diag-srv")
        run_cmd("sudo ip link set wg-diag-srv up")
        run_cmd("sudo iptables -I INPUT 1 -i wg-diag-srv -j ACCEPT")

        # 4. Client WG in netns
        run_cmd("sudo ip -n wdtt-diag-ns link add wg-diag-cl type wireguard")
        run_cmd(f"sudo ip netns exec wdtt-diag-ns wg set wg-diag-cl private-key {TEST_DIR}/cl_key listen-port 51831 peer {srv_pub} allowed-ips 10.151.0.1/32 endpoint 127.0.0.1:51832")
        run_cmd("sudo ip -n wdtt-diag-ns addr add 10.151.0.2/24 dev wg-diag-cl")
        run_cmd("sudo ip -n wdtt-diag-ns link set mtu 1200 dev wg-diag-cl")
        run_cmd("sudo ip -n wdtt-diag-ns link set wg-diag-cl up")

        # 5. Environment
        srv_env = os.environ.copy()
        cl_env = os.environ.copy()

        if self.disable_sock_tune:
            srv_env["WDTT_DISABLE_SOCK_TUNE"] = "1"
            cl_env["WDTT_DISABLE_SOCK_TUNE"] = "1"
        else:
            if self.rcvbuf:
                srv_env["WDTT_SOCK_RCVBUF"] = str(self.rcvbuf)
                cl_env["WDTT_SOCK_RCVBUF"] = str(self.rcvbuf)
            else:
                srv_env["WDTT_SOCK_RCVBUF"] = "0"
                cl_env["WDTT_SOCK_RCVBUF"] = "0"

            if self.sndbuf:
                srv_env["WDTT_SOCK_SNDBUF"] = str(self.sndbuf)
                cl_env["WDTT_SOCK_SNDBUF"] = str(self.sndbuf)
            else:
                srv_env["WDTT_SOCK_SNDBUF"] = "0"
                cl_env["WDTT_SOCK_SNDBUF"] = "0"

        # 6. Start wdtt-server
        relayed_file = os.path.join(TEST_DIR, "relayed.txt")
        server_bin = os.path.abspath("target/profiling/wdtt-server")
        srv_cmd = [
            "taskset", "-c", CPU_SERVER,
            server_bin,
            "--turn-server", f"192.168.131.1:{TURN_PORT}",
            "--turn-user", TURN_USER,
            "--turn-pass", TURN_PASS,
            "--turn-realm", TURN_REALM,
            "--wg-endpoint", "127.0.0.1:51830",
            "--psk", PSK,
            "--relayed-addr-file", relayed_file,
        ]
        server_log = open(os.path.join(TEST_DIR, "server.log"), "w")
        server_proc = subprocess.Popen(srv_cmd, env=srv_env, stdout=server_log, stderr=server_log)
        procs.append(server_proc)
        self.server_pid = str(server_proc.pid)

        srv_relayed = None
        for _ in range(50):
            if os.path.exists(relayed_file) and os.path.getsize(relayed_file) > 0:
                with open(relayed_file) as rf:
                    srv_relayed = rf.read().strip()
                break
            time.sleep(0.1)

        if not srv_relayed:
            raise RuntimeError("wdtt-server failed to obtain relayed addr via file")

        # 7. Start wdttd in netns
        client_bin = os.path.abspath("target/profiling/wdttd")
        cl_cmd = [
            "sudo", "ip", "netns", "exec", "wdtt-diag-ns",
            "taskset", "-c", CPU_CLIENT,
            client_bin,
            "--turn-server", f"192.168.131.1:{TURN_PORT}",
            "--turn-user", TURN_USER,
            "--turn-pass", TURN_PASS,
            "--turn-realm", TURN_REALM,
            "--server-relayed", srv_relayed,
            "--wg-listen", "127.0.0.1:51832",
            "--psk", PSK,
        ]
        client_log = open(os.path.join(TEST_DIR, "client.log"), "w")
        client_proc = subprocess.Popen(cl_cmd, env=cl_env, stdout=client_log, stderr=client_log)
        procs.append(client_proc)

        time.sleep(1.5)
        run_cmd("sudo ip netns exec wdtt-diag-ns ping -c 3 -W 2 10.151.0.1")
        cl_pids = run_cmd("pgrep -f target/profiling/wdttd").stdout.strip().split()
        self.client_pid = cl_pids[-1] if cl_pids else None
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        cleanup()

def test_buffer_drops_mechanism():
    configs = [
        ("Config A (Default ~208KB)", None, None, True),
        ("Config B (SO_RCVBUF 4MB)", 4*1024*1024, None, False),
        ("Config C (SO_SNDBUF 4MB)", None, 4*1024*1024, False),
        ("Config D (Both 4MB)", 4*1024*1024, 4*1024*1024, False),
    ]

    results = []
    print("=" * 80)
    print("INVESTIGATING SOCKET BUFFER DROP MECHANICS ACROSS CONFIGS A - D")
    print("=" * 80)

    for name, rcv, snd, dis in configs:
        print(f"\n--- Running: {name} ---")
        with DiagFixture(rcvbuf=rcv, sndbuf=snd, disable_sock_tune=dis) as f:
            srv_inodes = get_process_udp_inodes(f.server_pid)
            cot_inodes = get_process_udp_inodes(f.coturn_pid)
            cl_inodes = get_process_udp_inodes(f.client_pid) if f.client_pid else []

            host_udp_before = parse_proc_net_udp()
            ns_udp_before = parse_proc_net_udp(netns="wdtt-diag-ns")
            host_nstat_before = read_nstat()
            ns_nstat_before = read_nstat(netns="wdtt-diag-ns")

            iperf_s = subprocess.Popen([
                "taskset", "-c", CPU_IPERF_S,
                "iperf3", "-s", "-1"
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

            time.sleep(0.3)
            iperf_c_cmd = [
                "sudo", "ip", "netns", "exec", "wdtt-diag-ns",
                "taskset", "-c", CPU_IPERF_C,
                "iperf3", "-c", "10.151.0.1", "-t", "10", "--json"
            ]
            c_res = run_cmd(iperf_c_cmd, check=False)
            iperf_s.wait(timeout=2)

            host_udp_after = parse_proc_net_udp()
            ns_udp_after = parse_proc_net_udp(netns="wdtt-diag-ns")
            host_nstat_after = read_nstat()
            ns_nstat_after = read_nstat(netns="wdtt-diag-ns")

            retrans = -1
            mbps = 0.0
            try:
                data = json.loads(c_res.stdout)
                end = data["end"]
                retrans = end["sum_sent"]["retransmits"]
                mbps = (end["sum_received"]["bytes"] * 8) / (end["sum_received"]["seconds"] * 1e6)
            except Exception as e:
                print(f"Error parsing iperf3 JSON: {e}")

            srv_drops = {}
            for ino in srv_inodes:
                d_bef = host_udp_before.get(ino, {}).get("drops", 0)
                d_aft = host_udp_after.get(ino, {}).get("drops", 0)
                srv_drops[ino] = {"delta": d_aft - d_bef, "total": d_aft}

            cot_drops = {}
            for ino in cot_inodes:
                d_bef = host_udp_before.get(ino, {}).get("drops", 0)
                d_aft = host_udp_after.get(ino, {}).get("drops", 0)
                if d_aft - d_bef != 0 or d_aft > 0:
                    cot_drops[ino] = {"delta": d_aft - d_bef, "total": d_aft}

            cl_drops = {}
            for ino in cl_inodes:
                d_bef = ns_udp_before.get(ino, {}).get("drops", 0)
                d_aft = ns_udp_after.get(ino, {}).get("drops", 0)
                cl_drops[ino] = {"delta": d_aft - d_bef, "total": d_aft}

            host_nstat_diff = diff_nstat(host_nstat_before, host_nstat_after)
            ns_nstat_diff = diff_nstat(ns_nstat_before, ns_nstat_after)

            print(f"Throughput: {mbps:.2f} Mbps | Retransmits: {retrans}")
            print(f"wdtt-server socket drops: {srv_drops}")
            print(f"coturn socket drops: {cot_drops}")
            print(f"wdttd socket drops: {cl_drops}")
            print(f"Host nstat deltas: {host_nstat_diff}")
            print(f"Netns nstat deltas: {ns_nstat_diff}")

            results.append({
                "config": name,
                "mbps": mbps,
                "retransmits": retrans,
                "srv_drops": srv_drops,
                "cot_drops": cot_drops,
                "cl_drops": cl_drops,
                "host_nstat": host_nstat_diff,
                "ns_nstat": ns_nstat_diff
            })

    os.makedirs("docs", exist_ok=True)
    with open("docs/drop_mechanism_results.json", "w") as f:
        json.dump(results, f, indent=2)

def test_idle_wakeups():
    print("\n" + "=" * 80)
    print("MEASURING IDLE TUNNEL WAKEUPS AND CONTEXT SWITCHES")
    print("=" * 80)

    with DiagFixture() as f:
        th_cmd = f"ls -1 /proc/{f.server_pid}/task"
        threads = run_cmd(th_cmd).stdout.strip().split()
        print(f"wdtt-server PID {f.server_pid} has {len(threads)} threads: {threads}")

        print("Running pidstat -wt over 10 seconds...")
        pidstat_cmd = f"pidstat -wt -p {f.server_pid} 10 1"
        pidstat_res = run_cmd(pidstat_cmd).stdout

        print("Running perf stat over 10 seconds...")
        perf_cmd = f"sudo perf stat -p {f.server_pid} -e context-switches,cpu-migrations,cycles,instructions sleep 10"
        perf_res = run_cmd(perf_cmd, capture=True)

        print("\n--- PIDSTAT -wt OUTPUT ---")
        print(pidstat_res)
        print("\n--- PERF STAT OUTPUT ---")
        print(perf_res.stderr)

def test_fixed_rate_anomaly():
    print("\n" + "=" * 80)
    print("INVESTIGATING FIXED RATE ANOMALY: UDP@20 vs TCP@20 vs UDP@50")
    print("=" * 80)

    rates = [
        ("TCP", "20M"),
        ("UDP", "20M"),
        ("UDP", "50M"),
    ]

    with DiagFixture() as f:
        for proto, rate in rates:
            print(f"\n--- Testing {proto} at {rate} ---")
            iperf_s = subprocess.Popen([
                "taskset", "-c", CPU_IPERF_S,
                "iperf3", "-s", "-1"
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            time.sleep(0.3)

            is_udp = (proto == "UDP")
            c_cmd = [
                "sudo", "ip", "netns", "exec", "wdtt-diag-ns",
                "taskset", "-c", CPU_IPERF_C,
                "iperf3", "-c", "10.151.0.1", "-t", "5", "-b", rate, "--json"
            ]
            if is_udp:
                c_cmd.append("-u")

            pidstat_p = subprocess.Popen([
                "pidstat", "-u", "-p", str(f.server_pid), "1", "5"
            ], stdout=subprocess.PIPE, text=True)

            c_res = run_cmd(c_cmd, check=False)
            p_out, _ = pidstat_p.communicate()
            iperf_s.wait(timeout=2)

            try:
                data = json.loads(c_res.stdout)
                end = data["end"]
                if is_udp:
                    sum_stat = end["sum"]
                    pkts = sum_stat["packets"]
                    lost = sum_stat["lost_packets"]
                    pps = pkts / sum_stat["seconds"]
                    print(f"UDP {rate}: sent {pkts} packets ({pps:.1f} pps), lost {lost} packets ({sum_stat['lost_percent']:.2f}%)")
                else:
                    sent = end["sum_sent"]
                    rcv = end["sum_received"]
                    mbps = (rcv["bytes"] * 8) / (rcv["seconds"] * 1e6)
                    print(f"TCP {rate}: {mbps:.2f} Mbps, retransmits: {sent['retransmits']}")
            except Exception as e:
                print(f"Error parsing json: {e}")

            print("Server CPU during run:")
            for l in p_out.strip().split("\n"):
                if "Average" in l or "Среднее" in l or "%usr" in l:
                    print("  ", l)

if __name__ == "__main__":
    # test_buffer_drops_mechanism()
    test_idle_wakeups()
    test_fixed_rate_anomaly()
