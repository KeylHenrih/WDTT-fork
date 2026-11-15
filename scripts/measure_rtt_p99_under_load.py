#!/usr/bin/env python3
"""
Measurement of RTT p99 under load:
Compares:
  - Without coalescing window (coalesce_ms = 0)
  - With 1ms adaptive coalescing (coalesce_ms = 1)
  - With 2ms adaptive coalescing (coalesce_ms = 2)

Workload under load:
  - Background traffic: UDP stream @ 50 Mbps
  - Concurrently: 100 ping probes at 50ms interval (5 seconds total)
  - Captures each ping RTT with microsecond precision and computes p50, p90, p95, p99, max.
"""

import json
import os
import re
import shutil
import subprocess
import time
import numpy as np

TEST_DIR = "/tmp/wdtt_rtt_bench"
TURN_PORT = 34792
TURN_USER = "benchuser"
TURN_PASS = "benchpass"
TURN_REALM = "wdtt-bench"
PSK = "rttbenchsecretkey2026version2"

CPU_COTURN = "2"
CPU_SERVER = "4"
CPU_CLIENT = "6"
CPU_IPERF_S = "8"
CPU_IPERF_C = "10"

procs = []

def run_cmd(cmd, check=True):
    env = dict(os.environ, LC_ALL="C", LANG="C")
    res = subprocess.run(cmd, shell=True, text=True, capture_output=True, env=env)
    if check and res.returncode != 0:
        err = res.stderr.strip() or res.stdout.strip()
        raise RuntimeError(f"Command failed: {cmd}\nError: {err}")
    return res

def cleanup():
    for p in reversed(procs):
        try:
            p.terminate()
            p.wait(timeout=0.5)
        except Exception:
            try: p.kill()
            except Exception: pass
    procs.clear()

    run_cmd("sudo iptables -D INPUT -i veth-cln-host -j ACCEPT 2>/dev/null || true", check=False)
    run_cmd("sudo iptables -D INPUT -i wg-cln-srv -j ACCEPT 2>/dev/null || true", check=False)
    run_cmd("sudo pkill -9 -f 'target/profiling/wdtt' 2>/dev/null || true", check=False)
    run_cmd("sudo pkill -9 -f 'iperf3' 2>/dev/null || true", check=False)
    run_cmd("sudo pkill -9 -f 'turnserver.*34792' 2>/dev/null || true", check=False)
    run_cmd("sudo ip link del wg-cln-srv 2>/dev/null || true", check=False)
    run_cmd("sudo ip link del veth-cln-host 2>/dev/null || true", check=False)
    run_cmd("sudo ip netns del wdtt-cln-ns 2>/dev/null || true", check=False)
    shutil.rmtree(TEST_DIR, ignore_errors=True)

def setup_env(coalesce_ms=0):
    cleanup()
    os.makedirs(TEST_DIR, exist_ok=True)

    run_cmd("sudo ip netns add wdtt-cln-ns")
    run_cmd("sudo ip link add veth-cln-host type veth peer name veth-cln-cl")
    run_cmd("sudo ip link set veth-cln-cl netns wdtt-cln-ns")
    run_cmd("sudo ip addr add 192.168.130.1/24 dev veth-cln-host")
    run_cmd("sudo ip link set veth-cln-host up")
    run_cmd("sudo ip -n wdtt-cln-ns addr add 192.168.130.2/24 dev veth-cln-cl")
    run_cmd("sudo ip -n wdtt-cln-ns link set veth-cln-cl up")
    run_cmd("sudo ip -n wdtt-cln-ns link set lo up")
    run_cmd("sudo iptables -I INPUT 1 -i veth-cln-host -j ACCEPT")

    # Turnserver
    turn_cmd = [
        "taskset", "-c", CPU_COTURN,
        "turnserver", "-a", "-o", "-v",
        "-u", f"{TURN_USER}:{TURN_PASS}",
        "-r", TURN_REALM, "-p", str(TURN_PORT),
        "-L", "192.168.130.1", "-E", "192.168.130.1",
        "--min-port", "49550", "--max-port", "49580",
        "--no-tls", "--no-stdout-log",
    ]
    turn_proc = subprocess.Popen(turn_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs.append(turn_proc)
    time.sleep(0.5)

    # WireGuard
    server_priv = run_cmd("wg genkey").stdout.strip()
    server_pub = run_cmd(f"echo '{server_priv}' | wg pubkey").stdout.strip()
    client_priv = run_cmd("wg genkey").stdout.strip()
    client_pub = run_cmd(f"echo '{client_priv}' | wg pubkey").stdout.strip()

    srv_key = os.path.join(TEST_DIR, "srv.key")
    cl_key = os.path.join(TEST_DIR, "cl.key")
    with open(srv_key, "w") as f: f.write(server_priv)
    with open(cl_key, "w") as f: f.write(client_priv)

    run_cmd("sudo ip link add wg-cln-srv type wireguard")
    run_cmd(f"sudo wg set wg-cln-srv listen-port 51880 private-key {srv_key} peer {client_pub} allowed-ips 10.88.88.2/32")
    run_cmd("sudo ip addr add 10.88.88.1/24 dev wg-cln-srv")
    run_cmd("sudo ip link set wg-cln-srv up")
    run_cmd("sudo iptables -I INPUT 1 -i wg-cln-srv -j ACCEPT")

    run_cmd("sudo ip -n wdtt-cln-ns link add wg-cln-cl type wireguard")
    run_cmd(f"sudo ip netns exec wdtt-cln-ns wg set wg-cln-cl listen-port 51881 private-key {cl_key} peer {server_pub} allowed-ips 10.88.88.1/32 endpoint 127.0.0.1:51882")
    run_cmd("sudo ip -n wdtt-cln-ns addr add 10.88.88.2/24 dev wg-cln-cl")
    run_cmd("sudo ip -n wdtt-cln-ns link set wg-cln-cl up")

    # wdtt-server
    relayed_file = os.path.join(TEST_DIR, "relayed.txt")
    server_cmd = [
        "taskset", "-c", CPU_SERVER,
        "target/profiling/wdtt-server",
        "--turn-server", f"192.168.130.1:{TURN_PORT}",
        "--turn-user", TURN_USER, "--turn-pass", TURN_PASS, "--turn-realm", TURN_REALM,
        "--wg-endpoint", "127.0.0.1:51880", "--psk", PSK,
        "--relayed-addr-file", relayed_file,
        "--runtime", "multi_thread", "--workers", "2",
        "--coalesce-ms", str(coalesce_ms),
    ]
    server_proc = subprocess.Popen(server_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs.append(server_proc)

    for _ in range(50):
        if os.path.exists(relayed_file) and os.path.getsize(relayed_file) > 0:
            break
        time.sleep(0.1)

    with open(relayed_file) as f:
        server_relayed_addr = f.read().strip()

    # wdttd
    client_cmd = [
        "sudo", "ip", "netns", "exec", "wdtt-cln-ns",
        "taskset", "-c", CPU_CLIENT,
        "target/profiling/wdttd",
        "--turn-server", f"192.168.130.1:{TURN_PORT}",
        "--turn-user", TURN_USER, "--turn-pass", TURN_PASS, "--turn-realm", TURN_REALM,
        "--server-relayed", server_relayed_addr,
        "--wg-listen", "127.0.0.1:51882", "--psk", PSK,
        "--runtime", "current_thread",
        "--coalesce-ms", str(coalesce_ms),
    ]
    client_proc = subprocess.Popen(client_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs.append(client_proc)
    time.sleep(1.0)

    run_cmd("sudo ip netns exec wdtt-cln-ns ping -c 2 -W 1 10.88.88.1")

def measure_rtt(coalesce_ms, run_idx):
    setup_env(coalesce_ms=coalesce_ms)

    # Start iperf3 server
    iperf_s = subprocess.Popen(
        ["taskset", "-c", CPU_IPERF_S, "iperf3", "-s", "-B", "10.88.88.1", "-p", "5209"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    procs.append(iperf_s)
    time.sleep(0.3)

    # Start 50 Mbps UDP load in background (5 seconds)
    iperf_c = subprocess.Popen(
        ["sudo", "ip", "netns", "exec", "wdtt-cln-ns", "taskset", "-c", CPU_IPERF_C,
         "iperf3", "-c", "10.88.88.1", "-p", "5209", "-u", "-b", "50M", "-l", "1200", "-t", "5"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(0.5)

    # Concurrently send 80 pings with 50ms interval (~4 seconds)
    ping_res = run_cmd("sudo ip netns exec wdtt-cln-ns ping -c 80 -i 0.05 10.88.88.1", check=False)
    iperf_c.wait()
    cleanup()

    # Parse individual ping RTTs
    rtts = []
    for line in ping_res.stdout.splitlines():
        m = re.search(r'time=([\d\.]+)\s*ms', line)
        if m:
            rtts.append(float(m.group(1)))

    if not rtts:
        return None

    rtts = np.array(rtts)
    return {
        "coalesce_ms": coalesce_ms,
        "run": run_idx,
        "count": len(rtts),
        "rtt_min_ms": float(np.min(rtts)),
        "rtt_median_ms": float(np.median(rtts)),
        "rtt_p90_ms": float(np.percentile(rtts, 90)),
        "rtt_p95_ms": float(np.percentile(rtts, 95)),
        "rtt_p99_ms": float(np.percentile(rtts, 99)),
        "rtt_max_ms": float(np.max(rtts)),
        "rtt_mean_ms": float(np.mean(rtts)),
        "rtt_std_ms": float(np.std(rtts)),
    }

def main():
    print("=== RTT P99 UNDER LOAD (UDP @ 50M LOAD, 80 PROBES/RUN, n=5 INTERLEAVED) ===")
    run_cmd("sudo cpupower frequency-set -g performance > /dev/null 2>&1 || true")

    modes = [0, 1, 2]
    results = {m: [] for m in modes}

    try:
        for i in range(1, 6):
            for m in modes:
                print(f"Running run {i}/5 for coalesce_ms={m}...")
                res = measure_rtt(m, i)
                if res:
                    results[m].append(res)
                    print(f"  [coalesce={m}ms #{i}] median={res['rtt_median_ms']:.2f}ms | p90={res['rtt_p90_ms']:.2f}ms | p99={res['rtt_p99_ms']:.2f}ms | max={res['rtt_max_ms']:.2f}ms (std={res['rtt_std_ms']:.2f})")
                time.sleep(0.5)

        print("\n" + "="*80)
        print("  RTT P99 UNDER LOAD SUMMARY (n=5)")
        print("="*80)

        summary = {}
        for m in modes:
            meds = [r['rtt_median_ms'] for r in results[m]]
            p90s = [r['rtt_p90_ms'] for r in results[m]]
            p95s = [r['rtt_p95_ms'] for r in results[m]]
            p99s = [r['rtt_p99_ms'] for r in results[m]]
            maxs = [r['rtt_max_ms'] for r in results[m]]

            summary[f"coalesce_{m}ms"] = {
                "median_ms": {"min": np.min(meds), "median": np.median(meds), "max": np.max(meds)},
                "p90_ms": {"min": np.min(p90s), "median": np.median(p90s), "max": np.max(p90s)},
                "p95_ms": {"min": np.min(p95s), "median": np.median(p95s), "max": np.max(p95s)},
                "p99_ms": {"min": np.min(p99s), "median": np.median(p99s), "max": np.max(p99s)},
                "max_ms": {"min": np.min(maxs), "median": np.median(maxs), "max": np.max(maxs)},
            }

            print(f"\n--- COALESCE {m} MS ---")
            print(f"  Median RTT : median={np.median(meds):.2f} ms (min={np.min(meds):.2f}, max={np.max(meds):.2f})")
            print(f"  p90 RTT    : median={np.median(p90s):.2f} ms")
            print(f"  p95 RTT    : median={np.median(p95s):.2f} ms")
            print(f"  p99 RTT    : median={np.median(p99s):.2f} ms (min={np.min(p99s):.2f}, max={np.max(p99s):.2f})")
            print(f"  Max RTT    : median={np.median(maxs):.2f} ms (min={np.min(maxs):.2f}, max={np.max(maxs):.2f})")

        with open("docs/rtt_p99_load_results.json", "w") as f:
            json.dump({"raw": results, "summary": summary}, f, indent=2)
        print("\nWrote results to docs/rtt_p99_load_results.json")

    finally:
        cleanup()

if __name__ == "__main__":
    main()
