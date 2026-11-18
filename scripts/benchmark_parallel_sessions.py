#!/usr/bin/env python3
"""
Parallel Sessions 1+ Gbps Benchmark for WDTT v2 (Stage 4.1).
Sets up:
  - Bridge br-bench (192.168.130.1/24)
  - Coturn on 192.168.130.1:34793
  - WireGuard interface wg-srv (10.88.88.1/24) on port 51910 with 2 peers:
      * Client 1: 10.88.88.2/32
      * Client 2: 10.88.88.3/32
  - wdtt-server on host (multi_thread, 2 workers) pinned to P-cores (4, 6)
  - Session 1: Client 1 in netns 'wdtt-cln-ns1', wg IP 10.88.88.2 -> server 10.88.88.1
  - Session 2: Client 2 in netns 'wdtt-cln-ns2', wg IP 10.88.88.3 -> server 10.88.88.1
Measures:
  - Throughput per session and aggregate throughput
  - TCP Retransmits per session and total
  - Kernel reordering (nstat TcpExtTCPSACKReorder)
  - CPU utilization of server worker threads (verifying scaling across workers)
"""

import json
import os
import re
import shutil
import subprocess
import time

TEST_DIR = "/tmp/wdtt_multi_bench"
TURN_PORT = 34793
TURN_USER = "benchuser"
TURN_PASS = "benchpass"
TURN_REALM = "wdtt-bench"
PSK = "parallelbenchsecretkey2026version2"

# Pinning: Server gets 2 threads on P-core (4,6), Coturn on 2, Client 1 on 0, Client 2 on 1, Iperf on E-cores
CPU_COTURN = "2"
CPU_SERVER = "4,6"
CPU_CLN1   = "0"
CPU_CLN2   = "1"
CPU_IPERF_S1 = "8"
CPU_IPERF_S2 = "9"
CPU_IPERF_C1 = "10"
CPU_IPERF_C2 = "11"

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

    run_cmd("sudo iptables -D INPUT -i br-bench -j ACCEPT 2>/dev/null || true", check=False)
    run_cmd("sudo iptables -D INPUT -i wg-srv -j ACCEPT 2>/dev/null || true", check=False)
    run_cmd("sudo pkill -9 -f 'target/profiling/wdtt' 2>/dev/null || true", check=False)
    run_cmd("sudo pkill -9 -f 'iperf3' 2>/dev/null || true", check=False)
    run_cmd("sudo pkill -9 -f 'turnserver.*34793' 2>/dev/null || true", check=False)
    run_cmd("sudo ip link del wg-srv 2>/dev/null || true", check=False)
    run_cmd("sudo ip link del veth-cln1-host 2>/dev/null || true", check=False)
    run_cmd("sudo ip link del veth-cln2-host 2>/dev/null || true", check=False)
    run_cmd("sudo ip link del br-bench 2>/dev/null || true", check=False)
    run_cmd("sudo ip netns del wdtt-cln-ns1 2>/dev/null || true", check=False)
    run_cmd("sudo ip netns del wdtt-cln-ns2 2>/dev/null || true", check=False)
    shutil.rmtree(TEST_DIR, ignore_errors=True)

def setup_parallel_env():
    cleanup()
    os.makedirs(TEST_DIR, exist_ok=True)

    # 1. Bridge
    run_cmd("sudo ip link add br-bench type bridge")
    run_cmd("sudo ip addr add 192.168.130.1/24 dev br-bench")
    run_cmd("sudo ip link set br-bench up")
    run_cmd("sudo iptables -I INPUT 1 -i br-bench -j ACCEPT")

    # 2. Netns 1
    run_cmd("sudo ip netns add wdtt-cln-ns1")
    run_cmd("sudo ip link add veth-cln1-host type veth peer name veth-cln1-cl")
    run_cmd("sudo ip link set veth-cln1-host master br-bench")
    run_cmd("sudo ip link set veth-cln1-host up")
    run_cmd("sudo ip link set veth-cln1-cl netns wdtt-cln-ns1")
    run_cmd("sudo ip -n wdtt-cln-ns1 addr add 192.168.130.2/24 dev veth-cln1-cl")
    run_cmd("sudo ip -n wdtt-cln-ns1 link set veth-cln1-cl up")
    run_cmd("sudo ip -n wdtt-cln-ns1 link set lo up")

    # 3. Netns 2
    run_cmd("sudo ip netns add wdtt-cln-ns2")
    run_cmd("sudo ip link add veth-cln2-host type veth peer name veth-cln2-cl")
    run_cmd("sudo ip link set veth-cln2-host master br-bench")
    run_cmd("sudo ip link set veth-cln2-host up")
    run_cmd("sudo ip link set veth-cln2-cl netns wdtt-cln-ns2")
    run_cmd("sudo ip -n wdtt-cln-ns2 addr add 192.168.130.3/24 dev veth-cln2-cl")
    run_cmd("sudo ip -n wdtt-cln-ns2 link set veth-cln2-cl up")
    run_cmd("sudo ip -n wdtt-cln-ns2 link set lo up")

    # 4. Coturn listening on 192.168.130.1
    turn_cmd = [
        "taskset", "-c", CPU_COTURN,
        "turnserver", "-a", "-o", "-v",
        "-u", f"{TURN_USER}:{TURN_PASS}",
        "-r", TURN_REALM, "-p", str(TURN_PORT),
        "-L", "192.168.130.1",
        "-E", "192.168.130.1",
        "--min-port", "49600", "--max-port", "49650",
        "--no-tls", "--no-stdout-log",
    ]
    turn_proc = subprocess.Popen(turn_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs.append(turn_proc)
    time.sleep(0.5)

    # 5. WireGuard interface: wg-srv on port 51910 with 2 peers
    srv_priv = run_cmd("wg genkey").stdout.strip()
    srv_pub = run_cmd(f"echo '{srv_priv}' | wg pubkey").stdout.strip()
    cl1_priv = run_cmd("wg genkey").stdout.strip()
    cl1_pub = run_cmd(f"echo '{cl1_priv}' | wg pubkey").stdout.strip()
    cl2_priv = run_cmd("wg genkey").stdout.strip()
    cl2_pub = run_cmd(f"echo '{cl2_priv}' | wg pubkey").stdout.strip()

    k_s = os.path.join(TEST_DIR, "srv.key")
    k_c1 = os.path.join(TEST_DIR, "cl1.key")
    k_c2 = os.path.join(TEST_DIR, "cl2.key")
    with open(k_s, "w") as f: f.write(srv_priv)
    with open(k_c1, "w") as f: f.write(cl1_priv)
    with open(k_c2, "w") as f: f.write(cl2_priv)

    run_cmd("sudo ip link add wg-srv type wireguard")
    run_cmd(f"sudo wg set wg-srv listen-port 51910 private-key {k_s} "
            f"peer {cl1_pub} allowed-ips 10.88.88.2/32 "
            f"peer {cl2_pub} allowed-ips 10.88.88.3/32")
    run_cmd("sudo ip addr add 10.88.88.1/24 dev wg-srv")
    run_cmd("sudo ip link set wg-srv up")
    run_cmd("sudo iptables -I INPUT 1 -i wg-srv -j ACCEPT")

    # Client 1 in wdtt-cln-ns1
    run_cmd("sudo ip -n wdtt-cln-ns1 link add wg-cl1 type wireguard")
    run_cmd(f"sudo ip netns exec wdtt-cln-ns1 wg set wg-cl1 listen-port 51911 private-key {k_c1} peer {srv_pub} allowed-ips 10.88.88.1/32 endpoint 127.0.0.1:51912")
    run_cmd("sudo ip -n wdtt-cln-ns1 addr add 10.88.88.2/24 dev wg-cl1")
    run_cmd("sudo ip -n wdtt-cln-ns1 link set wg-cl1 up")

    # Client 2 in wdtt-cln-ns2
    run_cmd("sudo ip -n wdtt-cln-ns2 link add wg-cl2 type wireguard")
    run_cmd(f"sudo ip netns exec wdtt-cln-ns2 wg set wg-cl2 listen-port 51921 private-key {k_c2} peer {srv_pub} allowed-ips 10.88.88.1/32 endpoint 127.0.0.1:51922")
    run_cmd("sudo ip -n wdtt-cln-ns2 addr add 10.88.88.3/24 dev wg-cl2")
    run_cmd("sudo ip -n wdtt-cln-ns2 link set wg-cl2 up")

    # 6. Start wdtt-server pinned to CPU_SERVER (cores 4,6), multi_thread(2)
    relayed_file = os.path.join(TEST_DIR, "relayed.txt")
    server_cmd = [
        "taskset", "-c", CPU_SERVER,
        "target/profiling/wdtt-server",
        "--turn-server", f"192.168.130.1:{TURN_PORT}",
        "--turn-user", TURN_USER, "--turn-pass", TURN_PASS, "--turn-realm", TURN_REALM,
        "--wg-endpoint", "127.0.0.1:51910",
        "--psk", PSK,
        "--relayed-addr-file", relayed_file,
        "--runtime", "multi_thread", "--workers", "2",
    ]
    server_log = open(os.path.join(TEST_DIR, "server.log"), "w")
    server_proc = subprocess.Popen(server_cmd, stdout=server_log, stderr=server_log)
    procs.append(server_proc)

    for _ in range(50):
        if os.path.exists(relayed_file) and os.path.getsize(relayed_file) > 0:
            break
        time.sleep(0.1)

    with open(relayed_file) as f:
        server_relayed_addr = f.read().strip()
    print(f"    Server allocated relay: {server_relayed_addr}")

    # 7. Start Client 1 daemon in wdtt-cln-ns1
    cl1_cmd = [
        "sudo", "ip", "netns", "exec", "wdtt-cln-ns1",
        "taskset", "-c", CPU_CLN1,
        "target/profiling/wdttd",
        "--turn-server", f"192.168.130.1:{TURN_PORT}",
        "--turn-user", TURN_USER, "--turn-pass", TURN_PASS, "--turn-realm", TURN_REALM,
        "--server-relayed", server_relayed_addr,
        "--wg-listen", "127.0.0.1:51912", "--psk", PSK,
        "--runtime", "current_thread",
    ]
    cl1_log = open(os.path.join(TEST_DIR, "cl1.log"), "w")
    cl1_proc = subprocess.Popen(cl1_cmd, stdout=cl1_log, stderr=cl1_log)
    procs.append(cl1_proc)

    # 8. Start Client 2 daemon in wdtt-cln-ns2
    cl2_cmd = [
        "sudo", "ip", "netns", "exec", "wdtt-cln-ns2",
        "taskset", "-c", CPU_CLN2,
        "target/profiling/wdttd",
        "--turn-server", f"192.168.130.1:{TURN_PORT}",
        "--turn-user", TURN_USER, "--turn-pass", TURN_PASS, "--turn-realm", TURN_REALM,
        "--server-relayed", server_relayed_addr,
        "--wg-listen", "127.0.0.1:51922", "--psk", PSK,
        "--runtime", "current_thread",
    ]
    cl2_log = open(os.path.join(TEST_DIR, "cl2.log"), "w")
    cl2_proc = subprocess.Popen(cl2_cmd, stdout=cl2_log, stderr=cl2_log)
    procs.append(cl2_proc)
    time.sleep(2.0)

    # Verify both tunnels
    run_cmd("sudo ip netns exec wdtt-cln-ns1 ping -c 2 -W 1 10.88.88.1")
    print("    Session 1 is UP (10.88.88.2 -> 10.88.88.1)!")
    run_cmd("sudo ip netns exec wdtt-cln-ns2 ping -c 2 -W 1 10.88.88.1")
    print("    Session 2 is UP (10.88.88.3 -> 10.88.88.1)!")

    return server_proc.pid

def main():
    print("=================================================================")
    print("  PARALLEL SESSIONS BENCHMARK (2 CLIENT SESSIONS ON MULTI_THREAD)")
    print("=================================================================")
    run_cmd("sudo cpupower frequency-set -g performance > /dev/null 2>&1 || true")

    try:
        srv_pid = setup_parallel_env()
        duration = 10

        # Start iperf3 servers on host
        iperf_s1 = subprocess.Popen(
            ["taskset", "-c", CPU_IPERF_S1, "iperf3", "-s", "-B", "10.88.88.1", "-p", "5201", "-1"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        iperf_s2 = subprocess.Popen(
            ["taskset", "-c", CPU_IPERF_S2, "iperf3", "-s", "-B", "10.88.88.1", "-p", "5202", "-1"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        procs.append(iperf_s1)
        procs.append(iperf_s2)
        time.sleep(0.5)

        # Baseline nstat
        run_cmd("nstat -z > /dev/null 2>&1 || true")

        # Start pidstat on server
        pidstat_proc = subprocess.Popen(
            ["pidstat", "-u", "-t", "-p", str(srv_pid), "1", str(duration)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        # Start iperf3 clients in parallel
        print(f"[+] Launching 2 simultaneous TCP iperf3 streams for {duration}s...")
        c1_proc = subprocess.Popen(
            ["sudo", "ip", "netns", "exec", "wdtt-cln-ns1", "taskset", "-c", CPU_IPERF_C1,
             "iperf3", "-c", "10.88.88.1", "-p", "5201", "-t", str(duration), "-J"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        c2_proc = subprocess.Popen(
            ["sudo", "ip", "netns", "exec", "wdtt-cln-ns2", "taskset", "-c", CPU_IPERF_C2,
             "iperf3", "-c", "10.88.88.1", "-p", "5202", "-t", str(duration), "-J"],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        c1_out, _ = c1_proc.communicate()
        c2_out, _ = c2_proc.communicate()
        pidstat_out, _ = pidstat_proc.communicate()

        nstat_out = run_cmd("nstat").stdout

        d1 = json.loads(c1_out)
        d2 = json.loads(c2_out)

        s1_mbps = d1["end"]["sum_received"]["bits_per_second"] / 1e6
        s1_retr = d1["end"]["sum_sent"].get("retransmits", 0)
        s2_mbps = d2["end"]["sum_received"]["bits_per_second"] / 1e6
        s2_retr = d2["end"]["sum_sent"].get("retransmits", 0)

        total_mbps = s1_mbps + s2_mbps
        total_retr = s1_retr + s2_retr

        # Parse nstat reorders
        reorder_match = re.search(r"TcpExtTCPSACKReorder\s+(\d+)", nstat_out)
        reorders = int(reorder_match.group(1)) if reorder_match else 0
        lost_retr_match = re.search(r"TcpExtTCPLostRetransmit\s+(\d+)", nstat_out)
        lost_retr = int(lost_retr_match.group(1)) if lost_retr_match else 0

        print("\n" + "="*80)
        print("  PARALLEL SESSIONS BENCHMARK RESULT")
        print("="*80)
        print(f"Session 1: {s1_mbps:.2f} Mbps | Retransmits: {s1_retr}")
        print(f"Session 2: {s2_mbps:.2f} Mbps | Retransmits: {s2_retr}")
        print(f"TOTAL AGGREGATE THROUGHPUT: {total_mbps:.2f} Mbps ({total_mbps/1000.0:.2f} Gbps)")
        print(f"TOTAL RETRANSMITS         : {total_retr}")
        print(f"TcpExtTCPSACKReorder      : {reorders}")
        print(f"TcpExtTCPLostRetransmit   : {lost_retr}")
        print("\nServer Worker Threads CPU (pidstat):")
        for line in pidstat_out.strip().splitlines():
            if "Average:" in line or "target/profiling/wdtt" in line or "tokio-runtime-w" in line:
                print("  " + line)

        res = {
            "session_1_mbps": round(s1_mbps, 2),
            "session_1_retransmits": s1_retr,
            "session_2_mbps": round(s2_mbps, 2),
            "session_2_retransmits": s2_retr,
            "total_throughput_mbps": round(total_mbps, 2),
            "total_throughput_gbps": round(total_mbps / 1000.0, 3),
            "total_retransmits": total_retr,
            "tcpext_reorders": reorders,
            "tcpext_lost_retransmits": lost_retr,
            "pidstat": pidstat_out,
        }

        with open("docs/parallel_sessions_results.json", "w") as f:
            json.dump(res, f, indent=2)
        print("\nWrote results to docs/parallel_sessions_results.json")

    except Exception:
        print("\n--- SERVER LOG ---")
        if os.path.exists(f"{TEST_DIR}/server.log"):
            with open(f"{TEST_DIR}/server.log") as f: print(f.read())
        print("\n--- CLIENT 1 LOG ---")
        if os.path.exists(f"{TEST_DIR}/cl1.log"):
            with open(f"{TEST_DIR}/cl1.log") as f: print(f.read())
        print("\n--- CLIENT 2 LOG ---")
        if os.path.exists(f"{TEST_DIR}/cl2.log"):
            with open(f"{TEST_DIR}/cl2.log") as f: print(f.read())
        cleanup()
        raise
    finally:
        cleanup()

if __name__ == "__main__":
    main()
