#!/usr/bin/env python3
"""
Clean 10s TCP Benchmark Runner for WDTT v2 (Stage 4.1).
- Enforces taskset CPU pinning (P-cores for daemons, E-cores for iperf3)
- Measures: iperf3 (throughput, retransmits), pps, CPU (pidstat -t on server, client, coturn)
- Measures: socket memory drops (ss -u -a -m), link drops (veth), nstat
- Optional low-overhead PMU sampling via perf record -F 99
- ZERO strace or ptrace interference
"""

import os
import sys
import time
import json
import shutil
import signal
import argparse
import subprocess

TEST_DIR = "/tmp/wdtt_clean_bench"
TURN_PORT = 34790
TURN_USER = "cleanuser"
TURN_PASS = "cleanpass"
TURN_REALM = "wdtt-clean"
PSK = "stage4cleanbenchmarksecret2026v2"

# CPU Core Pinning Map (Honor MagicBook Intel Core 5 220H)
# P-cores: Core 0 (0,1), Core 1 (2,3), Core 2 (4,5), Core 3 (6,7)
# E-cores: Core 4 (8), Core 5 (9), Core 6 (10), Core 7 (11)
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

    run_cmd("sudo iptables -D INPUT -i veth-cln-host -j ACCEPT 2>/dev/null || true", check=False)
    run_cmd("sudo iptables -D INPUT -i wg-cln-srv -j ACCEPT 2>/dev/null || true", check=False)
    run_cmd("sudo pkill -9 -f 'target/profiling/wdtt' 2>/dev/null || true", check=False)
    run_cmd("sudo pkill -9 -f 'turnserver.*34790' 2>/dev/null || true", check=False)
    run_cmd("sudo ip link del wg-cln-srv 2>/dev/null || true", check=False)
    run_cmd("sudo ip link del veth-cln-host 2>/dev/null || true", check=False)
    run_cmd("sudo ip netns del wdtt-cln-ns 2>/dev/null || true", check=False)
    shutil.rmtree(TEST_DIR, ignore_errors=True)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--disable-sock-tune", action="store_true", help="Do not tune socket buffers (use kernel default ~208 KB)")
    parser.add_argument("--enable-perf", action="store_true", help="Run low-overhead perf record -F 99")
    parser.add_argument("--duration", type=int, default=10, help="Test duration in seconds")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, lambda s, f: (cleanup(), sys.exit(1)))
    signal.signal(signal.SIGTERM, lambda s, f: (cleanup(), sys.exit(1)))

    cleanup()
    os.makedirs(TEST_DIR, exist_ok=True)

    try:
        res = run_benchmark(disable_sock_tune=args.disable_sock_tune, enable_perf=args.enable_perf, duration=args.duration)
        print("\n--- BENCHMARK RESULT JSON ---")
        print(json.dumps(res, indent=2))
    finally:
        cleanup()

def run_benchmark(disable_sock_tune=False, enable_perf=False, duration=10):
    print(f"\n=======================================================")
    print(f"  RUNNING BENCHMARK (disable_sock_tune={disable_sock_tune}, duration={duration}s)")
    print(f"=======================================================\n")

    # Step 1: netns + veth
    run_cmd("sudo ip netns add wdtt-cln-ns")
    run_cmd("sudo ip link add veth-cln-host type veth peer name veth-cln-cl")
    run_cmd("sudo ip link set veth-cln-cl netns wdtt-cln-ns")
    run_cmd("sudo ip addr add 192.168.130.1/24 dev veth-cln-host")
    run_cmd("sudo ip link set veth-cln-host up")
    run_cmd("sudo ip -n wdtt-cln-ns addr add 192.168.130.2/24 dev veth-cln-cl")
    run_cmd("sudo ip -n wdtt-cln-ns link set veth-cln-cl up")
    run_cmd("sudo ip -n wdtt-cln-ns link set lo up")
    run_cmd("sudo iptables -I INPUT 1 -i veth-cln-host -j ACCEPT")

    # Step 2: Coturn pinned to CPU_COTURN
    turn_cmd = [
        "taskset", "-c", CPU_COTURN,
        "turnserver",
        "-a", "-o", "-v",
        "-u", f"{TURN_USER}:{TURN_PASS}",
        "-r", TURN_REALM,
        "-p", str(TURN_PORT),
        "-L", "192.168.130.1",
        "-E", "192.168.130.1",
        "--min-port", "49460",
        "--max-port", "49500",
        "--no-tls",
        "--no-stdout-log",
    ]
    turn_proc = subprocess.Popen(turn_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs.append(turn_proc)
    time.sleep(1)

    # Step 3: WireGuard interfaces
    server_priv = run_cmd("wg genkey").stdout.strip()
    server_pub = run_cmd(f"echo '{server_priv}' | wg pubkey").stdout.strip()
    client_priv = run_cmd("wg genkey").stdout.strip()
    client_pub = run_cmd(f"echo '{client_priv}' | wg pubkey").stdout.strip()

    srv_key_file = os.path.join(TEST_DIR, "srv.key")
    with open(srv_key_file, "w") as f:
        f.write(server_priv)
    run_cmd("sudo ip link add dev wg-cln-srv type wireguard")
    run_cmd("sudo ip addr add 10.88.88.1/24 dev wg-cln-srv")
    run_cmd(f"sudo wg set wg-cln-srv listen-port 51850 private-key {srv_key_file} peer {client_pub} allowed-ips 10.88.88.2/32")
    run_cmd("sudo ip link set up dev wg-cln-srv")
    run_cmd("sudo iptables -I INPUT 1 -i wg-cln-srv -j ACCEPT")

    cl_key_file = os.path.join(TEST_DIR, "cl.key")
    with open(cl_key_file, "w") as f:
        f.write(client_priv)
    run_cmd("sudo ip -n wdtt-cln-ns link add dev wg-cln-cl type wireguard")
    run_cmd("sudo ip -n wdtt-cln-ns addr add 10.88.88.2/24 dev wg-cln-cl")
    run_cmd(f"sudo ip netns exec wdtt-cln-ns wg set wg-cln-cl private-key {cl_key_file} peer {server_pub} allowed-ips 10.88.88.1/32 endpoint 127.0.0.1:51851")
    run_cmd("sudo ip -n wdtt-cln-ns link set up dev wg-cln-cl")

    # Step 4: wdtt-server pinned to CPU_SERVER
    env = os.environ.copy()
    if disable_sock_tune:
        env["WDTT_DISABLE_SOCK_TUNE"] = "1"
    else:
        env.pop("WDTT_DISABLE_SOCK_TUNE", None)

    relayed_file = os.path.join(TEST_DIR, "relayed.txt")
    server_bin = os.path.abspath("target/profiling/wdtt-server")
    server_cmd = [
        "taskset", "-c", CPU_SERVER,
        server_bin,
        "--turn-server", f"192.168.130.1:{TURN_PORT}",
        "--turn-user", TURN_USER,
        "--turn-pass", TURN_PASS,
        "--turn-realm", TURN_REALM,
        "--wg-endpoint", "127.0.0.1:51850",
        "--psk", PSK,
        "--relayed-addr-file", relayed_file,
    ]
    server_log = open(os.path.join(TEST_DIR, "server.log"), "w")
    server_proc = subprocess.Popen(server_cmd, env=env, stdout=server_log, stderr=server_log)
    procs.append(server_proc)

    for _ in range(50):
        if os.path.exists(relayed_file) and os.path.getsize(relayed_file) > 0:
            break
        time.sleep(0.1)

    with open(relayed_file) as f:
        server_relayed_addr = f.read().strip()
    print(f"    Server allocated relay: {server_relayed_addr}")

    # Step 5: wdttd pinned to CPU_CLIENT
    client_bin = os.path.abspath("target/profiling/wdttd")
    client_cmd = [
        "sudo", "ip", "netns", "exec", "wdtt-cln-ns",
        "taskset", "-c", CPU_CLIENT,
        client_bin,
        "--turn-server", f"192.168.130.1:{TURN_PORT}",
        "--turn-user", TURN_USER,
        "--turn-pass", TURN_PASS,
        "--turn-realm", TURN_REALM,
        "--server-relayed", server_relayed_addr,
        "--wg-listen", "127.0.0.1:51851",
        "--psk", PSK,
    ]
    client_log = open(os.path.join(TEST_DIR, "client.log"), "w")
    client_proc = subprocess.Popen(client_cmd, env=env, stdout=client_log, stderr=client_log)
    procs.append(client_proc)
    time.sleep(1.5)

    # Step 6: Verify ping
    run_cmd("sudo ip netns exec wdtt-cln-ns ping -c 3 -W 2 10.88.88.1")
    print("    Tunnel is UP!")

    # Find client pid inside netns
    cl_pids = run_cmd("pgrep -f target/profiling/wdttd").stdout.strip().split()
    client_pid = cl_pids[-1] if cl_pids else None
    server_pid = str(server_proc.pid)
    turn_pid = str(turn_proc.pid)
    print(f"    PIDs: server={server_pid}, client={client_pid}, coturn={turn_pid}")

    # Reset nstat counters
    run_cmd("nstat -z > /dev/null 2>&1 || true", check=False)

    # Start iperf3 server on CPU_IPERF_S
    iperf_s = subprocess.Popen(
        ["taskset", "-c", CPU_IPERF_S, "iperf3", "-s", "-B", "10.88.88.1", "-p", "5209", "-1"],
        stdout=subprocess.DEVNULL,
    )
    time.sleep(0.5)

    # Start pidstat on all 3 pids
    pid_list = ",".join(filter(None, [server_pid, client_pid, turn_pid]))
    pidstat_proc = subprocess.Popen(
        ["pidstat", "-u", "-t", "-p", pid_list, "1", str(duration)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    # Low-overhead perf record -F 99 (if enabled)
    perf_proc = None
    perf_data = "/tmp/wdtt_perf.data"
    if enable_perf:
        perf_proc = subprocess.Popen(
            ["sudo", "perf", "record", "-F", "99", "-g", "-p", server_pid, "-o", perf_data, "--", "sleep", str(duration - 2)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    # Start iperf3 client on CPU_IPERF_C
    print(f"[+] Starting {duration}s iperf3 TCP stream...")
    iperf_c = subprocess.Popen(
        ["sudo", "ip", "netns", "exec", "wdtt-cln-ns", "taskset", "-c", CPU_IPERF_C, "iperf3", "-c", "10.88.88.1", "-p", "5209", "-t", str(duration), "--json"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    # Mid-flight snapshot of socket buffers
    time.sleep(duration / 2.0)
    ss_mid = run_cmd("ss -u -a -m").stdout

    # Wait for iperf3 and monitors
    stdout, stderr = iperf_c.communicate()
    iperf_s.wait()
    pidstat_out, _ = pidstat_proc.communicate()
    if perf_proc:
        perf_proc.wait()

    # Post-run stats
    nstat_out = run_cmd("nstat -a | grep -E 'UdpRcvbufErrors|UdpInErrors' || true").stdout
    veth_h = run_cmd("ip -s link show dev veth-cln-host").stdout
    veth_c = run_cmd("sudo ip netns exec wdtt-cln-ns ip -s link show dev veth-cln-cl").stdout

    # Parse iperf3 json
    tcp_json = json.loads(stdout)
    bps = tcp_json["end"]["sum_received"]["bits_per_second"]
    mbps = bps / 1_000_000.0
    retrans = tcp_json["end"]["sum_sent"].get("retransmits", 0)

    # Calculate PPS
    pps = int(bps / (1200 * 8))

    # Extract server, client, coturn averages
    def get_proc_cpu(pid):
        for line in pidstat_out.splitlines():
            if ("Average:" in line or "Среднее:" in line) and pid in line:
                parts = line.split()
                try:
                    if parts[3] == "-":
                        return {
                            "usr": float(parts[4].replace(",", ".")),
                            "sys": float(parts[5].replace(",", ".")),
                            "cpu": float(parts[8].replace(",", ".")),
                        }
                    elif len(parts) >= 9:
                        return {
                            "usr": float(parts[4].replace(",", ".")),
                            "sys": float(parts[5].replace(",", ".")),
                            "cpu": float(parts[8].replace(",", ".")),
                        }
                except Exception:
                    pass
        return {"usr": 0.0, "sys": 0.0, "cpu": 0.0}

    print("\n--- RAW PIDSTAT OUTPUT ---")
    print(pidstat_out)

    srv_cpu = get_proc_cpu(server_pid)
    cl_cpu = get_proc_cpu(client_pid) if client_pid else {"usr": 0.0, "sys": 0.0, "cpu": 0.0}
    turn_cpu = get_proc_cpu(turn_pid)

    # CPU-sec / Gbit calculation
    total_gbit = (bps * duration) / 1e9
    srv_cpu_sec = (srv_cpu["cpu"] / 100.0) * duration
    cl_cpu_sec = (cl_cpu["cpu"] / 100.0) * duration
    tot_cpu_sec = srv_cpu_sec + cl_cpu_sec
    cpu_sec_per_gbit = tot_cpu_sec / total_gbit if total_gbit > 0 else 0
    srv_cpu_sec_per_gbit = srv_cpu_sec / total_gbit if total_gbit > 0 else 0

    if enable_perf and os.path.exists(perf_data) and os.path.getsize(perf_data) > 0:
        try:
            print("[+] Generating clean flamegraph...")
            script_out = run_cmd(f"sudo perf script -i {perf_data}").stdout
            c_proc = subprocess.Popen(["inferno-collapse-perf"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            collapsed, _ = c_proc.communicate(input=script_out)
            f_proc = subprocess.Popen(["inferno-flamegraph"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            svg_content, _ = f_proc.communicate(input=collapsed)
            svg_path = os.path.abspath("docs/flamegraph_stage4_1_clean.svg")
            svg_content = svg_content.replace(
                '<text id="title" fill="rgb(0,0,0)" x="50.0000%" y="24.00">Flame Graph</text>',
                '<text id="title" fill="rgb(0,0,0)" x="50.0000%" y="24.00">Flame Graph — стенд netns/veth (чистый профиль wdtt-server 10s TCP, perf -F 99, без strace)</text>'
            )
            with open(svg_path, "w") as f:
                f.write(svg_content)
            print(f"[+] Saved clean flamegraph to {svg_path} ({len(svg_content)} bytes)")
        except Exception as e:
            print(f"[-] Failed to generate flamegraph: {e}")

    return {
        "disable_sock_tune": disable_sock_tune,
        "duration_sec": duration,
        "throughput_mbps": round(mbps, 2),
        "retransmits": retrans,
        "pps": pps,
        "server_cpu_pct": srv_cpu,
        "client_cpu_pct": cl_cpu,
        "coturn_cpu_pct": turn_cpu,
        "srv_cpu_sec_per_gbit": round(srv_cpu_sec_per_gbit, 4),
        "total_cpu_sec_per_gbit": round(cpu_sec_per_gbit, 4),
        "nstat": nstat_out.strip(),
        "veth_host_drops": "0" if "dropped 0" in veth_h or "dropped: 0" in veth_h else "check output",
        "veth_client_drops": "0" if "dropped 0" in veth_c or "dropped: 0" in veth_c else "check output",
    }

if __name__ == "__main__":
    main()
