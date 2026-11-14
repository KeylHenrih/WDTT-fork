#!/usr/bin/env python3
"""
Stage 4.1 Profiler and Diagnostic Benchmark Runner.
Collects:
- Per-thread CPU breakdown via pidstat -t
- Per-core CPU breakdown via mpstat -P ALL
- CPU stack profile and Flamegraph via perf record + inferno
- Socket buffer memory state via ss -u -a -m on ALL sockets
- Veth link drop statistics via ip -s link
- Exact PPS and Throughput
"""

import os
import sys
import time
import json
import shutil
import signal
import subprocess

TEST_DIR = "/tmp/wdtt_prof_test"
TURN_PORT = 34789
TURN_USER = "profuser"
TURN_PASS = "profpass"
TURN_REALM = "wdtt-prof"
PSK = "stage4profsecretkey2026wdttv2"

procs = []

def run_cmd(cmd, check=True, capture=True):
    shell = isinstance(cmd, str)
    res = subprocess.run(cmd, shell=shell, text=True, capture_output=capture)
    if check and res.returncode != 0:
        err = res.stderr.strip() or res.stdout.strip()
        raise RuntimeError(f"Command failed (code {res.returncode}): {cmd}\nError: {err}")
    return res

def cleanup():
    print("\n[-] Cleaning up profiling environment...")
    for p in reversed(procs):
        try:
            p.terminate()
            p.wait(timeout=1)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass

    run_cmd("sudo iptables -D INPUT -i veth-prof-host -j ACCEPT 2>/dev/null || true", check=False)
    run_cmd("sudo iptables -D INPUT -i wg-prof-srv -j ACCEPT 2>/dev/null || true", check=False)
    run_cmd("sudo pkill -9 -f 'target/profiling/wdtt' 2>/dev/null || true", check=False)
    run_cmd("sudo pkill -9 -f 'turnserver.*34789' 2>/dev/null || true", check=False)
    run_cmd("sudo ip link del wg-prof-srv 2>/dev/null || true", check=False)
    run_cmd("sudo ip link del veth-prof-host 2>/dev/null || true", check=False)
    run_cmd("sudo ip netns del wdtt-prof-ns 2>/dev/null || true", check=False)
    shutil.rmtree(TEST_DIR, ignore_errors=True)
    print("[-] Cleanup complete.")

def main():
    signal.signal(signal.SIGINT, lambda s, f: (cleanup(), sys.exit(1)))
    signal.signal(signal.SIGTERM, lambda s, f: (cleanup(), sys.exit(1)))

    cleanup()
    os.makedirs(TEST_DIR, exist_ok=True)

    try:
        run_profile()
    finally:
        cleanup()

def run_profile():
    print("[+] Step 1: Creating netns and veth link...")
    run_cmd("sudo ip netns add wdtt-prof-ns")
    run_cmd("sudo ip link add veth-prof-host type veth peer name veth-prof-cl")
    run_cmd("sudo ip link set veth-prof-cl netns wdtt-prof-ns")
    run_cmd("sudo ip addr add 192.168.120.1/24 dev veth-prof-host")
    run_cmd("sudo ip link set veth-prof-host up")
    run_cmd("sudo ip -n wdtt-prof-ns addr add 192.168.120.2/24 dev veth-prof-cl")
    run_cmd("sudo ip -n wdtt-prof-ns link set veth-prof-cl up")
    run_cmd("sudo ip -n wdtt-prof-ns link set lo up")
    run_cmd("sudo iptables -I INPUT 1 -i veth-prof-host -j ACCEPT")

    print("[+] Step 2: Starting Coturn on 192.168.120.1:34789...")
    turn_proc = subprocess.Popen(
        [
            "turnserver",
            "-a", "-o", "-v",
            "-u", f"{TURN_USER}:{TURN_PASS}",
            "-r", TURN_REALM,
            "-p", str(TURN_PORT),
            "-L", "192.168.120.1",
            "-E", "192.168.120.1",
            "--min-port", "49360",
            "--max-port", "49400",
            "--no-tls",
            "--no-stdout-log",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    procs.append(turn_proc)
    time.sleep(1)

    print("[+] Step 3: Configuring WireGuard interfaces...")
    server_priv = run_cmd("wg genkey").stdout.strip()
    server_pub = run_cmd(f"echo '{server_priv}' | wg pubkey").stdout.strip()
    client_priv = run_cmd("wg genkey").stdout.strip()
    client_pub = run_cmd(f"echo '{client_priv}' | wg pubkey").stdout.strip()

    srv_key_file = os.path.join(TEST_DIR, "srv.key")
    with open(srv_key_file, "w") as f:
        f.write(server_priv)
    run_cmd("sudo ip link add dev wg-prof-srv type wireguard")
    run_cmd("sudo ip addr add 10.99.99.1/24 dev wg-prof-srv")
    run_cmd(f"sudo wg set wg-prof-srv listen-port 51840 private-key {srv_key_file} peer {client_pub} allowed-ips 10.99.99.2/32")
    run_cmd("sudo ip link set up dev wg-prof-srv")
    run_cmd("sudo iptables -I INPUT 1 -i wg-prof-srv -j ACCEPT")

    cl_key_file = os.path.join(TEST_DIR, "cl.key")
    with open(cl_key_file, "w") as f:
        f.write(client_priv)
    run_cmd("sudo ip -n wdtt-prof-ns link add dev wg-prof-cl type wireguard")
    run_cmd("sudo ip -n wdtt-prof-ns addr add 10.99.99.2/24 dev wg-prof-cl")
    run_cmd(f"sudo ip netns exec wdtt-prof-ns wg set wg-prof-cl private-key {cl_key_file} peer {server_pub} allowed-ips 10.99.99.1/32 endpoint 127.0.0.1:51841")
    run_cmd("sudo ip -n wdtt-prof-ns link set up dev wg-prof-cl")

    print("[+] Step 4: Starting target/profiling/wdtt-server...")
    relayed_file = os.path.join(TEST_DIR, "relayed.txt")
    server_bin = os.path.abspath("target/profiling/wdtt-server")
    server_cmd = [
        server_bin,
        "--turn-server", f"192.168.120.1:{TURN_PORT}",
        "--turn-user", TURN_USER,
        "--turn-pass", TURN_PASS,
        "--turn-realm", TURN_REALM,
        "--wg-endpoint", "127.0.0.1:51840",
        "--psk", PSK,
        "--relayed-addr-file", relayed_file,
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

    print("[+] Step 5: Starting target/profiling/wdttd...")
    client_bin = os.path.abspath("target/profiling/wdttd")
    client_cmd = [
        "sudo", "ip", "netns", "exec", "wdtt-prof-ns",
        client_bin,
        "--turn-server", f"192.168.120.1:{TURN_PORT}",
        "--turn-user", TURN_USER,
        "--turn-pass", TURN_PASS,
        "--turn-realm", TURN_REALM,
        "--server-relayed", server_relayed_addr,
        "--wg-listen", "127.0.0.1:51841",
        "--psk", PSK,
    ]
    client_log = open(os.path.join(TEST_DIR, "client.log"), "w")
    client_proc = subprocess.Popen(client_cmd, stdout=client_log, stderr=client_log)
    procs.append(client_proc)
    time.sleep(1.5)

    print("[+] Step 6: Verifying tunnel...")
    run_cmd("sudo ip netns exec wdtt-prof-ns ping -c 3 -W 2 10.99.99.1")
    print("    Tunnel is UP!")

    server_pid = server_proc.pid
    print(f"    Server PID: {server_pid}")

    print("\n=======================================================")
    print("       RUNNING 10s TCP STREAM WITH PROFILING")
    print("=======================================================\n")

    # Start iperf3 server
    iperf_s = subprocess.Popen(["iperf3", "-s", "-B", "10.99.99.1", "-p", "5205", "-1"], stdout=subprocess.DEVNULL)
    time.sleep(0.5)

    # Start pidstat in background (1 second intervals, 8 samples)
    pidstat_proc = subprocess.Popen(
        ["pidstat", "-u", "-r", "-t", "-p", str(server_pid), "1", "8"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    # Start mpstat in background (1 second intervals, 8 samples)
    mpstat_proc = subprocess.Popen(
        ["mpstat", "-P", "ALL", "1", "8"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    # Start iperf3 client (10 seconds)
    iperf_c = subprocess.Popen(
        ["sudo", "ip", "netns", "exec", "wdtt-prof-ns", "iperf3", "-c", "10.99.99.1", "-p", "5205", "-t", "10", "--json"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    # Allow 2 seconds for ramp up, then capture perf record for 4 seconds
    time.sleep(2.0)
    perf_data = os.path.join(TEST_DIR, "perf.data")
    print("[+] Capturing perf stack traces on wdtt-server (4s)...")
    run_cmd(f"sudo perf record -F 997 -g -p {server_pid} -o {perf_data} -- sleep 4", check=False)

    # Mid-transfer socket and link snapshot
    print("\n--- Detailed ss -u -a -m snapshot ---")
    ss_out = run_cmd("ss -u -a -m").stdout
    for line in ss_out.splitlines():
        if any(k in line for k in ["51840", "51841", "34789", "skmem"]):
            print(f"    {line}")

    # Wait for iperf to finish
    stdout, stderr = iperf_c.communicate()
    iperf_s.wait()
    pidstat_out, _ = pidstat_proc.communicate()
    mpstat_out, _ = mpstat_proc.communicate()

    # Veth interface packet drops
    print("\n--- Veth interface stats ---")
    veth_h = run_cmd("ip -s link show dev veth-prof-host").stdout
    print("Host veth:\n" + veth_h)
    veth_c = run_cmd("sudo ip netns exec wdtt-prof-ns ip -s link show dev veth-prof-cl").stdout
    print("Client veth:\n" + veth_c)

    # Print pidstat summary
    print("\n--- pidstat -t (Per-Thread Server CPU Breakdown) ---")
    print(pidstat_out)

    # Print mpstat summary (averaged)
    print("\n--- mpstat -P ALL (Per-Core Utilization) ---")
    for line in mpstat_out.splitlines():
        if "Average:" in line:
            print(line)

    # Generate Flamegraph SVG
    if os.path.exists(perf_data) and os.path.getsize(perf_data) > 0:
        print("\n[+] Generating flamegraph SVG...")
        perf_script_out = run_cmd(f"sudo perf script -i {perf_data}").stdout
        collapse_cmd = subprocess.Popen(["inferno-collapse-perf"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        collapsed, _ = collapse_cmd.communicate(input=perf_script_out)

        flamegraph_svg = os.path.abspath("docs/flamegraph_stage4_1.svg")
        flamegraph_cmd = subprocess.Popen(["inferno-flamegraph"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        svg_content, _ = flamegraph_cmd.communicate(input=collapsed)

        with open(flamegraph_svg, "w") as f:
            f.write(svg_content)
        print(f"    Saved flamegraph to {flamegraph_svg} ({len(svg_content)} bytes)")

    # Parse iperf results
    tcp_json = json.loads(stdout)
    bps = tcp_json["end"]["sum_received"]["bits_per_second"]
    mbps = bps / 1_000_000.0
    retrans = tcp_json["end"]["sum_sent"].get("retransmits", 0)
    print(f"\n[+] Final Result: {mbps:.2f} Mbits/sec | Retransmits: {retrans}")

if __name__ == "__main__":
    main()
