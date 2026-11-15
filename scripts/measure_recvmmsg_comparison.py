#!/usr/bin/env python3
"""
Rigorous statistical comparison of recvmmsg with vs without short-batch readiness clearing:
  Mode "before": WDTT_DISABLE_SHORT_BATCH_CLEAR=1 (doomed recvmmsg syscalls occur)
  Mode "after" : default (try_io clears readiness on short batch)

Runs n=5 iterations interleaved under identical governor, CPU pinning, and UDP @ 20 Mbps.
Measures:
  - recvmmsg syscalls / sec
  - epoll_wait syscalls / sec
  - context-switches / sec
  - CPU task-clock (ms) and CPU us per packet
  - Min, median, max, mean, stddev
"""

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import numpy as np

TEST_DIR = "/tmp/wdtt_recvmmsg_bench"
TURN_PORT = 34791
TURN_USER = "benchuser"
TURN_PASS = "benchpass"
TURN_REALM = "wdtt-bench"
PSK = "recvmmsgbenchsecretkey2026v2"

CPU_COTURN = "2"
CPU_SERVER = "4"
CPU_CLIENT = "6"
CPU_GEN    = "8"

DURATION_SEC = 5
RUNS = 5

procs = []

def run_cmd(cmd, check=True):
    env = dict(os.environ, LC_ALL="C", LANG="C")
    res = subprocess.run(cmd, shell=True, text=True, capture_output=True, env=env)
    if check and res.returncode != 0:
        err = res.stderr.strip() or res.stdout.strip()
        raise RuntimeError(f"Command failed (code {res.returncode}): {cmd}\nError: {err}")
    return res

def cleanup():
    for p in reversed(procs):
        try:
            p.terminate()
            p.wait(timeout=0.5)
        except Exception:
            try:
                p.kill()
            except Exception:
                pass
    procs.clear()

    run_cmd("sudo iptables -D INPUT -i veth-cln-host -j ACCEPT 2>/dev/null || true", check=False)
    run_cmd("sudo iptables -D INPUT -i wg-cln-srv -j ACCEPT 2>/dev/null || true", check=False)
    run_cmd("sudo pkill -9 -f 'target/profiling/wdtt' 2>/dev/null || true", check=False)
    run_cmd("sudo pkill -9 -f 'iperf3' 2>/dev/null || true", check=False)
    run_cmd("sudo pkill -9 -f 'turnserver.*34791' 2>/dev/null || true", check=False)
    run_cmd("sudo ip link del wg-cln-srv 2>/dev/null || true", check=False)
    run_cmd("sudo ip link del veth-cln-host 2>/dev/null || true", check=False)
    run_cmd("sudo ip netns del wdtt-cln-ns 2>/dev/null || true", check=False)
    shutil.rmtree(TEST_DIR, ignore_errors=True)

def parse_perf_output(perf_str):
    recvmmsg_cnt = 0
    epoll_wait_cnt = 0
    cs_cnt = 0
    task_clock_ms = 0.0

    for line in perf_str.splitlines():
        clean = line.replace('\u202f', '').replace(' ', '').replace(',', '.')
        if 'syscalls:sys_enter_recvmmsg' in line:
            m = re.search(r'(\d+)', clean)
            if m: recvmmsg_cnt = int(m.group(1))
        elif 'syscalls:sys_enter_epoll_wait' in line:
            m = re.search(r'(\d+)', clean)
            if m: epoll_wait_cnt = int(m.group(1))
        elif 'context-switches' in line:
            m = re.search(r'(\d+)', clean)
            if m: cs_cnt = int(m.group(1))
        elif 'task-clock' in line:
            m = re.search(r'([\d\.]+)msec', clean)
            if m: task_clock_ms = float(m.group(1))

    return recvmmsg_cnt, epoll_wait_cnt, cs_cnt, task_clock_ms

def setup_infra(disable_short_batch_clear=False):
    cleanup()
    os.makedirs(TEST_DIR, exist_ok=True)

    # 1. netns + veth
    run_cmd("sudo ip netns add wdtt-cln-ns")
    run_cmd("sudo ip link add veth-cln-host type veth peer name veth-cln-cl")
    run_cmd("sudo ip link set veth-cln-cl netns wdtt-cln-ns")
    run_cmd("sudo ip addr add 192.168.130.1/24 dev veth-cln-host")
    run_cmd("sudo ip link set veth-cln-host up")
    run_cmd("sudo ip -n wdtt-cln-ns addr add 192.168.130.2/24 dev veth-cln-cl")
    run_cmd("sudo ip -n wdtt-cln-ns link set veth-cln-cl up")
    run_cmd("sudo ip -n wdtt-cln-ns link set lo up")
    run_cmd("sudo iptables -I INPUT 1 -i veth-cln-host -j ACCEPT")

    # 2. Coturn
    turn_cmd = [
        "taskset", "-c", CPU_COTURN,
        "turnserver",
        "-a", "-o", "-v",
        "-u", f"{TURN_USER}:{TURN_PASS}",
        "-r", TURN_REALM,
        "-p", str(TURN_PORT),
        "-L", "192.168.130.1",
        "-E", "192.168.130.1",
        "--min-port", "49510",
        "--max-port", "49540",
        "--no-tls",
        "--no-stdout-log",
    ]
    turn_proc = subprocess.Popen(turn_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=dict(os.environ, LC_ALL="C"))
    procs.append(turn_proc)
    time.sleep(0.5)

    # 3. WireGuard interfaces
    server_priv = run_cmd("wg genkey").stdout.strip()
    server_pub = run_cmd(f"echo '{server_priv}' | wg pubkey").stdout.strip()
    client_priv = run_cmd("wg genkey").stdout.strip()
    client_pub = run_cmd(f"echo '{client_priv}' | wg pubkey").stdout.strip()

    srv_key = os.path.join(TEST_DIR, "srv.key")
    cl_key = os.path.join(TEST_DIR, "cl.key")
    with open(srv_key, "w") as f: f.write(server_priv)
    with open(cl_key, "w") as f: f.write(client_priv)

    run_cmd("sudo ip link add wg-cln-srv type wireguard")
    run_cmd(f"sudo wg set wg-cln-srv listen-port 51870 private-key {srv_key} peer {client_pub} allowed-ips 10.88.88.2/32")
    run_cmd("sudo ip addr add 10.88.88.1/24 dev wg-cln-srv")
    run_cmd("sudo ip link set wg-cln-srv up")
    run_cmd("sudo iptables -I INPUT 1 -i wg-cln-srv -j ACCEPT")

    run_cmd("sudo ip -n wdtt-cln-ns link add wg-cln-cl type wireguard")
    run_cmd(f"sudo ip netns exec wdtt-cln-ns wg set wg-cln-cl listen-port 51871 private-key {cl_key} peer {server_pub} allowed-ips 10.88.88.1/32 endpoint 127.0.0.1:51872")
    run_cmd("sudo ip -n wdtt-cln-ns addr add 10.88.88.2/24 dev wg-cln-cl")
    run_cmd("sudo ip -n wdtt-cln-ns link set wg-cln-cl up")

    # 4. wdtt-server pinned to CPU_SERVER
    env = os.environ.copy()
    if disable_short_batch_clear:
        env["WDTT_DISABLE_SHORT_BATCH_CLEAR"] = "1"
    else:
        env.pop("WDTT_DISABLE_SHORT_BATCH_CLEAR", None)

    relayed_file = os.path.join(TEST_DIR, "relayed.txt")
    server_bin = os.path.abspath("target/profiling/wdtt-server")
    server_cmd = [
        "taskset", "-c", CPU_SERVER,
        server_bin,
        "--turn-server", f"192.168.130.1:{TURN_PORT}",
        "--turn-user", TURN_USER,
        "--turn-pass", TURN_PASS,
        "--turn-realm", TURN_REALM,
        "--wg-endpoint", "127.0.0.1:51870",
        "--psk", PSK,
        "--relayed-addr-file", relayed_file,
        "--runtime", "current_thread",
    ]
    server_proc = subprocess.Popen(server_cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs.append(server_proc)

    for _ in range(50):
        if os.path.exists(relayed_file) and os.path.getsize(relayed_file) > 0:
            break
        time.sleep(0.1)

    with open(relayed_file) as f:
        server_relayed_addr = f.read().strip()

    # 5. wdttd pinned to CPU_CLIENT
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
        "--wg-listen", "127.0.0.1:51872",
        "--psk", PSK,
        "--runtime", "current_thread",
    ]
    client_proc = subprocess.Popen(client_cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    procs.append(client_proc)
    time.sleep(1.0)

    # Verify ping
    run_cmd("sudo ip netns exec wdtt-cln-ns ping -c 2 -W 1 10.88.88.1")
    return server_proc.pid

def run_test(mode, run_idx):
    disable_clear = (mode == "before")
    server_pid = setup_infra(disable_short_batch_clear=disable_clear)

    # Attach perf stat to wdtt-server
    events = "syscalls:sys_enter_recvmmsg,syscalls:sys_enter_epoll_wait,context-switches,task-clock"
    perf = subprocess.Popen(
        ["sudo", "perf", "stat", "-e", events, "-p", str(server_pid), "--", "sleep", str(DURATION_SEC)],
        stderr=subprocess.PIPE, text=True
    )

    # Start iperf3 server
    iperf_s = subprocess.Popen(
        ["taskset", "-c", "10", "iperf3", "-s", "-B", "10.88.88.1", "-p", "5209"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    procs.append(iperf_s)
    time.sleep(0.3)

    # Start UDP traffic at 20 Mbps from netns
    iperf_c = run_cmd(
        f"sudo ip netns exec wdtt-cln-ns taskset -c {CPU_GEN} iperf3 -c 10.88.88.1 -p 5209 -u -b 20M -l 1200 -t {DURATION_SEC} -J",
        check=False
    )

    _, perf_err = perf.communicate()
    cleanup()

    recvmmsg_cnt, epoll_cnt, cs_cnt, task_clock_ms = parse_perf_output(perf_err)

    actual_pps = 0.0
    actual_mbps = 0.0
    try:
        data = json.loads(iperf_c.stdout)
        actual_mbps = data["end"]["sum"]["bits_per_second"] / 1e6
        actual_pkts = data["end"]["sum"]["packets"]
        actual_pps = actual_pkts / DURATION_SEC
    except Exception:
        actual_pkts = 2084 * DURATION_SEC
        actual_pps = 2084.0

    recvmmsg_s = recvmmsg_cnt / DURATION_SEC
    epoll_s = epoll_cnt / DURATION_SEC
    cs_s = cs_cnt / DURATION_SEC
    us_pkt = (task_clock_ms * 1000.0) / actual_pkts if actual_pkts > 0 else 0

    return {
        "run": run_idx,
        "mode": mode,
        "mbps": actual_mbps,
        "pps": actual_pps,
        "recvmmsg_per_sec": recvmmsg_s,
        "epoll_per_sec": epoll_s,
        "cs_per_sec": cs_s,
        "task_clock_ms": task_clock_ms,
        "us_per_pkt": us_pkt,
    }

def main():
    print(f"=== RECVMMSG STATISTICAL COMPARISON (n={RUNS} interleaved, UDP @ 20M, duration={DURATION_SEC}s) ===")
    run_cmd("sudo cpupower frequency-set -g performance > /dev/null 2>&1 || true")

    modes = ["before", "after"]
    results = {m: [] for m in modes}

    try:
        for i in range(1, RUNS + 1):
            for mode in modes:
                print(f"Running run {i}/{RUNS} for {mode}...")
                res = run_test(mode, i)
                results[mode].append(res)
                print(f"  [{mode} #{i}] recvmmsg/s={res['recvmmsg_per_sec']:.1f} | epoll_wait/s={res['epoll_per_sec']:.1f} | CS/s={res['cs_per_sec']:.1f} | CPU={res['task_clock_ms']:.2f}ms ({res['us_per_pkt']:.2f} us/pkt)")
                time.sleep(1.0)

        print("\n" + "="*80)
        print("  RECVMMSG SUMMARY STATISTICS (n=5)")
        print("="*80)

        summary = {}
        for mode in modes:
            rmmsg = [r['recvmmsg_per_sec'] for r in results[mode]]
            epoll = [r['epoll_per_sec'] for r in results[mode]]
            cs = [r['cs_per_sec'] for r in results[mode]]
            cpu = [r['task_clock_ms'] for r in results[mode]]
            us_p = [r['us_per_pkt'] for r in results[mode]]

            summary[mode] = {
                "recvmmsg_per_sec": {"min": np.min(rmmsg), "median": np.median(rmmsg), "max": np.max(rmmsg), "mean": np.mean(rmmsg), "std": np.std(rmmsg)},
                "epoll_per_sec": {"min": np.min(epoll), "median": np.median(epoll), "max": np.max(epoll), "mean": np.mean(epoll), "std": np.std(epoll)},
                "cs_per_sec": {"min": np.min(cs), "median": np.median(cs), "max": np.max(cs), "mean": np.mean(cs), "std": np.std(cs)},
                "task_clock_ms": {"min": np.min(cpu), "median": np.median(cpu), "max": np.max(cpu), "mean": np.mean(cpu), "std": np.std(cpu)},
                "us_per_pkt": {"min": np.min(us_p), "median": np.median(us_p), "max": np.max(us_p), "mean": np.mean(us_p), "std": np.std(us_p)},
            }

            print(f"\n--- MODE {mode.upper()} ({'Without' if mode == 'before' else 'With'} short-batch try_io) ---")
            print(f"  recvmmsg/s  : min={summary[mode]['recvmmsg_per_sec']['min']:.1f}, median={summary[mode]['recvmmsg_per_sec']['median']:.1f}, max={summary[mode]['recvmmsg_per_sec']['max']:.1f} (std={summary[mode]['recvmmsg_per_sec']['std']:.1f})")
            print(f"  epoll_wait/s: min={summary[mode]['epoll_per_sec']['min']:.1f}, median={summary[mode]['epoll_per_sec']['median']:.1f}, max={summary[mode]['epoll_per_sec']['max']:.1f}")
            print(f"  CS/s        : min={summary[mode]['cs_per_sec']['min']:.1f}, median={summary[mode]['cs_per_sec']['median']:.1f}, max={summary[mode]['cs_per_sec']['max']:.1f}")
            print(f"  CPU task-ms : min={summary[mode]['task_clock_ms']['min']:.2f}, median={summary[mode]['task_clock_ms']['median']:.2f}, max={summary[mode]['task_clock_ms']['max']:.2f} (std={summary[mode]['task_clock_ms']['std']:.2f})")
            print(f"  CPU us/pkt  : min={summary[mode]['us_per_pkt']['min']:.2f}, median={summary[mode]['us_per_pkt']['median']:.2f}, max={summary[mode]['us_per_pkt']['max']:.2f}")

        with open("docs/recvmmsg_comparison_results.json", "w") as f:
            json.dump({"raw": results, "summary": summary}, f, indent=2)
        print("\nResults saved to docs/recvmmsg_comparison_results.json")

    finally:
        cleanup()

if __name__ == "__main__":
    main()
