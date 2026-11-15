#!/usr/bin/env python3
"""
Benchmark suite for:
1. Baseline cost floor: minimal raw Rust UDP forwarder (recv -> send, no crypto/framing)
   under current_thread and multi_thread(2) at ~2000 pps.
2. Datapath: Tokio runtime comparison: multi_thread(2) vs current_thread on hot path for:
   - UDP @ 20 Mbps (~2084 pps)
   - UDP @ 50 Mbps (~5208 pps)
   - TCP @ 20 Mbps
   Measures: wakeups/context-switches, epoll_wait/recvmmsg/futex syscalls, batch size distribution, CPU us/packet.
3. Idle client daemon (wdttd):
   - Interface down / closed (keepalive disabled)
   - Interface open / idle (powersave keepalive, initial 10s)
   - Interface open / idle (powersave steady state after 60s)
   - Interface open / idle (chaff Opus voice emulation keepalive)
"""

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time

TEST_DIR = "/tmp/wdtt_tokio_idle_bench"
TURN_PORT = 34790
TURN_USER = "benchuser"
TURN_PASS = "benchpass"
TURN_REALM = "wdtt-bench"
PSK = "tokiobenchsecretkey2026version2"

# CPU Pinning Map (x86_64, 16 threads, Linux)
CPU_COTURN = "2"   # Core 1
CPU_SERVER = "4"   # Core 2
CPU_CLIENT = "6"   # Core 3
CPU_IPERF_S = "8"  # Generator Core 4
CPU_IPERF_C = "10" # Generator Core 6

procs = []

def run_cmd(cmd, check=True, shell=True, capture=True):
    env = dict(os.environ, LC_ALL="C", LANG="C")
    res = subprocess.run(cmd, shell=shell, text=True, capture_output=capture, env=env)
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

    run_cmd("sudo iptables -D INPUT -i veth-cln-host -j ACCEPT 2>/dev/null || true", check=False)
    run_cmd("sudo iptables -D INPUT -i wg-cln-srv -j ACCEPT 2>/dev/null || true", check=False)
    run_cmd("sudo pkill -9 -f 'target/profiling/wdtt' 2>/dev/null || true", check=False)
    run_cmd("sudo pkill -9 -f 'target/profiling/forwarder-baseline' 2>/dev/null || true", check=False)
    run_cmd("sudo pkill -9 -f 'turnserver.*34790' 2>/dev/null || true", check=False)
    run_cmd("sudo pkill -9 -f 'iperf3' 2>/dev/null || true", check=False)
    run_cmd("sudo ip link del wg-cln-srv 2>/dev/null || true", check=False)
    run_cmd("sudo ip link del veth-cln-host 2>/dev/null || true", check=False)
    run_cmd("sudo ip netns del wdtt-cln-ns 2>/dev/null || true", check=False)
    shutil.rmtree(TEST_DIR, ignore_errors=True)

def lock_performance_governor():
    try:
        run_cmd("sudo cpupower frequency-set -g performance > /dev/null 2>&1 || true", check=False)
    except Exception:
        pass

def setup_environment(runtime="multi_thread", workers=2, keepalive="powersave", start_wg=True, coalesce_ms=0):
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
        "--min-port", "49460",
        "--max-port", "49500",
        "--no-tls",
        "--no-stdout-log",
    ]
    turn_proc = subprocess.Popen(turn_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=dict(os.environ, LC_ALL="C"))
    procs.append(turn_proc)
    time.sleep(1)

    # 3. WireGuard interfaces (if requested)
    if start_wg:
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

    # 4. wdtt-server
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
        "--runtime", runtime,
        "--workers", str(workers),
    ]
    if coalesce_ms > 0:
        server_cmd.extend(["--coalesce-ms", str(coalesce_ms)])
    server_log = open(os.path.join(TEST_DIR, "server.log"), "w")
    server_proc = subprocess.Popen(server_cmd, stdout=server_log, stderr=server_log, env=dict(os.environ, LC_ALL="C"))
    procs.append(server_proc)

    for _ in range(50):
        if os.path.exists(relayed_file) and os.path.getsize(relayed_file) > 0:
            break
        time.sleep(0.1)

    with open(relayed_file) as f:
        server_relayed_addr = f.read().strip()

    # 5. wdttd
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
        "--keepalive", keepalive,
        "--runtime", runtime,
        "--workers", str(workers),
    ]
    if coalesce_ms > 0:
        client_cmd.extend(["--coalesce-ms", str(coalesce_ms)])
    client_log = open(os.path.join(TEST_DIR, "client.log"), "w")
    client_proc = subprocess.Popen(client_cmd, stdout=client_log, stderr=client_log, env=dict(os.environ, LC_ALL="C"))
    procs.append(client_proc)
    time.sleep(1.5)

    if start_wg:
        run_cmd("sudo ip netns exec wdtt-cln-ns ping -c 2 -W 1 10.88.88.1")

    # Get client pid inside netns
    cl_pids = run_cmd("pgrep -f target/profiling/wdttd").stdout.strip().split()
    client_pid = cl_pids[-1] if cl_pids else None
    server_pid = str(server_proc.pid)

    return server_pid, client_pid

def parse_perf_stat(output):
    metrics = {}
    for line in output.splitlines():
        line = line.strip()
        if "context-switches" in line:
            parts = line.split()
            val = parts[0].replace(".", "").replace(",", "")
            try:
                metrics["context_switches"] = int(val)
            except ValueError:
                metrics["context_switches"] = 0
        elif "cpu-migrations" in line:
            parts = line.split()
            val = parts[0].replace(".", "").replace(",", "")
            try:
                metrics["cpu_migrations"] = int(val)
            except ValueError:
                metrics["cpu_migrations"] = 0
        elif "task-clock" in line:
            parts = line.split()
            # Under LC_ALL=C, decimal separator is dot (e.g. "46.75 msec task-clock")
            val = parts[0].replace(",", ".")
            try:
                metrics["task_clock_ms"] = float(val)
            except ValueError:
                metrics["task_clock_ms"] = 0.0
    return metrics

def parse_perf_trace(output):
    syscalls = {}
    in_table = False
    for line in output.splitlines():
        if "syscall" in line and "calls" in line:
            in_table = True
            continue
        if in_table and "---" in line:
            continue
        if in_table:
            parts = line.split()
            if len(parts) >= 2:
                name = parts[0]
                try:
                    calls = int(parts[1].replace(".", "").replace(",", ""))
                    syscalls[name] = calls
                except ValueError:
                    pass
    return syscalls

def parse_pidstat_w(output):
    cswch_sum = 0.0
    nvcswch_sum = 0.0
    for line in output.splitlines():
        parts = line.replace(",", ".").split()
        if len(parts) >= 6 and (parts[-1] == "wdttd" or parts[-1] == "wdtt-server"):
            try:
                cswch_sum += float(parts[-3])
                nvcswch_sum += float(parts[-2])
            except ValueError:
                pass
    return {"cswch_s": cswch_sum, "nvcswch_s": nvcswch_sum}

def measure_forwarder_baseline(runtime_mode, workers=1, target_rate_mbps=20, duration=6):
    print(f"\n>>> Measuring Baseline Cost Floor: forwarder-baseline @ {target_rate_mbps} Mbps | Runtime: {runtime_mode} (workers={workers})")
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

    # 2. Sink listening on 192.168.130.1:51852 (Core 4)
    fwd_bin = os.path.abspath("target/profiling/forwarder-baseline")
    sink_cmd = ["taskset", "-c", CPU_IPERF_S, fwd_bin, "sink", "192.168.130.1:51852"]
    sink_proc = subprocess.Popen(sink_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=dict(os.environ, LC_ALL="C"))
    procs.append(sink_proc)
    time.sleep(0.5)

    # 3. forwarder-baseline listening on 192.168.130.1:51851 forwarding to 192.168.130.1:51852 (Core 2)
    fwd_cmd = [
        "taskset", "-c", CPU_SERVER,
        fwd_bin,
        "forward",
        "192.168.130.1:51851",
        "192.168.130.1:51852",
        runtime_mode,
    ]
    fwd_proc = subprocess.Popen(fwd_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=dict(os.environ, LC_ALL="C"))
    procs.append(fwd_proc)
    time.sleep(0.5)
    fwd_pid = str(fwd_proc.pid)

    # 4. perf stat and perf trace
    perf_stat_file = os.path.join(TEST_DIR, "perf_stat_fwd.txt")
    perf_trace_file = os.path.join(TEST_DIR, "perf_trace_fwd.txt")

    perf_stat_p = subprocess.Popen(
        f"sudo LC_ALL=C perf stat -e context-switches,cpu-migrations,task-clock,cycles,instructions -p {fwd_pid} sleep {duration - 1} 2> {perf_stat_file}",
        shell=True,
    )
    perf_trace_p = subprocess.Popen(
        f"sudo LC_ALL=C perf trace -s -p {fwd_pid} sleep {duration - 1} 2> {perf_trace_file}",
        shell=True,
    )

    # 5. Generator client from netns to 192.168.130.1:51851 (Core 6)
    rate_pps = 2084.0 # corresponding to 20 Mbps @ 1200 bytes
    gen_cmd = [
        "sudo", "ip", "netns", "exec", "wdtt-cln-ns",
        "taskset", "-c", CPU_IPERF_C,
        fwd_bin,
        "gen",
        "192.168.130.1:51851",
        str(rate_pps),
        str(duration),
    ]
    gen_res = run_cmd(" ".join(gen_cmd))
    perf_stat_p.wait()
    perf_trace_p.wait()

    gen_data = json.loads(gen_res.stdout.strip())
    packets = gen_data["sent_packets"]
    pps = gen_data["actual_pps"]
    actual_mbps = round((packets * 1200 * 8) / (gen_data["elapsed_sec"] * 1e6), 2)

    perf_stat = {}
    if os.path.exists(perf_stat_file):
        with open(perf_stat_file) as f:
            perf_stat = parse_perf_stat(f.read())

    syscalls = {}
    if os.path.exists(perf_trace_file):
        with open(perf_trace_file) as f:
            syscalls = parse_perf_trace(f.read())

    cleanup()

    task_clock_ms = perf_stat.get("task_clock_ms", 0.0)
    monitored_duration = duration - 1
    monitored_packets = pps * monitored_duration
    us_per_packet = (task_clock_ms * 1000.0) / monitored_packets if monitored_packets > 0 else 0.0
    cs_per_sec = perf_stat.get("context_switches", 0) / float(monitored_duration)

    epoll_calls = syscalls.get("epoll_pwait", 0) + syscalls.get("epoll_wait", 0)
    recvmmsg_calls = syscalls.get("recvmmsg", 0) + syscalls.get("recvmsg", 0) + syscalls.get("recvfrom", 0)
    futex_calls = syscalls.get("futex", 0)

    epoll_per_sec = epoll_calls / float(monitored_duration)
    recvmmsg_per_sec = recvmmsg_calls / float(monitored_duration)

    res = {
        "component": "baseline_forwarder_floor",
        "traffic_type": "UDP",
        "target_rate_mbps": target_rate_mbps,
        "actual_mbps": actual_mbps,
        "pps": round(pps, 1),
        "runtime": runtime_mode,
        "workers": workers,
        "context_switches_per_sec": round(cs_per_sec, 1),
        "epoll_calls_per_sec": round(epoll_per_sec, 1),
        "recvmmsg_calls_per_sec": round(recvmmsg_per_sec, 1),
        "futex_calls": futex_calls,
        "cpu_task_clock_ms": round(task_clock_ms, 2),
        "cpu_us_per_packet": round(us_per_packet, 2),
    }
    print(f"    Result: {res}")
    return res

def measure_idle_mode(mode_name, keepalive_arg, start_wg, duration=5, settle_sec=0):
    print(f"\n>>> Measuring Idle: {mode_name} (keepalive={keepalive_arg}, wg={start_wg}, settle={settle_sec}s, duration={duration}s)")
    srv_pid, cln_pid = setup_environment(runtime="current_thread", workers=1, keepalive=keepalive_arg, start_wg=start_wg)

    if settle_sec > 0:
        print(f"    Waiting {settle_sec}s for steady-state...")
        time.sleep(settle_sec)

    # Measure with pidstat -wt
    pidstat_cmd = f"pidstat -wt -p {cln_pid} {duration} 1"
    pidstat_res = run_cmd(pidstat_cmd).stdout

    # Measure with perf stat
    perf_cmd = f"sudo LC_ALL=C perf stat -e context-switches,cpu-migrations,task-clock -p {cln_pid} sleep {duration}"
    perf_res = run_cmd(perf_cmd, capture=True)
    perf_stat = parse_perf_stat(perf_res.stderr)

    pidstat_metrics = parse_pidstat_w(pidstat_res)

    cleanup()

    cs_total = perf_stat.get("context_switches", 0)
    cs_per_sec = cs_total / float(duration)
    task_clock_ms = perf_stat.get("task_clock_ms", 0.0)
    cpu_percent = (task_clock_ms / (duration * 1000.0)) * 100.0

    res = {
        "mode": mode_name,
        "keepalive": keepalive_arg,
        "wg_interface": "UP" if start_wg else "DOWN",
        "duration_sec": duration,
        "settle_sec": settle_sec,
        "context_switches_total": cs_total,
        "context_switches_per_sec": round(cs_per_sec, 2),
        "cpu_percent": round(cpu_percent, 3),
        "pidstat_cswch_s": pidstat_metrics.get("cswch_s", 0.0),
        "pidstat_nvcswch_s": pidstat_metrics.get("nvcswch_s", 0.0),
    }
    print(f"    Result: {res}")
    return res

def measure_rate_workload(traffic_type, target_rate_mbps, runtime_mode, workers=2, duration=6, coalesce_ms=0):
    print(f"\n>>> Measuring Datapath: {traffic_type} @ {target_rate_mbps} Mbps | Runtime: {runtime_mode} (workers={workers}, coalesce={coalesce_ms}ms)")
    srv_pid, cln_pid = setup_environment(runtime=runtime_mode, workers=workers, keepalive="powersave", start_wg=True, coalesce_ms=coalesce_ms)

    # Start iperf3 server on CPU_IPERF_S
    iperf_s_cmd = ["taskset", "-c", CPU_IPERF_S, "iperf3", "-s", "-B", "10.88.88.1"]
    iperf_s_proc = subprocess.Popen(iperf_s_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=dict(os.environ, LC_ALL="C"))
    procs.append(iperf_s_proc)
    time.sleep(0.5)

    # Prepare iperf3 client command
    if traffic_type == "UDP":
        iperf_c_cmd = [
            "sudo", "ip", "netns", "exec", "wdtt-cln-ns",
            "taskset", "-c", CPU_IPERF_C,
            "iperf3", "-c", "10.88.88.1",
            "-u",
            "-b", f"{target_rate_mbps}M",
            "-l", "1200",
            "-t", str(duration),
            "-J",
        ]
    else: # TCP
        iperf_c_cmd = [
            "sudo", "ip", "netns", "exec", "wdtt-cln-ns",
            "taskset", "-c", CPU_IPERF_C,
            "iperf3", "-c", "10.88.88.1",
            "-b", f"{target_rate_mbps}M",
            "-t", str(duration),
            "-J",
        ]

    # Run perf trace and perf stat in background during iperf run
    perf_stat_file = os.path.join(TEST_DIR, "perf_stat.txt")
    perf_trace_file = os.path.join(TEST_DIR, "perf_trace.txt")

    perf_stat_p = subprocess.Popen(
        f"sudo LC_ALL=C perf stat -e context-switches,cpu-migrations,task-clock,cycles,instructions -p {srv_pid} sleep {duration - 1} 2> {perf_stat_file}",
        shell=True,
    )
    perf_trace_p = subprocess.Popen(
        f"sudo LC_ALL=C perf trace -s -p {srv_pid} sleep {duration - 1} 2> {perf_trace_file}",
        shell=True,
    )

    # Execute iperf3
    iperf_res = run_cmd(" ".join(iperf_c_cmd), check=False)
    perf_stat_p.wait()
    perf_trace_p.wait()

    # Parse iperf3 json
    try:
        iperf_data = json.loads(iperf_res.stdout)
    except Exception:
        iperf_data = {}

    bps = 0.0
    packets = 0
    if "end" in iperf_data:
        end = iperf_data["end"]
        if "sum_received" in end and end["sum_received"].get("bits_per_second", 0) > 0:
            bps = end["sum_received"]["bits_per_second"]
        elif "sum_sent" in end:
            bps = end["sum_sent"].get("bits_per_second", 0)
        elif "sum" in end:
            bps = end["sum"].get("bits_per_second", 0)

        if traffic_type == "UDP":
            packets = end.get("sum", {}).get("packets", 0)
            if packets == 0:
                packets = end.get("sum_sent", {}).get("packets", 0)
        else:
            bytes_sent = end.get("sum_sent", {}).get("bytes", 0)
            packets = bytes_sent // 1200

    actual_mbps = round(bps / 1e6, 2)
    pps = packets / duration

    # Parse perf stat
    perf_stat = {}
    if os.path.exists(perf_stat_file):
        with open(perf_stat_file) as f:
            perf_stat = parse_perf_stat(f.read())

    # Parse perf trace
    syscalls = {}
    if os.path.exists(perf_trace_file):
        with open(perf_trace_file) as f:
            syscalls = parse_perf_trace(f.read())

    # Stop server & client cleanly to flush final metrics log
    cleanup()

    # Read server.log for batch metrics
    server_log_file = os.path.join(TEST_DIR, "server.log")
    batches_single = 0
    batches_multi = 0
    if os.path.exists(server_log_file):
        with open(server_log_file) as f:
            content = f.read()
            m = re.search(r"batches single=(\d+) multi=(\d+)", content)
            if m:
                batches_single = int(m.group(1))
                batches_multi = int(m.group(2))

    task_clock_ms = perf_stat.get("task_clock_ms", 0.0)
    monitored_duration = duration - 1
    monitored_packets = pps * monitored_duration
    us_per_packet = (task_clock_ms * 1000.0) / monitored_packets if monitored_packets > 0 else 0.0
    cs_per_sec = perf_stat.get("context_switches", 0) / float(monitored_duration)

    epoll_calls = syscalls.get("epoll_pwait", 0) + syscalls.get("epoll_wait", 0)
    recvmmsg_calls = syscalls.get("recvmmsg", 0)
    futex_calls = syscalls.get("futex", 0)

    epoll_per_sec = epoll_calls / float(monitored_duration)
    recvmmsg_per_sec = recvmmsg_calls / float(monitored_duration)

    # Measure RTT under load (30 pings)
    ping_cmd = "sudo ip netns exec wdtt-cln-ns ping -c 30 -i 0.05 10.88.88.1"
    ping_out = run_cmd(ping_cmd, check=False).stdout
    rtts = []
    for line in ping_out.splitlines():
        if "time=" in line:
            try:
                t = float(line.split("time=")[1].split()[0])
                rtts.append(t)
            except Exception:
                pass
    rtts.sort()
    rtt_med = rtts[len(rtts)//2] if rtts else 0.0
    p99_idx = min(len(rtts) - 1, int(len(rtts) * 0.99)) if rtts else 0
    rtt_p99 = rtts[p99_idx] if rtts else 0.0

    res = {
        "component": "wdtt_datapath",
        "traffic_type": traffic_type,
        "target_rate_mbps": target_rate_mbps,
        "actual_mbps": actual_mbps,
        "pps": round(pps, 1),
        "runtime": runtime_mode,
        "workers": workers,
        "coalesce_ms": coalesce_ms,
        "rtt_median_ms": round(rtt_med, 2),
        "rtt_p99_ms": round(rtt_p99, 2),
        "context_switches_per_sec": round(cs_per_sec, 1),
        "epoll_calls_per_sec": round(epoll_per_sec, 1),
        "recvmmsg_calls_per_sec": round(recvmmsg_per_sec, 1),
        "futex_calls": futex_calls,
        "batches_single": batches_single,
        "batches_multi": batches_multi,
        "cpu_task_clock_ms": round(task_clock_ms, 2),
        "cpu_us_per_packet": round(us_per_packet, 2),
    }
    print(f"    Result: {res}")
    return res

def main():
    parser = argparse.ArgumentParser(description="WDTT Tokio and Idle Benchmarks")
    parser.add_argument("--idle-only", action="store_true", help="Run only idle benchmarks")
    parser.add_argument("--rate-only", action="store_true", help="Run only datapath rate benchmarks")
    parser.add_argument("--coalesce-ms", type=int, default=0, help="Enable coalescing window in ms")
    parser.add_argument("--output", default="docs/tokio_and_idle_results.json", help="Output JSON path")
    cli_args = parser.parse_args()

    signal.signal(signal.SIGINT, lambda s, f: (cleanup(), sys.exit(1)))
    signal.signal(signal.SIGTERM, lambda s, f: (cleanup(), sys.exit(1)))

    lock_performance_governor()

    results = {
        "cost_floor_benchmarks": [],
        "idle_benchmarks": [],
        "rate_benchmarks": [],
    }

    try:
        # 1. Baseline Cost Floor (forwarder-baseline)
        if not cli_args.idle_only and not cli_args.rate_only:
            print("=================================================================")
            print("  STAGE 0: COST FLOOR (RAW UDP FORWARDER BASELINE)")
            print("=================================================================")
            res_fwd_cur = measure_forwarder_baseline(runtime_mode="current_thread", workers=1, target_rate_mbps=20, duration=6)
            results["cost_floor_benchmarks"].append(res_fwd_cur)

            res_fwd_multi = measure_forwarder_baseline(runtime_mode="multi_thread", workers=2, target_rate_mbps=20, duration=6)
            results["cost_floor_benchmarks"].append(res_fwd_multi)

        # 2. Idle Benchmarks
        if not cli_args.rate_only:
            print("\n=================================================================")
            print("  STAGE 1: IDLE TUNNEL & KEEPALIVE BENCHMARKS")
            print("=================================================================")
            results["idle_benchmarks"].append(
                measure_idle_mode("Idle Interface DOWN", keepalive_arg="disabled", start_wg=False, duration=5, settle_sec=0)
            )
            results["idle_benchmarks"].append(
                measure_idle_mode("Idle Interface UP (PowerSave Initial 10s)", keepalive_arg="powersave", start_wg=True, duration=10, settle_sec=0)
            )
            results["idle_benchmarks"].append(
                measure_idle_mode("Idle Interface UP (PowerSave Steady State after 60s)", keepalive_arg="powersave", start_wg=True, duration=20, settle_sec=60)
            )
            results["idle_benchmarks"].append(
                measure_idle_mode("Idle Interface UP (Chaff Voice)", keepalive_arg="chaff", start_wg=True, duration=5, settle_sec=0)
            )

        # 3. Rate Datapath Benchmarks: Tokio multi_thread(2) vs current_thread
        if not cli_args.idle_only:
            print("\n=================================================================")
            print(f"  STAGE 2: UDP VS TCP LOW-RATE DATAPATH (coalesce_ms={cli_args.coalesce_ms})")
            print("=================================================================")
            test_matrix = [
                ("UDP", 20),
                ("UDP", 50),
                ("TCP", 20),
            ]

            for traffic, rate in test_matrix:
                # Mode A: multi_thread(2)
                res_multi = measure_rate_workload(traffic, rate, runtime_mode="multi_thread", workers=2, duration=6)
                results["rate_benchmarks"].append(res_multi)

                # Mode B: current_thread
                res_current = measure_rate_workload(traffic, rate, runtime_mode="current_thread", workers=1, duration=6)
                results["rate_benchmarks"].append(res_current)

        output_file = cli_args.output
        os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
        with open(output_file, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n[OK] Results successfully written to {output_file}")

    finally:
        cleanup()

if __name__ == "__main__":
    main()
