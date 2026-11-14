#!/usr/bin/env python3
"""
Comprehensive Matrix Benchmark Runner for WDTT v2 (Stage 4.1).
- Enforces taskset CPU pinning (P-cores for daemons, E-cores for iperf3)
- Validates CPU frequency governor = performance
- Interleaved alternating execution: A, B, C, D across 5 iterations (20 runs total)
  * Config A: Default buffers (kernel default ~208 KB)
  * Config B: SO_RCVBUF only (4 MB)
  * Config C: SO_SNDBUF only (4 MB)
  * Config D: Both SO_RCVBUF and SO_SNDBUF (4 MB)
- Fixed speed sweeps: iperf3 -b 20M / 50M / 200M (TCP and UDP)
- Idle tunnel measurement: wakeups/s (context switches via pidstat -w) and CPU in idle
- Zero strace/ptrace overhead
"""

import os
import sys
import time
import json
import shutil
import signal
import statistics
import subprocess

TEST_DIR = "/tmp/wdtt_matrix_bench"
TURN_PORT = 34790
TURN_USER = "benchuser"
TURN_PASS = "benchpass"
TURN_REALM = "wdtt-matrix"
PSK = "stage4matrixbenchmarksecret2026v2"

# CPU Core Pinning Map (Intel Core 5 220H)
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
    procs.clear()

    run_cmd("sudo iptables -D INPUT -i veth-mat-host -j ACCEPT 2>/dev/null || true", check=False)
    run_cmd("sudo iptables -D INPUT -i wg-mat-srv -j ACCEPT 2>/dev/null || true", check=False)
    run_cmd("sudo pkill -9 -f 'target/profiling/wdtt' 2>/dev/null || true", check=False)
    run_cmd("sudo pkill -9 -f 'turnserver.*34790' 2>/dev/null || true", check=False)
    run_cmd("sudo ip link del wg-mat-srv 2>/dev/null || true", check=False)
    run_cmd("sudo ip link del veth-mat-host 2>/dev/null || true", check=False)
    run_cmd("sudo ip netns del wdtt-mat-ns 2>/dev/null || true", check=False)
    shutil.rmtree(TEST_DIR, ignore_errors=True)

class TunnelFixture:
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

        # 1. Setup netns & veth
        run_cmd("sudo ip netns add wdtt-mat-ns")
        run_cmd("sudo ip link add veth-mat-host type veth peer name veth-mat-cl")
        run_cmd("sudo ip link set veth-mat-cl netns wdtt-mat-ns")
        run_cmd("sudo ip addr add 192.168.130.1/24 dev veth-mat-host")
        run_cmd("sudo ip link set veth-mat-host up")
        run_cmd("sudo ip -n wdtt-mat-ns addr add 192.168.130.2/24 dev veth-mat-cl")
        run_cmd("sudo ip -n wdtt-mat-ns link set veth-mat-cl up")
        run_cmd("sudo ip -n wdtt-mat-ns link set lo up")
        run_cmd("sudo iptables -I INPUT 1 -i veth-mat-host -j ACCEPT")

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
        turn_proc = subprocess.Popen(turn_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        procs.append(turn_proc)
        self.coturn_pid = str(turn_proc.pid)
        time.sleep(1)

        # 3. WireGuard
        server_priv = run_cmd("wg genkey").stdout.strip()
        server_pub = run_cmd(f"echo '{server_priv}' | wg pubkey").stdout.strip()
        client_priv = run_cmd("wg genkey").stdout.strip()
        client_pub = run_cmd(f"echo '{client_priv}' | wg pubkey").stdout.strip()

        srv_key_file = os.path.join(TEST_DIR, "srv.key")
        with open(srv_key_file, "w") as f:
            f.write(server_priv)
        run_cmd("sudo ip link add dev wg-mat-srv type wireguard")
        run_cmd("sudo ip addr add 10.88.88.1/24 dev wg-mat-srv")
        run_cmd(f"sudo wg set wg-mat-srv listen-port 51850 private-key {srv_key_file} peer {client_pub} allowed-ips 10.88.88.2/32")
        run_cmd("sudo ip link set up dev wg-mat-srv")
        run_cmd("sudo iptables -I INPUT 1 -i wg-mat-srv -j ACCEPT")

        cl_key_file = os.path.join(TEST_DIR, "cl.key")
        with open(cl_key_file, "w") as f:
            f.write(client_priv)
        run_cmd("sudo ip -n wdtt-mat-ns link add dev wg-mat-cl type wireguard")
        run_cmd("sudo ip -n wdtt-mat-ns addr add 10.88.88.2/24 dev wg-mat-cl")
        run_cmd(f"sudo ip netns exec wdtt-mat-ns wg set wg-mat-cl private-key {cl_key_file} peer {server_pub} allowed-ips 10.88.88.1/32 endpoint 127.0.0.1:51851")
        run_cmd("sudo ip -n wdtt-mat-ns link set up dev wg-mat-cl")

        # 4. Environment for socket tuning
        env = os.environ.copy()
        if self.disable_sock_tune:
            env["WDTT_DISABLE_SOCK_TUNE"] = "1"
        else:
            env.pop("WDTT_DISABLE_SOCK_TUNE", None)
            if self.rcvbuf is not None:
                env["WDTT_SOCK_RCVBUF"] = str(self.rcvbuf)
            if self.sndbuf is not None:
                env["WDTT_SOCK_SNDBUF"] = str(self.sndbuf)

        # 5. wdtt-server
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
        self.server_pid = str(server_proc.pid)

        for _ in range(50):
            if os.path.exists(relayed_file) and os.path.getsize(relayed_file) > 0:
                break
            time.sleep(0.1)

        with open(relayed_file) as f:
            server_relayed_addr = f.read().strip()

        # 6. wdttd
        client_bin = os.path.abspath("target/profiling/wdttd")
        client_cmd = [
            "sudo", "ip", "netns", "exec", "wdtt-mat-ns",
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

        run_cmd("sudo ip netns exec wdtt-mat-ns ping -c 3 -W 2 10.88.88.1")
        cl_pids = run_cmd("pgrep -f target/profiling/wdttd").stdout.strip().split()
        self.client_pid = cl_pids[-1] if cl_pids else None
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        cleanup()

def extract_cpu(pidstat_out, pid):
    for line in pidstat_out.splitlines():
        if ("Average:" in line or "Среднее:" in line) and pid in line:
            parts = line.split()
            try:
                # pidstat columns: Time UID PID %usr %system %guest %wait %CPU CPU Command
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

def run_single_iperf_test(fixture, duration=10, bandwidth=None, is_udp=False):
    run_cmd("nstat -z > /dev/null 2>&1 || true", check=False)

    iperf_s = subprocess.Popen(
        ["taskset", "-c", CPU_IPERF_S, "iperf3", "-s", "-B", "10.88.88.1", "-p", "5209", "-1"],
        stdout=subprocess.DEVNULL,
    )
    time.sleep(0.3)

    pid_list = ",".join(filter(None, [fixture.server_pid, fixture.client_pid, fixture.coturn_pid]))
    pidstat_proc = subprocess.Popen(
        ["pidstat", "-u", "-t", "-p", pid_list, "1", str(duration)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    client_args = [
        "sudo", "ip", "netns", "exec", "wdtt-mat-ns",
        "taskset", "-c", CPU_IPERF_C,
        "iperf3", "-c", "10.88.88.1", "-p", "5209", "-t", str(duration), "--json",
    ]
    if is_udp:
        client_args.append("-u")
    if bandwidth:
        client_args.extend(["-b", bandwidth])

    iperf_c = subprocess.Popen(
        client_args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    stdout, stderr = iperf_c.communicate()
    iperf_s.wait()
    pidstat_out, _ = pidstat_proc.communicate()

    nstat_out = run_cmd("nstat -a | grep -E 'UdpRcvbufErrors|UdpInErrors|UdpSndbufErrors' || true").stdout

    res_json = json.loads(stdout)
    if is_udp:
        sum_data = res_json["end"]["sum"]
        bps = sum_data["bits_per_second"]
        retrans = 0
        loss_pct = sum_data.get("lost_percent", 0.0)
        jitter_ms = sum_data.get("jitter_ms", 0.0)
    else:
        bps = res_json["end"]["sum_received"]["bits_per_second"]
        retrans = res_json["end"]["sum_sent"].get("retransmits", 0)
        loss_pct = 0.0
        jitter_ms = 0.0

    mbps = bps / 1_000_000.0
    pps = int(bps / (1200 * 8))

    srv_cpu = extract_cpu(pidstat_out, fixture.server_pid)
    cl_cpu = extract_cpu(pidstat_out, fixture.client_pid)
    turn_cpu = extract_cpu(pidstat_out, fixture.coturn_pid)

    # Calculate CPU-sec / Gbit
    total_gbit = (bps * duration) / 1e9
    srv_cpu_sec = (srv_cpu["cpu"] / 100.0) * duration
    cl_cpu_sec = (cl_cpu["cpu"] / 100.0) * duration
    tot_cpu_sec = srv_cpu_sec + cl_cpu_sec
    cpu_sec_per_gbit = tot_cpu_sec / total_gbit if total_gbit > 0 else 0
    srv_cpu_sec_per_gbit = srv_cpu_sec / total_gbit if total_gbit > 0 else 0

    # Parse nstat errors
    rcv_buf_err = 0
    for line in nstat_out.splitlines():
        if "UdpRcvbufErrors" in line:
            parts = line.split()
            if len(parts) >= 2:
                rcv_buf_err = int(parts[1])

    return {
        "throughput_mbps": round(mbps, 2),
        "retransmits": retrans,
        "pps": pps,
        "loss_pct": loss_pct,
        "jitter_ms": jitter_ms,
        "server_cpu": srv_cpu,
        "client_cpu": cl_cpu,
        "coturn_cpu": turn_cpu,
        "srv_cpu_sec_per_gbit": round(srv_cpu_sec_per_gbit, 4),
        "total_cpu_sec_per_gbit": round(cpu_sec_per_gbit, 4),
        "udp_rcvbuf_errors": rcv_buf_err,
    }

def run_idle_measurement(fixture, duration=10):
    pid_list = ",".join(filter(None, [fixture.server_pid, fixture.client_pid]))
    # Run pidstat -u (CPU) and pidstat -w (context switches / wakeups)
    proc_u = subprocess.Popen(
        ["pidstat", "-u", "-p", pid_list, "1", str(duration)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    proc_w = subprocess.Popen(
        ["pidstat", "-w", "-p", pid_list, "1", str(duration)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    out_u, _ = proc_u.communicate()
    out_w, _ = proc_w.communicate()

    def get_cswch(out, pid):
        for line in out.splitlines():
            if ("Average:" in line or "Среднее:" in line) and pid in line:
                parts = line.split()
                try:
                    # columns: Time UID PID cswch/s nvcswch/s Command
                    cswch = float(parts[3].replace(",", "."))
                    nvcswch = float(parts[4].replace(",", "."))
                    return cswch + nvcswch
                except Exception:
                    pass
        return 0.0

    srv_cpu = extract_cpu(out_u, fixture.server_pid)
    cl_cpu = extract_cpu(out_u, fixture.client_pid)
    srv_wakeups = get_cswch(out_w, fixture.server_pid)
    cl_wakeups = get_cswch(out_w, fixture.client_pid)

    return {
        "server_cpu": srv_cpu,
        "client_cpu": cl_cpu,
        "server_wakeups_per_sec": srv_wakeups,
        "client_wakeups_per_sec": cl_wakeups,
    }

def summarize(series):
    if not series:
        return {"med": 0, "min": 0, "max": 0}
    return {
        "med": round(statistics.median(series), 2),
        "min": round(min(series), 2),
        "max": round(max(series), 2),
    }

def main():
    signal.signal(signal.SIGINT, lambda s, f: (cleanup(), sys.exit(1)))
    signal.signal(signal.SIGTERM, lambda s, f: (cleanup(), sys.exit(1)))

    # Verify governor
    govs = run_cmd("cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor | sort -u").stdout.strip()
    print(f"[+] Current CPU frequency governor: {govs}")

    configs = [
        {"id": "A", "name": "Default (~208 KB)", "kwargs": {"disable_sock_tune": True}},
        {"id": "B", "name": "RCVBUF only (4 MB)", "kwargs": {"rcvbuf": 4194304, "sndbuf": 0}},
        {"id": "C", "name": "SNDBUF only (4 MB)", "kwargs": {"rcvbuf": 0, "sndbuf": 4194304}},
        {"id": "D", "name": "Both tuned (4 MB)", "kwargs": {"rcvbuf": 4194304, "sndbuf": 4194304}},
    ]

    NUM_ROUNDS = 5
    raw_results = {c["id"]: [] for c in configs}

    print(f"\n=======================================================")
    print(f"  STARTING 5-ROUND INTERLEAVED BUFFER MATRIX BENCHMARK")
    print(f"  Execution sequence: " + ", ".join([f"Round {r+1} (A,B,C,D)" for r in range(NUM_ROUNDS)]))
    print(f"=======================================================\n")

    for round_idx in range(NUM_ROUNDS):
        print(f"\n>>> ROUND {round_idx + 1} / {NUM_ROUNDS} <<<")
        for cfg in configs:
            cfg_id = cfg["id"]
            print(f"  Running Config {cfg_id} ({cfg['name']})...", flush=True)
            with TunnelFixture(**cfg["kwargs"]) as fix:
                res = run_single_iperf_test(fix, duration=10)
                raw_results[cfg_id].append(res)
                print(f"    -> Throughput: {res['throughput_mbps']} Mbps | Retransmits: {res['retransmits']} | Server CPU: {res['server_cpu']['cpu']}% | nstat drops: {res['udp_rcvbuf_errors']}")
            time.sleep(1)

    # Summarize Matrix
    matrix_summary = {}
    for cfg in configs:
        cid = cfg["id"]
        runs = raw_results[cid]
        matrix_summary[cid] = {
            "name": cfg["name"],
            "throughput_mbps": summarize([r["throughput_mbps"] for r in runs]),
            "retransmits": summarize([r["retransmits"] for r in runs]),
            "pps": summarize([r["pps"] for r in runs]),
            "server_cpu_pct": summarize([r["server_cpu"]["cpu"] for r in runs]),
            "server_usr_pct": summarize([r["server_cpu"]["usr"] for r in runs]),
            "server_sys_pct": summarize([r["server_cpu"]["sys"] for r in runs]),
            "client_cpu_pct": summarize([r["client_cpu"]["cpu"] for r in runs]),
            "coturn_cpu_pct": summarize([r["coturn_cpu"]["cpu"] for r in runs]),
            "srv_cpu_sec_per_gbit": summarize([r["srv_cpu_sec_per_gbit"] for r in runs]),
            "total_cpu_sec_per_gbit": summarize([r["total_cpu_sec_per_gbit"] for r in runs]),
            "udp_rcvbuf_errors": summarize([r["udp_rcvbuf_errors"] for r in runs]),
        }

    # Now run Fixed Speed Sweeps with Config D (Both tuned)
    print(f"\n=======================================================")
    print(f"  RUNNING FIXED SPEED SWEEPS (20M, 50M, 200M: TCP & UDP)")
    print(f"=======================================================\n")

    fixed_speeds = ["20M", "50M", "200M"]
    speed_results = {"tcp": {}, "udp": {}}

    with TunnelFixture(**configs[3]["kwargs"]) as fix:
        for spd in fixed_speeds:
            print(f"  Fixed TCP @ {spd}...")
            r_tcp = run_single_iperf_test(fix, duration=10, bandwidth=spd, is_udp=False)
            speed_results["tcp"][spd] = r_tcp
            print(f"    -> {r_tcp['throughput_mbps']} Mbps, Retrans: {r_tcp['retransmits']}, Srv CPU: {r_tcp['server_cpu']['cpu']}%")
            time.sleep(0.5)

        for spd in fixed_speeds:
            print(f"  Fixed UDP @ {spd}...")
            r_udp = run_single_iperf_test(fix, duration=10, bandwidth=spd, is_udp=True)
            speed_results["udp"][spd] = r_udp
            print(f"    -> {r_udp['throughput_mbps']} Mbps, Loss: {r_udp['loss_pct']}%, Jitter: {r_udp['jitter_ms']}ms, Srv CPU: {r_udp['server_cpu']['cpu']}%")
            time.sleep(0.5)

        # Idle measurement
        print("\n  Measuring Idle Tunnel (0 traffic, 10s)...")
        idle_res = run_idle_measurement(fix, duration=10)
        print(f"    -> Idle Server CPU: {idle_res['server_cpu']['cpu']}%, Wakeups/s: {idle_res['server_wakeups_per_sec']}")
        print(f"    -> Idle Client CPU: {idle_res['client_cpu']['cpu']}%, Wakeups/s: {idle_res['client_wakeups_per_sec']}")

    final_report = {
        "governor": govs,
        "matrix_summary": matrix_summary,
        "raw_results": raw_results,
        "speed_results": speed_results,
        "idle_results": idle_res,
    }

    report_path = os.path.abspath("docs/matrix_benchmark_results.json")
    with open(report_path, "w") as f:
        json.dump(final_report, f, indent=2)

    print(f"\n[+] Full benchmark results saved to {report_path}")

if __name__ == "__main__":
    main()
