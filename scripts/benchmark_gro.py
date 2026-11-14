#!/usr/bin/env python3
"""
Step 5(b) Benchmark Runner: recvmmsg/sendmmsg vs recvmmsg + GRO/GSO.
- 5 rounds alternating: A (recvmmsg only: WDTT_DISABLE_GRO=1 WDTT_DISABLE_GSO=1), B (recvmmsg + GRO/GSO)
- 10s iperf3 TCP stream per run
- Taskset pinning: P-cores for daemons, E-cores for iperf3
- Governor: performance
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

TEST_DIR = "/tmp/wdtt_gro_bench"
TURN_PORT = 34790
TURN_USER = "benchuser"
TURN_PASS = "benchpass"
TURN_REALM = "wdtt-gro"
PSK = "stage4grobenchmarksecret2026v2"

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

    run_cmd("sudo iptables -D INPUT -i veth-gro-host -j ACCEPT 2>/dev/null || true", check=False)
    run_cmd("sudo iptables -D INPUT -i wg-gro-srv -j ACCEPT 2>/dev/null || true", check=False)
    run_cmd("sudo pkill -9 -f 'target/profiling/wdtt' 2>/dev/null || true", check=False)
    run_cmd("sudo pkill -9 -f 'turnserver.*34790' 2>/dev/null || true", check=False)
    run_cmd("sudo ip link del wg-gro-srv 2>/dev/null || true", check=False)
    run_cmd("sudo ip link del veth-gro-host 2>/dev/null || true", check=False)
    run_cmd("sudo ip netns del wdtt-gro-ns 2>/dev/null || true", check=False)
    shutil.rmtree(TEST_DIR, ignore_errors=True)

class TunnelFixture:
    def __init__(self, enable_gro_gso=True):
        self.enable_gro_gso = enable_gro_gso
        self.server_pid = None
        self.client_pid = None
        self.coturn_pid = None

    def __enter__(self):
        cleanup()
        os.makedirs(TEST_DIR, exist_ok=True)

        # 1. Setup netns & veth
        run_cmd("sudo ip netns add wdtt-gro-ns")
        run_cmd("sudo ip link add veth-gro-host type veth peer name veth-gro-cl")
        run_cmd("sudo ip link set veth-gro-cl netns wdtt-gro-ns")
        run_cmd("sudo ip addr add 192.168.130.1/24 dev veth-gro-host")
        run_cmd("sudo ip link set veth-gro-host up")
        run_cmd("sudo ip -n wdtt-gro-ns addr add 192.168.130.2/24 dev veth-gro-cl")
        run_cmd("sudo ip -n wdtt-gro-ns link set veth-gro-cl up")
        run_cmd("sudo ip -n wdtt-gro-ns link set lo up")
        run_cmd("sudo iptables -I INPUT 1 -i veth-gro-host -j ACCEPT")

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
        run_cmd("sudo ip link add dev wg-gro-srv type wireguard")
        run_cmd("sudo ip addr add 10.88.88.1/24 dev wg-gro-srv")
        run_cmd(f"sudo wg set wg-gro-srv listen-port 51850 private-key {srv_key_file} peer {client_pub} allowed-ips 10.88.88.2/32")
        run_cmd("sudo ip link set up dev wg-gro-srv")
        run_cmd("sudo iptables -I INPUT 1 -i wg-gro-srv -j ACCEPT")

        cl_key_file = os.path.join(TEST_DIR, "cl.key")
        with open(cl_key_file, "w") as f:
            f.write(client_priv)
        run_cmd("sudo ip -n wdtt-gro-ns link add dev wg-gro-cl type wireguard")
        run_cmd("sudo ip -n wdtt-gro-ns addr add 10.88.88.2/24 dev wg-gro-cl")
        run_cmd(f"sudo ip netns exec wdtt-gro-ns wg set wg-gro-cl private-key {cl_key_file} peer {server_pub} allowed-ips 10.88.88.1/32 endpoint 127.0.0.1:51851")
        run_cmd("sudo ip -n wdtt-gro-ns link set up dev wg-gro-cl")

        # 4. Environment
        env = os.environ.copy()
        if not self.enable_gro_gso:
            env["WDTT_DISABLE_GRO"] = "1"
            env["WDTT_DISABLE_GSO"] = "1"
        else:
            env.pop("WDTT_DISABLE_GRO", None)
            env.pop("WDTT_DISABLE_GSO", None)

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
            "sudo", "ip", "netns", "exec", "wdtt-gro-ns",
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

        run_cmd("sudo ip netns exec wdtt-gro-ns ping -c 3 -W 2 10.88.88.1")
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

def run_single_iperf_test(fixture, duration=10):
    run_cmd("sudo ip netns exec wdtt-gro-ns ping -c 1 -W 1 10.88.88.1 > /dev/null 2>&1 || true", check=False)
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
        "sudo", "ip", "netns", "exec", "wdtt-gro-ns",
        "taskset", "-c", CPU_IPERF_C,
        "iperf3", "-c", "10.88.88.1", "-p", "5209", "-t", str(duration), "--json",
    ]

    iperf_c = subprocess.Popen(
        client_args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    stdout, stderr = iperf_c.communicate()
    try:
        iperf_s.wait(timeout=2)
    except subprocess.TimeoutExpired:
        iperf_s.kill()
        iperf_s.wait()
    pidstat_out, _ = pidstat_proc.communicate()

    try:
        res_json = json.loads(stdout)
    except Exception as e:
        print(f"[-] iperf3 JSON parse error: {e}. stdout: {stdout[:200]} stderr: {stderr[:200]}")
        return {
            "throughput_mbps": 0.0,
            "retransmits": 0,
            "pps": 0,
            "server_cpu": {"usr": 0.0, "sys": 0.0, "cpu": 0.0},
            "client_cpu": {"usr": 0.0, "sys": 0.0, "cpu": 0.0},
            "coturn_cpu": {"usr": 0.0, "sys": 0.0, "cpu": 0.0},
            "srv_cpu_sec_per_gbit": 0.0,
            "total_cpu_sec_per_gbit": 0.0,
        }
    bps = res_json["end"]["sum_received"]["bits_per_second"]
    retrans = res_json["end"]["sum_sent"].get("retransmits", 0)
    mbps = bps / 1_000_000.0
    pps = int(bps / (1200 * 8))

    srv_cpu = extract_cpu(pidstat_out, fixture.server_pid)
    cl_cpu = extract_cpu(pidstat_out, fixture.client_pid)
    turn_cpu = extract_cpu(pidstat_out, fixture.coturn_pid)

    total_gbit = (bps * duration) / 1e9
    srv_cpu_sec = (srv_cpu["cpu"] / 100.0) * duration
    cl_cpu_sec = (cl_cpu["cpu"] / 100.0) * duration
    tot_cpu_sec = srv_cpu_sec + cl_cpu_sec
    cpu_sec_per_gbit = tot_cpu_sec / total_gbit if total_gbit > 0 else 0
    srv_cpu_sec_per_gbit = srv_cpu_sec / total_gbit if total_gbit > 0 else 0

    return {
        "throughput_mbps": round(mbps, 2),
        "retransmits": retrans,
        "pps": pps,
        "server_cpu": srv_cpu,
        "client_cpu": cl_cpu,
        "coturn_cpu": turn_cpu,
        "srv_cpu_sec_per_gbit": round(srv_cpu_sec_per_gbit, 4),
        "total_cpu_sec_per_gbit": round(cpu_sec_per_gbit, 4),
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

    cfgs = [
        {"id": "no_gro", "name": "recvmmsg only (GRO/GSO disabled)", "enable_gro": False},
        {"id": "with_gro", "name": "recvmmsg + GRO/GSO enabled", "enable_gro": True},
    ]

    NUM_ROUNDS = 5
    raw_results = {c["id"]: [] for c in cfgs}

    print(f"\n=======================================================")
    print(f"  STEP 5(b) BENCHMARK: recvmmsg only vs recvmmsg + GRO/GSO")
    print(f"  5 interleaved rounds (no_gro, with_gro, no_gro...)")
    print(f"=======================================================\n")

    for r in range(NUM_ROUNDS):
        print(f"\n>>> ROUND {r + 1} / {NUM_ROUNDS} <<<")
        for c in cfgs:
            cid = c["id"]
            print(f"  Running {c['name']}...", flush=True)
            with TunnelFixture(enable_gro_gso=c["enable_gro"]) as fix:
                res = run_single_iperf_test(fix, duration=10)
                raw_results[cid].append(res)
                print(f"    -> {res['throughput_mbps']} Mbps | Retransmits: {res['retransmits']} | Srv CPU: {res['server_cpu']['cpu']}% (usr: {res['server_cpu']['usr']}%, sys: {res['server_cpu']['sys']}%) | Srv CPU-s/Gbit: {res['srv_cpu_sec_per_gbit']}")
            time.sleep(1)

    summary = {}
    for c in cfgs:
        cid = c["id"]
        runs = raw_results[cid]
        summary[cid] = {
            "name": c["name"],
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
        }

    out_file = os.path.abspath("docs/gro_benchmark_results.json")
    with open(out_file, "w") as f:
        json.dump({"summary": summary, "raw": raw_results}, f, indent=2)

    print(f"\n[+] Results saved to {out_file}")

if __name__ == "__main__":
    main()
