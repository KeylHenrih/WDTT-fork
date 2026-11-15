#!/usr/bin/env python3
"""
Empirical test of the Tokio EPOLLOUT hypothesis:
Comparing:
  Mode A: Standard Tokio UdpSocket (recv_from + send_to)
  Mode B: AsyncFd with Interest::READABLE only + direct non-blocking sendto

Measures:
  - epoll_wait syscalls per second
  - context switches per second
  - CPU task-clock (ms) and CPU us per packet
Over n >= 5 runs under identical conditions.
"""

import json
import os
import re
import subprocess
import time
import numpy as np

RATE_PPS = 2084
DURATION_SEC = 5
RUNS = 5

CPU_FWD = "4"
CPU_GEN = "8"

def run_cmd(cmd):
    env = dict(os.environ, LC_ALL="C")
    return subprocess.run(cmd, shell=True, text=True, capture_output=True, env=env)

def parse_perf_output(perf_str):
    # e.g.:
    #      10 534      syscalls:sys_enter_epoll_wait
    #       5 270      context-switches
    #      190,83 msec task-clock
    epoll_wait = 0
    cs = 0
    task_clock_ms = 0.0

    for line in perf_str.splitlines():
        clean = line.replace('\u202f', '').replace(' ', '').replace(',', '.')
        if 'syscalls:sys_enter_epoll_wait' in line:
            m = re.search(r'(\d+)', clean)
            if m: epoll_wait = int(m.group(1))
        elif 'context-switches' in line:
            m = re.search(r'(\d+)', clean)
            if m: cs = int(m.group(1))
        elif 'task-clock' in line:
            m = re.search(r'([\d\.]+)msec', clean)
            if m: task_clock_ms = float(m.group(1))

    return epoll_wait, cs, task_clock_ms

def run_single(mode, run_idx):
    # 1. Start sink
    sink = subprocess.Popen(
        ['target/profiling/forwarder-baseline', 'sink', '127.0.0.1:45556'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(0.2)

    # 2. Start forwarder
    subcmd = 'forward' if mode == 'tokio_standard' else 'forward-asyncfd'
    fwd = subprocess.Popen(
        ['taskset', '-c', CPU_FWD, 'target/profiling/forwarder-baseline', subcmd, '127.0.0.1:45555', '127.0.0.1:45556', 'current_thread'],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(0.3)

    # 3. Attach perf stat
    events = 'syscalls:sys_enter_epoll_wait,context-switches,task-clock'
    perf = subprocess.Popen(
        ['sudo', 'perf', 'stat', '-e', events, '-p', str(fwd.pid), '--', 'sleep', str(DURATION_SEC)],
        stderr=subprocess.PIPE, text=True
    )

    # 4. Run generator
    gen_res = run_cmd(f"taskset -c {CPU_GEN} target/profiling/forwarder-baseline gen 127.0.0.1:45555 {RATE_PPS} {DURATION_SEC}")
    _, perf_err = perf.communicate()

    fwd.terminate()
    sink.terminate()
    fwd.wait()
    sink.wait()

    epoll_wait, cs, task_clock_ms = parse_perf_output(perf_err)
    gen_data = json.loads(gen_res.stdout.strip())
    sent = gen_data.get('sent_packets', RATE_PPS * DURATION_SEC)
    actual_pps = gen_data.get('actual_pps', RATE_PPS)

    epoll_per_sec = epoll_wait / DURATION_SEC
    cs_per_sec = cs / DURATION_SEC
    epoll_per_pkt = epoll_wait / sent if sent > 0 else 0
    us_per_pkt = (task_clock_ms * 1000.0) / sent if sent > 0 else 0

    return {
        "run": run_idx,
        "mode": mode,
        "sent": sent,
        "actual_pps": actual_pps,
        "epoll_wait_total": epoll_wait,
        "epoll_per_sec": epoll_per_sec,
        "epoll_per_pkt": epoll_per_pkt,
        "cs_per_sec": cs_per_sec,
        "task_clock_ms": task_clock_ms,
        "us_per_pkt": us_per_pkt,
    }

def main():
    print(f"=== EPOLL HYPOTHESIS TEST: n={RUNS} iterations, rate={RATE_PPS} pps, duration={DURATION_SEC}s ===")
    run_cmd("sudo cpupower frequency-set -g performance > /dev/null 2>&1 || true")

    modes = ['tokio_standard', 'async_fd_read_only']
    results = {m: [] for m in modes}

    # Interleaved execution: A, B, A, B...
    for i in range(1, RUNS + 1):
        for mode in modes:
            print(f"Running run {i}/{RUNS} for {mode}...")
            res = run_single(mode, i)
            results[mode].append(res)
            print(f"  [{mode} #{i}] epoll_wait/s={res['epoll_per_sec']:.1f} (ratio {res['epoll_per_pkt']:.2f}/pkt) | CS/s={res['cs_per_sec']:.1f} | CPU={res['task_clock_ms']:.2f}ms ({res['us_per_pkt']:.2f} us/pkt)")
            time.sleep(0.5)

    print("\n" + "="*80)
    print("  SUMMARY STATISTICS (n=5)")
    print("="*80)

    summary = {}
    for mode in modes:
        epoll_s = [r['epoll_per_sec'] for r in results[mode]]
        epoll_pkt = [r['epoll_per_pkt'] for r in results[mode]]
        cs_s = [r['cs_per_sec'] for r in results[mode]]
        cpu_ms = [r['task_clock_ms'] for r in results[mode]]
        us_pkt = [r['us_per_pkt'] for r in results[mode]]

        summary[mode] = {
            "epoll_per_sec": {"min": np.min(epoll_s), "median": np.median(epoll_s), "max": np.max(epoll_s), "mean": np.mean(epoll_s), "std": np.std(epoll_s)},
            "epoll_per_pkt": {"min": np.min(epoll_pkt), "median": np.median(epoll_pkt), "max": np.max(epoll_pkt), "mean": np.mean(epoll_pkt), "std": np.std(epoll_pkt)},
            "cs_per_sec": {"min": np.min(cs_s), "median": np.median(cs_s), "max": np.max(cs_s), "mean": np.mean(cs_s), "std": np.std(cs_s)},
            "task_clock_ms": {"min": np.min(cpu_ms), "median": np.median(cpu_ms), "max": np.max(cpu_ms), "mean": np.mean(cpu_ms), "std": np.std(cpu_ms)},
            "us_per_pkt": {"min": np.min(us_pkt), "median": np.median(us_pkt), "max": np.max(us_pkt), "mean": np.mean(us_pkt), "std": np.std(us_pkt)},
        }

        print(f"\n--- {mode.upper()} ---")
        print(f"  epoll_wait/s: min={summary[mode]['epoll_per_sec']['min']:.1f}, median={summary[mode]['epoll_per_sec']['median']:.1f}, max={summary[mode]['epoll_per_sec']['max']:.1f} (std={summary[mode]['epoll_per_sec']['std']:.2f})")
        print(f"  epoll/packet: min={summary[mode]['epoll_per_pkt']['min']:.3f}, median={summary[mode]['epoll_per_pkt']['median']:.3f}, max={summary[mode]['epoll_per_pkt']['max']:.3f}")
        print(f"  CS/s        : min={summary[mode]['cs_per_sec']['min']:.1f}, median={summary[mode]['cs_per_sec']['median']:.1f}, max={summary[mode]['cs_per_sec']['max']:.1f}")
        print(f"  CPU (ms)    : min={summary[mode]['task_clock_ms']['min']:.2f}, median={summary[mode]['task_clock_ms']['median']:.2f}, max={summary[mode]['task_clock_ms']['max']:.2f}")
        print(f"  CPU us/pkt  : min={summary[mode]['us_per_pkt']['min']:.2f}, median={summary[mode]['us_per_pkt']['median']:.2f}, max={summary[mode]['us_per_pkt']['max']:.2f}")

    with open("docs/epoll_hypothesis_results.json", "w") as f:
        json.dump({"raw": results, "summary": summary}, f, indent=2)
    print("\nWrote results to docs/epoll_hypothesis_results.json")

if __name__ == "__main__":
    main()
