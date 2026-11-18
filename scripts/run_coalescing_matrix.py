#!/usr/bin/env python3
"""
Coalescing Matrix Benchmark:
Measures UDP@20, UDP@50, TCP@20 under coalesce_ms in [0, 1, 2].
Records: CPU (task-clock ms), us/packet, wakeups/s (context-switches/s),
epoll calls/s, recvmmsg calls/s, throughput, and ping RTT under load (median & p99).
"""

import os
import sys
import json
from benchmark_tokio_and_idle import (
    cleanup, lock_performance_governor, measure_rate_workload
)

def main():
    lock_performance_governor()
    results = []

    matrix = [
        # (traffic, rate_mbps, coalesce_ms)
        ("UDP", 20, 0),
        ("UDP", 20, 1),
        ("UDP", 20, 2),
        ("UDP", 50, 0),
        ("UDP", 50, 1),
        ("UDP", 50, 2),
        ("TCP", 20, 0),
        ("TCP", 20, 1),
        ("TCP", 20, 2),
    ]

    try:
        for traffic, rate, coal in matrix:
            res = measure_rate_workload(
                traffic_type=traffic,
                target_rate_mbps=rate,
                runtime_mode="current_thread",
                workers=1,
                duration=6,
                coalesce_ms=coal,
            )
            results.append(res)

        out_path = "docs/coalescing_matrix_results.json"
        with open(out_path, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n[OK] Coalescing matrix results written to {out_path}")

    finally:
        cleanup()

if __name__ == "__main__":
    main()
