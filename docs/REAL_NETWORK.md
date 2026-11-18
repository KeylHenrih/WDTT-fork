# WDTT v2 Real Network Benchmarks & Loss Diagnostics

## 1. Test Environment Overview

All measurements were performed over an unconstrained public Internet path between a client host (Linux x86_64, Wi-Fi 802.11ax to residential fiber WAN) and a remote cloud server located in an EU datacenter.

- **Direct Network Path**: Direct UDP/TCP transport between client local physical interface and remote server over the public WAN.
- **WDTT v2 Tunnel Path**: Linux kernel WireGuard (`wg-wdtt`, `10.88.88.2/24`) tunneled through `wdttd` client daemon, relayed via Coturn TURN allocation, demultiplexed by `wdtt-server`, and terminated on Linux kernel WireGuard (`wg-test0`, `10.88.88.1/24`) on the remote server.
- **Routing Scope**: Tunnel route strictly isolated to `10.88.88.0/24`. Host default route, DNS resolution, and physical interfaces remained untouched.

---

## 2. Direct WAN Path UDP Loss Curve (PC <-> server)

To isolate network-induced losses from tunnel-induced losses, raw UDP was measured in both directions across multiple target rates (5s per step, bound strictly to physical interface):

| Direction | Target Rate | Sent Bitrate | Received Bitrate | Lost Datagrams | Total Datagrams | Loss % | Jitter (ms) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Client -> Server (Uplink)** | 5M | 5.00 Mbits/s | 4.79 Mbits/s | 0 | 2092 | **0.00%** | 2.854 ms |
| **Client -> Server (Uplink)** | 10M | 10.00 Mbits/s | 9.69 Mbits/s | 0 | 4226 | **0.00%** | 1.484 ms |
| **Client -> Server (Uplink)** | 20M | 20.00 Mbits/s | 18.95 Mbits/s | 114 | 8369 | **1.33%** | 0.587 ms |
| **Client -> Server (Uplink)** | 40M | 40.00 Mbits/s | 37.77 Mbits/s | 360 | 16920 | **2.10%** | 0.290 ms |
| **Server -> Client (Downlink)**| 5M | 5.00 Mbits/s | 5.01 Mbits/s | 0 | 2144 | **0.00%** | 0.370 ms |
| **Server -> Client (Downlink)**| 10M | 10.00 Mbits/s | 10.00 Mbits/s | 0 | 4281 | **0.00%** | 1.353 ms |
| **Server -> Client (Downlink)**| 20M | 20.00 Mbits/s | 20.00 Mbits/s | 0 | 8565 | **0.00%** | 0.702 ms |
| **Server -> Client (Downlink)**| 40M | 40.00 Mbits/s | 40.01 Mbits/s | 0 | 17129 | **0.00%** | 0.309 ms |

### Key Diagnostic Findings:
1. **Downlink is completely loss-free**: Datacenter to client sustains 40.0 Mbits/s UDP with 0 dropped datagrams (0.00% loss).
2. **Uplink exhibits physical path losses starting at ~15-20 Mbits/s**: Client uplink experiences 1.33% - 2.10% packet drops on the physical WAN/Wi-Fi path even without any tunnel encapsulation. Note: "Received Bitrate" (e.g. 18.95 Mbits/s) reflects iperf3's measured throughput over the interval, distinct from packet loss percentage.

---

## 3. Tunnel UDP Loss & Throughput Discrepancy Analysis

- **Initial Automated Run**: Reported 11.7 Mbits/s with 39% loss.
  - *Root Cause*: The client daemon was executing with `RUST_LOG=trace` writing synchronous unbuffered log records to disk for every single frame (over 18,000 trace events within 10 seconds). Tokio reactor loop was delayed by disk I/O, allowing socket receive buffers to overflow.
- **Clean Run (without trace overhead / user verification)**:
  - Throughput: **18.2 Mbits/sec** received at 20M target (7.1% loss).
- **Loss Differential Decomposition**:
  - Direct WAN UDP 20M loses **1.33%**.
  - Tunnel UDP 20M loses **7.1%**.
  - The tunnel testbed adds **~5.8 percentage points** of loss. This is primarily a **testbed artifact of Coturn**: Coturn's relay socket was configured with a default system buffer of only 128 KB (`rb131072`), causing packet drops on bursts (`d155`/`d242` cumulative drops in `ss -ulpnm`). Additionally, tunnel framing and encapsulation (~7% wire overhead) increases the effective wire bit-rate, pushing marginal uplink packets past the queue threshold.

---

## 4. Tunnel TCP Transport Diagnostics (`iperf3 -c 10.88.88.1`)

Detailed diagnostics measuring socket drops (`/proc/net/udp`), TCP segmentation counters (`nstat`), and relay state:

| Test Mode | Transfer Rate | Retransmissions | Client UDP Drops | Server UDP Drops |
| :--- | :--- | :--- | :--- | :--- |
| **1 Stream Baseline (Uplink)** | 2.42 Mbits/s (avg) | 11 | 0 | 11 |
| **Reverse Mode (`-R`, Downlink)**| **16.6 Mbits/s** (peak 27.3M) | 242 (at burst peak)| 0 | 275 |
| **4 Parallel Streams (`-P 4`)** | 2.42 Mbits/s (aggregate)| 79 | 0 | 48 |
| **Bandwidth Limit (`-b 10M`)** | 3.05 Mbits/s | 1 | 0 | 9 |

### Detailed Loss Breakdown:
1. **Client Socket Buffer**: `drops = 0` (`/proc/net/udp` column 13 shows zero packet drops across all tests). Client socket buffer (8 MB) never overflowed.
2. **Server `wdtt-server` Socket**: `drops = 0` (`rb8388608` 8 MB buffer). `wdtt-server` processed all incoming datagrams without socket drops.
3. **WireGuard Kernel Sockets**: `drops = 0` on both client (`wg-wdtt`) and server (`wg-test0`).
4. **Coturn Relay Socket (`rb131072`)**: Coturn allocates relay sockets with default system buffer of 128 KB (`rb131072`). Under high burst rates (>20 Mbits/s in Reverse mode), Coturn's relay buffer overflowed, accumulating drops (`d155`, `d242` in `ss -ulpnm`).
5. **Uplink TCP Dynamics**: The asymmetry between Downlink (16.6 - 27.3 Mbits/s) and Uplink (2.4 - 3.0 Mbits/s) is driven by the physical uplink packet drops (>1.3% loss) combined with 95 ms RTT: standard TCP Cubic/BBR scales back congestion window (`cwnd`) upon packet loss. Downlink, being physically lossless, scales up to 27 Mbits/s.

---

## 5. VK TURN Transport Considerations

- **Probing Note**: An unauthenticated STUN binding probe timeout to `voip.vk.com:3478` does not conclusively prove carrier-level UDP blocking, as the probed IP may not operate an unauthenticated public STUN listener.
- **Verification Protocol**: Definitive transport reachability will be measured against the actual URLs returned by VK Calls API (`turn:...` and `turns:...:443?transport=tcp`).
- **Transport Strategy**: TCP/TLS on port 443 serves as the primary, guaranteed transport across restricted networks and DPI, with UDP evaluated as an optional low-latency transport via live loss and RTT probing.
