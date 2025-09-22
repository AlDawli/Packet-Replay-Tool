# Packet-Replay-Tool
invaluable for IDS/IPS testing, network troubleshooting, and controlled experiment repeatability

# Project objective
Build a toolkit that:
captures, organizes, and labels network traffic flows,
extracts specific flows (by 5-tuple or BPF filter),
replays those flows to test IDS/IPS, firewalls, or other network devices,
supports timing control, rate shaping, rewriting (IP/MAC), and anonymization,
records replay metadata for reproducibility and evaluation.

# Primary benefit: reproducible testcases so you can measure IDS/IPS detection accuracy and tuning impact.
Components & tools
Capture: tcpdump, tshark, Wireshark (pcap files)
Edit/Rewrite: tcprewrite (rewrite IPs/MACs, fix checksums, strip VLAN)
Replay: tcpreplay (replay pcap with speed/rate control, preserve timing)
Flow extraction: tshark / scapy / pyshark for automated slicing
Automation / orchestration: Bash or Python scripts
Measurement: tcpreplay stats, IDS/IPS alert logs, timestamped PCAPs, packet counters (if available on device)
Optional: netmap/af_xdp/dpdk for high-speed replay

# Test scenarios & experiments
Design experiments that exercise IDS/IPS capabilities:
1. Baseline replay: replay benign traffic at original timing; verify no alerts.
2. Detection sensitivity: replay malicious flow at original timing — expect detection.
3. Rate variation: replay malicious flow at 0.1x, 1x, 10x speed — measure detection vs rate.
4. Burst vs sustained: short high-rate bursts vs sustained medium-rate — observe IDS thresholds.
5. IP/MAC rewrite: test rule reliance on source IPs — rewrite source, see if IDS still catches content-based rules.
6. Inter-packet timing manipulation: split flows across time to evade simplistic signature-based correlation.
7. Fragmentation & reassembly: rewrite packets to fragment payloads; test IDS reassembly correctness.
8. Mix with noise: interleave malicious flow into large benign background to test false-negative risk.
9. Multicast/multiple sources: split same flow across several source IPs to emulate distributed attack.
10. High-speed stress: topspeed replays to measure IDS throughput and packet loss.

# Evaluation metrics (what to measure)
True Positive Rate (TPR): fraction of malicious replays that triggered expected alerts.
False Positive Rate (FPR): fraction of benign replays that triggered alerts.
Detection latency: time from packet replay to alert generation.
Throughput: packets/sec processed by IDS (before drop).
Packet loss: packets dropped by replay device or monitoring point (use tcpreplay --stats).
Reproducibility: ability to reproduce same alert pattern across runs.
Rule robustness: sensitivity to rewriting, timing changes, fragmentation.

