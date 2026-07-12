# netguard

A streaming network telemetry engine with anomaly detection.
Written in C using libpcap and epoll. Personal project, work in progress.

## Overview
netguard captures live network traffic, tracks flows, and detects
anomalies (port scans, floods, tunneling) using probabilistic data
structures and information-theoretic methods. It also runs low-interaction
honeypot services and models attacker behavior.

## Build
    make            # normal build
    make asan       # build with AddressSanitizer

## Run
    sudo ./netguard [interface]

## Status
- [x] Live capture + Ethernet/IP/TCP/UDP parsing
- [x] Flow tracking
- [ ] Probabilistic data structures (Count-Min, HyperLogLog, Bloom)
- [ ] Entropy / change-point anomaly detection
- [ ] Honeypot services
- [ ] Attacker behavior modeling
