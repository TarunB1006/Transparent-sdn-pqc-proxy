# Reproducing the results

All numbers in the paper come from the files in `evaluation/results/`.
`analysis/analysis.py` and `analysis/make_figs.py` recompute the reported
statistics and figures from them. The commands below regenerate those files.

## Testbed

- QEMU virtual machine, 24 vCPUs, 24 GB RAM, Linux 6.8.
- The vCPU exposes AES-NI but not PCLMULQDQ or AVX2, so AES-GCM computes GHASH
  in software and liboqs uses its portable C code. Timings on bare metal will differ.
- Python 3.10.12, liboqs 0.15.0 (liboqs-python 0.15.0), Open vSwitch 2.17.9, Ryu 4.34, Mininet 2.3.
- TLS baselines: stunnel 5.82 built against OpenSSL 3.5.4 (native ML-KEM and ML-DSA).

## TLS baselines (only needed for the channel experiments)

`evaluation/mininet_bench.py` expects OpenSSL and stunnel under
`$PQC_OPT_DIR` (default: the directory above this repository, `../opt`):

```bash
OPT=$(realpath ..)/opt
# OpenSSL 3.5.4
curl -LO https://github.com/openssl/openssl/releases/download/openssl-3.5.4/openssl-3.5.4.tar.gz
tar xf openssl-3.5.4.tar.gz && cd openssl-3.5.4
./Configure --prefix="$OPT/openssl-3.5" --libdir=lib && make -j"$(nproc)" && make install_sw && cd ..
# stunnel 5.82 linked against it
curl -LO https://www.stunnel.org/archive/5.x/stunnel-5.82.tar.gz
tar xf stunnel-5.82.tar.gz && cd stunnel-5.82
./configure --prefix="$OPT/stunnel" --with-ssl="$OPT/openssl-3.5" LDFLAGS="-Wl,-rpath,$OPT/openssl-3.5/lib"
make -j"$(nproc)" && make install && cd ..
```

The harness generates every stunnel certificate (separate client and server
CAs, plus root/intermediate/leaf chains) itself. The fat-tree experiment's native
Open vSwitch TLS baseline needs `bash scripts/gen_ovs_tls_certs.sh`.

## Experiments

| Paper section | Command | Output |
|---|---|---|
| V-B Primitive cost (Table 4), multi-algorithm comparison; V-E cipher throughput (Fig. 6); Table 8 protocol tests (TVLA etc.) | `bash scripts/run_microbench.sh` | `evaluation/results/raw/*.csv` |
| V-C Handshake bytes (Table 5), delay and loss (Fig. 3) | `sudo -E PYTHON=$(which python) bash scripts/run_channel_bench.sh --reps 10 --exp wire,rtt` | `evaluation/results/mininet/wire.json`, `rtt_loss.json` |
| V-D Reconnection storms (Fig. 4), switch arrival (Fig. 5) | `... --reps 10 --exp storm,arrival` | `storm.json`, `storm_emu.json`, `arrival.json`, `arrival_emu.json` |
| V-E New-flow flood (Fig. 7a, b) | `... --reps 10 --exp flood` | `flood.json` |
| V-E Constrained-CPU flood (Fig. 7c, d) | `... --reps 10 --exp flood_constrained` | `flood_constrained.json` |
| V-F Traffic analysis (Table 6) | `... --reps 10 --exp ta` | `traffic_analysis.json` |
| V-G Live attack campaign (Table 7) | `bash scripts/run_live_attacks.sh` | `evaluation/results/raw/live_attacks.json` |
| V-H Fat-tree validation (Table 9) | `bash scripts/gen_ovs_tls_certs.sh && sudo -E PYTHON=$(which python) bash scripts/run_fat_tree.sh 5` | `evaluation/results/topo_final/` |

Run `--pilot` first for a quick (1 to 2 repetitions, reduced grid) check of the
channel bench. The full channel bench with 10 repetitions takes many hours.

## Statistics

`analysis/analysis.py <section ...>` prints the values reported in the paper:
`wire`, `rtt`, `rtt_tests` (Welch + Holm), `storm`, `arrival`, `flood`,
`flood_tests` (Welch + Holm, TOST), `topo` (fat-tree ping and throughput tests).
Means over repetitions are reported with 95% t-intervals.

## Notes

- The registration-time experiments use an instrumented OpenFlow client
  (`*_emu` files) to exclude Open vSwitch's reconnection timers. Bytes on the
  wire, CPU time, floods and traffic analysis use real Open vSwitch switches.
- The fat-tree harness waits for a counter of the management service before
  timing convergence. That service was disabled, so no convergence time was
  obtained for the proxied configurations, and the paper reports only ping and
  throughput for them.
