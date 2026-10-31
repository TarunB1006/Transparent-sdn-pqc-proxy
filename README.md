# Transparent SDN PQC Proxy

A transparent post-quantum proxy pair for the OpenFlow control channel between
Open vSwitch switches and a Ryu controller. Neither the switch nor the
controller is modified.

```
Open vSwitch ──plain OpenFlow──▶ sw_proxy_async ══ post-quantum tunnel ══▶ ctrl_proxy ──plain OpenFlow──▶ Ryu
   (local)          :6634                         untrusted network          :6652            (local)     :6653
```

- **Key establishment:** ML-KEM-1024 (FIPS 203), one round trip, ephemeral per connection.
- **Mutual authentication:** ML-DSA-87 (FIPS 204). The controller proxy key is pinned on every
  switch proxy; switch-proxy keys are allowlisted on the controller proxy.
- **Record layer:** AEAD (AES-256-GCM, AES-128-GCM or ChaCha20-Poly1305) with padding to
  fixed blocks, sequence and epoch bound into the tag, and a per-frame cipher identifier.
  It is fail-closed: any bad frame closes the connection.
- **DSCP policy:** the DSCP of the packet inside each PACKET_IN/PACKET_OUT selects the AEAD
  cipher for that frame. A per-flow baseline detects and blocks downgrade by remarking.
  A fixed-cipher mode bypasses the policy.

This repository contains the code, the evaluation harness and the raw results
behind the manuscript *A Transparent Post-Quantum Proxy for the SDN Control
Channel: Design and Live Adversarial Evaluation* (T. Bhupathi, Sravya D,
Varsha V P, Sneha M; RV College of Engineering, Bengaluru), currently under review.

## Repository layout

| Path | Contents |
|---|---|
| `src/pqc_sdn/apps/sw_proxy_async.py` | Switch-side proxy |
| `src/pqc_sdn/apps/ctrl_proxy.py` | Controller-side proxy |
| `src/pqc_sdn/crypto/`, `src/pqc_sdn/tls/` | ML-KEM / ML-DSA wrappers, handshake, key schedule, identities |
| `src/pqc_sdn/channel/` | Record layer (framing, padding, AEAD, sequence checks) |
| `src/pqc_sdn/policy/` | DSCP to cipher policy and downgrade baseline |
| `src/pqc_sdn/controller/`, `src/pqc_sdn/routing/` | Ryu application used for the fat-tree experiments |
| `tests/` | 130 automated tests, including a regression run of every live attack |
| `evaluation/` | Experiment harness (microbenchmarks, Mininet channel bench, live attacks, fat trees) |
| `evaluation/results/` | Raw results of the final runs reported in the paper |
| `analysis/` | Statistics (`analysis.py`) and figures (`make_figs.py`) computed from those results |
| `scripts/` | One script per experiment family |
| `benchmarks/` | Standalone exploratory benchmarks (not used for the paper's numbers) |

## Install

Tested on Ubuntu 22.04 with Python 3.10.12, liboqs 0.15.0, Open vSwitch 2.17.9,
Ryu 4.34 and Mininet 2.3.

```bash
python3 -m venv venv && . venv/bin/activate
pip install -r requirements.txt        # liboqs-python builds/loads liboqs 0.15.0
pip install -e .
```

## Quick start

```bash
# Unit, integration and live-attack regression tests (no root needed)
PYTHONPATH=src python -m pytest tests -q

# Run the two proxies in front of an existing Ryu controller on :6653
ryu-manager --ofp-tcp-listen-port 6653 ryu.app.simple_switch_13 &
PYTHONPATH=src python -m pqc_sdn.apps.ctrl_proxy &
PYTHONPATH=src python -m pqc_sdn.apps.sw_proxy_async &
# then point Open vSwitch at the switch-side proxy:
sudo ovs-vsctl set-controller br0 tcp:127.0.0.1:6634
```

Each proxy generates its ML-DSA-87 identity in `certs/` on first start
(secret keys with owner-only permissions). The switch proxy pins the controller
proxy's public key from `certs/ctrl_identity.pk`, or from
`proxy.pinned_identity_key` (hex) in `config/default.yaml`, and refuses to
connect without a pin. The controller proxy accepts only switch-proxy keys listed in
`certs/authorized_switches.txt` (hex, one key per line):

```bash
python -c "print(open('certs/sw_identity.pk','rb').read().hex())" >> certs/authorized_switches.txt
```

## Reproducing the paper

See [REPRODUCING.md](REPRODUCING.md) for the experiment commands, the
paper-to-file mapping and the testbed. To recompute every statistic and figure
from the shipped results without rerunning any experiment:

```bash
python analysis/analysis.py wire rtt rtt_tests storm arrival flood flood_tests topo
python analysis/make_figs.py            # figures/ (single-column width)
python analysis/make_figs.py --access   # figures/access/ (IEEE two-column widths)
```

## Known limitations

These match the limitations stated in the paper.

- The proxies are single-process Python. They serialize concurrent handshakes
  and recover large reconnection storms more slowly than stunnel.
- There is no in-band rekeying and no per-source handshake rate limiting.
- Key establishment is pure post-quantum, not hybrid.
- The handshake has not been verified in a symbolic model.
- The management API and dashboard (`src/pqc_sdn/apps/mgmt_api.py`,
  `deploy/`) are development tools. They were disabled in every experiment and
  ship with a fixed development token, so do not expose them on a network.

## License

MIT, see [LICENSE](LICENSE).
