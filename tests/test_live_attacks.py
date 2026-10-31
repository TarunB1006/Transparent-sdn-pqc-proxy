"""Regression: run every live MITM scenario once against the real proxy pair."""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from evaluation.live_attacks import run_all  # noqa: E402

# Only the two negative controls (defense disabled) are expected to succeed.
EXPECTED_SUCCESS = {"mitm_impersonation_unpinned", "rogue_switch_mutual_off"}


def test_live_attack_matrix():
    rows = asyncio.run(run_all(trials=1))
    for row in rows:
        expected = 1 if row["scenario"] in EXPECTED_SUCCESS else 0
        assert row["attack_success"] == expected, row
