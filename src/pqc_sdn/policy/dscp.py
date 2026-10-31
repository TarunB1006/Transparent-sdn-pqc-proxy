"""DSCP codepoint definitions (RFC 2474 / 2597 / 3246)."""

from __future__ import annotations

import enum


class DscpClass(enum.IntEnum):
    BE = 0
    AF11 = 10
    AF12 = 12
    AF13 = 14
    AF21 = 18
    AF22 = 20
    AF23 = 22
    CS3 = 24
    AF31 = 26
    AF32 = 28
    AF33 = 30
    CS4 = 32
    AF41 = 34
    AF42 = 36
    AF43 = 38
    CS5 = 40
    EF = 46
    CS6 = 48
    CS7 = 56
    HIGH_SEC = 63

    @classmethod
    def from_value(cls, value: int) -> "DscpClass":
        try:
            return cls(value)
        except ValueError:
            return cls.BE


def extract_dscp(ip_tos: int) -> int:
    """Extract 6-bit DSCP from IPv4 ToS byte."""
    return (ip_tos >> 2) & 0x3F


def dscp_name(value: int) -> str:
    try:
        return DscpClass(value).name
    except ValueError:
        return f"DSCP-{value}"
