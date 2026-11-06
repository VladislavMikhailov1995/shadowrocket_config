#!/usr/bin/env python3
"""Build an Xray-compatible geoip.dat from itdoginfo public CIDR lists."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import os
import tempfile
import urllib.request
from pathlib import Path


BASE = "https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Subnets"
SOURCES = {
    "DISCORD": (f"{BASE}/IPv4/discord.lst", f"{BASE}/IPv6/discord.lst"),
    "META": (f"{BASE}/IPv4/meta.lst", f"{BASE}/IPv6/meta.lst"),
    "TELEGRAM": (f"{BASE}/IPv4/telegram.lst", f"{BASE}/IPv6/telegram.lst"),
    "TWITTER": (f"{BASE}/IPv4/twitter.lst", f"{BASE}/IPv6/twitter.lst"),
}


def varint(value: int) -> bytes:
    result = bytearray()
    while value > 0x7F:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def bytes_field(number: int, value: bytes) -> bytes:
    return varint((number << 3) | 2) + varint(len(value)) + value


def uint_field(number: int, value: int) -> bytes:
    return varint(number << 3) + varint(value)


def fetch(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "xray-geoip-builder/1.0"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8")


def networks(url: str) -> set[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    result = set()
    for line_number, line in enumerate(fetch(url).splitlines(), start=1):
        value = line.split("#", maxsplit=1)[0].strip()
        if not value:
            continue
        try:
            result.add(ipaddress.ip_network(value, strict=True))
        except ValueError as exc:
            raise ValueError(f"{url}:{line_number}: invalid CIDR {value!r}") from exc
    return result


def sort_key(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> tuple[int, int, int]:
    return network.version, int(network.network_address), network.prefixlen


def build() -> tuple[bytes, dict[str, int]]:
    result = bytearray()
    counts = {}
    for code, urls in SOURCES.items():
        values = set().union(*(networks(url) for url in urls))
        counts[code] = len(values)
        geoip = bytearray(bytes_field(1, code.encode("ascii")))
        for network in sorted(values, key=sort_key):
            cidr = bytes_field(1, network.network_address.packed) + uint_field(2, network.prefixlen)
            geoip.extend(bytes_field(2, cidr))
        result.extend(bytes_field(1, bytes(geoip)))
    return bytes(result), counts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    data, counts = build()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=args.output.parent, delete=False) as temporary:
        temporary.write(data)
        temporary_path = Path(temporary.name)
    os.replace(temporary_path, args.output)
    summary = ", ".join(f"{code}={count}" for code, count in counts.items())
    print(f"Wrote {args.output} ({len(data)} bytes; sha256={hashlib.sha256(data).hexdigest()})")
    print(f"CIDRs: {summary}")


if __name__ == "__main__":
    main()
