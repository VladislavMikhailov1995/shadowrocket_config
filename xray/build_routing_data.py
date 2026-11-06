
#!/usr/bin/env python3
"""Build OneXray GeoSite/GeoIP DAT files with one stable PROXY category.

Clients permanently reference PROXY. Add source URLs below to expand VPN
routing without editing or reimporting their OneXray JSON profile.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import os
import tempfile
import urllib.request
from pathlib import Path


RAW = "https://raw.githubusercontent.com/itdoginfo/allow-domains/main"
DOMAIN_SOURCES = {
    "RUSSIA-INSIDE": f"{RAW}/Russia/inside-raw.lst",
    "GOOGLE-AI": f"{RAW}/Services/google_ai.lst",
    "GOOGLE-PLAY": f"{RAW}/Services/google_play.lst",
    "TELEGRAM": f"{RAW}/Services/telegram.lst",
}
IP_SOURCES = {
    "DISCORD": (f"{RAW}/Subnets/IPv4/discord.lst", f"{RAW}/Subnets/IPv6/discord.lst"),
    "META": (f"{RAW}/Subnets/IPv4/meta.lst", f"{RAW}/Subnets/IPv6/meta.lst"),
    "TELEGRAM": (f"{RAW}/Subnets/IPv4/telegram.lst", f"{RAW}/Subnets/IPv6/telegram.lst"),
    "TWITTER": (f"{RAW}/Subnets/IPv4/twitter.lst", f"{RAW}/Subnets/IPv6/twitter.lst"),
}
# A Shadowrocket list may contain domains and CIDRs in the same source. Its
# entries are parsed strictly, so a source-format change cannot silently add
# malformed rules to the routing data.
SHADOWROCKET_SOURCES = {
    "SPOTIFY": "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Shadowrocket/Spotify/Spotify.list",
}

DOMAIN_PLAIN = 0
DOMAIN_ROOT = 2
DOMAIN_FULL = 3
DomainRule = tuple[int, str]


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
    request = urllib.request.Request(url, headers={"User-Agent": "friends-routing-builder/1.0"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read().decode("utf-8")


def lines(url: str) -> list[str]:
    return [line.split("#", maxsplit=1)[0].strip() for line in fetch(url).splitlines()]


def domains(url: str) -> set[DomainRule]:
    # Xray RootDomain accepts suffix values without a leading dot.
    return {(DOMAIN_ROOT, value.lstrip(".").lower()) for value in lines(url) if value}


def networks(url: str) -> set[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    result = set()
    for line_number, value in enumerate(lines(url), start=1):
        if not value:
            continue
        try:
            result.add(ipaddress.ip_network(value, strict=True))
        except ValueError as exc:
            raise ValueError(f"{url}:{line_number}: invalid CIDR {value!r}") from exc
    return result


def shadowrocket_rules(
    url: str,
) -> tuple[set[DomainRule], set[ipaddress.IPv4Network | ipaddress.IPv6Network]]:
    """Parse the routing forms that can safely be represented in Xray DAT."""
    domain_values: set[DomainRule] = set()
    ip_values: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()
    domain_types = {
        "DOMAIN": DOMAIN_FULL,
        "DOMAIN-SUFFIX": DOMAIN_ROOT,
        "DOMAIN-KEYWORD": DOMAIN_PLAIN,
    }
    ignored_types = {"USER-AGENT"}

    for line_number, line in enumerate(lines(url), start=1):
        if not line:
            continue
        rule_type, separator, raw_value = line.partition(",")
        if not separator or not raw_value:
            raise ValueError(f"{url}:{line_number}: invalid Shadowrocket rule {line!r}")

        rule_type = rule_type.strip().upper()
        value = raw_value.split(",", maxsplit=1)[0].strip()
        if rule_type in domain_types:
            if not value or "," in value:
                raise ValueError(f"{url}:{line_number}: invalid domain {value!r}")
            domain_values.add((domain_types[rule_type], value.lstrip(".").lower()))
        elif rule_type in {"IP-CIDR", "IP-CIDR6"}:
            try:
                ip_values.add(ipaddress.ip_network(value, strict=True))
            except ValueError as exc:
                raise ValueError(f"{url}:{line_number}: invalid CIDR {value!r}") from exc
        elif rule_type in ignored_types:
            # Xray GeoSite/GeoIP has no User-Agent equivalent. The service's
            # hostname and CIDR rules still cover network traffic safely.
            continue
        else:
            raise ValueError(f"{url}:{line_number}: unsupported Shadowrocket rule {rule_type!r}")

    return domain_values, ip_values


def network_sort_key(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> tuple[int, int, int]:
    return network.version, int(network.network_address), network.prefixlen


def build_geosite(values: set[DomainRule]) -> bytes:
    # GeoSiteList { entry: GeoSite { country_code: "PROXY", domain: [...] } }
    geosite = bytearray(bytes_field(1, b"PROXY"))
    for domain_type, value in sorted(values, key=lambda item: (item[1], item[0])):
        domain = uint_field(1, domain_type) + bytes_field(2, value.encode("utf-8"))
        geosite.extend(bytes_field(2, domain))
    return bytes_field(1, bytes(geosite))


def build_geoip(values: set[ipaddress.IPv4Network | ipaddress.IPv6Network]) -> bytes:
    # GeoIPList { entry: GeoIP { country_code: "PROXY", cidr: [...] } }
    geoip = bytearray(bytes_field(1, b"PROXY"))
    for network in sorted(values, key=network_sort_key):
        cidr = bytes_field(1, network.network_address.packed) + uint_field(2, network.prefixlen)
        geoip.extend(bytes_field(2, cidr))
    return bytes_field(1, bytes(geoip))


def write_atomically(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as temporary:
        temporary.write(data)
        temporary_path = Path(temporary.name)
    os.replace(temporary_path, path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--geosite-output", type=Path, required=True)
    parser.add_argument("--geoip-output", type=Path, required=True)
    args = parser.parse_args()

    domain_values = set().union(*(domains(url) for url in DOMAIN_SOURCES.values()))
    ip_values = set().union(*(networks(url) for urls in IP_SOURCES.values() for url in urls))
    for url in SHADOWROCKET_SOURCES.values():
        source_domains, source_networks = shadowrocket_rules(url)
        domain_values.update(source_domains)
        ip_values.update(source_networks)
    geosite_data = build_geosite(domain_values)
    geoip_data = build_geoip(ip_values)
    write_atomically(args.geosite_output, geosite_data)
    write_atomically(args.geoip_output, geoip_data)

    print(f"PROXY domains: {len(domain_values)}")
    print(f"PROXY CIDRs: {len(ip_values)}")
    print(f"Wrote {args.geosite_output} ({len(geosite_data)} bytes; sha256={hashlib.sha256(geosite_data).hexdigest()})")
    print(f"Wrote {args.geoip_output} ({len(geoip_data)} bytes; sha256={hashlib.sha256(geoip_data).hexdigest()})")


if __name__ == "__main__":
    main()
