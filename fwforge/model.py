"""Intermediate representation (IR) for firewall configurations.

Every vendor parser produces a FirewallConfig; every emitter consumes one.
Cross-vendor conversion is lossy by nature — the rule here is that nothing
is dropped *silently*: whatever a parser cannot represent lands in
FirewallConfig.unparsed (with file/line provenance) and surfaces in the
conversion report.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SourceRef:
    """Provenance: where in the source config an IR object came from."""

    file: str = ""
    line: int = 0  # 1-based
    raw: str = ""  # the original line(s), trimmed

    def loc(self) -> str:
        return f"{self.file}:{self.line}" if self.file else f"line {self.line}"


@dataclass
class Interface:
    name: str  # vendor-side name (ASA nameif, FortiOS port)
    ip: str | None = None  # "192.0.2.1/24"
    description: str | None = None
    vlan_id: int | None = None
    parent: str | None = None  # physical parent for subinterfaces
    enabled: bool = True
    target_name: str | None = None  # FortiGate port after mapping
    # physical | aggregate | aggregate-member | vlan | loopback | tunnel
    kind: str = "physical"
    members: list[str] = field(default_factory=list)  # for aggregates
    lacp_mode: str | None = None  # active | passive | static (aggregates)
    source: SourceRef | None = None

    @property
    def mapped(self) -> str:
        return self.target_name or self.name


@dataclass
class Zone:
    """A security zone (PAN-OS zones map 1:1 to FortiOS zones)."""

    name: str
    members: list[str] = field(default_factory=list)  # interface names
    comment: str | None = None
    source: SourceRef | None = None


@dataclass
class Address:
    name: str
    type: str = "subnet"  # host | subnet | range | fqdn
    value: str = ""  # "10.0.0.1", "10.0.0.0/24", "10.0.0.1-10.0.0.9", "x.com"
    comment: str | None = None
    source: SourceRef | None = None


@dataclass
class AddressGroup:
    name: str
    members: list[str] = field(default_factory=list)
    comment: str | None = None
    source: SourceRef | None = None


@dataclass
class Service:
    name: str
    protocol: str = "tcp"  # tcp | udp | tcp/udp | icmp | ip
    dst_ports: str = ""  # "443", "8000-8080", "80 443"
    src_ports: str = ""
    icmp_type: int | None = None
    proto_number: int | None = None  # when protocol == "ip" (e.g. 47 = GRE)
    comment: str | None = None
    source: SourceRef | None = None

    def signature(self) -> tuple:
        """Definition identity, ignoring the name — used for dedup."""
        return (
            self.protocol,
            self.dst_ports,
            self.src_ports,
            self.icmp_type,
            self.proto_number,
        )


@dataclass
class ServiceGroup:
    name: str
    members: list[str] = field(default_factory=list)
    comment: str | None = None
    source: SourceRef | None = None


@dataclass
class AppList:
    """FortiOS application-control profile (from PAN App-ID conversion)."""

    name: str
    categories: list[int] = field(default_factory=list)
    cat_names: list[str] = field(default_factory=list)
    apps: list[str] = field(default_factory=list)  # source PAN app names
    source: SourceRef | None = None


@dataclass
class Policy:
    name: str = ""
    src_zones: list[str] = field(default_factory=list)  # interface/zone names
    dst_zones: list[str] = field(default_factory=list)
    src_addrs: list[str] = field(default_factory=list)  # object names or "all"
    dst_addrs: list[str] = field(default_factory=list)
    services: list[str] = field(default_factory=list)  # names or "ALL"
    action: str = "accept"  # accept | deny
    nat: bool = False  # source-NAT to outgoing interface
    log: bool = True
    disabled: bool = False
    src_negate: bool = False  # match everything EXCEPT src_addrs
    dst_negate: bool = False
    comment: str | None = None
    dst_inferred: bool = False  # dstintf derived from routing, not the source
    app_list: str = ""  # FortiOS application-list profile name (App-ID)
    family: int = 0  # 0 = derive from addresses, 4, or 6
    source: SourceRef | None = None


@dataclass
class Vip:
    """Static destination NAT (FortiOS virtual IP)."""

    name: str
    ext_ip: str = ""
    mapped_ip: str = ""
    ext_intf: str = ""  # vendor-side name; mapped later
    protocol: str | None = None  # tcp/udp when port-forwarding
    ext_port: str | None = None
    mapped_port: str | None = None
    comment: str | None = None
    source: SourceRef | None = None


@dataclass
class NatRule:
    """Source-NAT intent that is not a VIP (v1: interface PAT)."""

    kind: str = "dynamic-interface"
    real_obj: str = ""  # address object being translated
    real_ifc: str = ""
    mapped_ifc: str = ""
    source: SourceRef | None = None


@dataclass
class VpnPhase1:
    """Route-based IPsec phase1 (FortiOS phase1-interface)."""

    name: str  # becomes a FortiOS interface name — max 15 chars
    interface: str = ""  # egress interface (vendor name, mapped later)
    remote_gw: str = ""
    ike_version: int = 1
    proposals: list[str] = field(default_factory=list)  # enc-auth tokens
    dhgrp: list[str] = field(default_factory=list)
    psk: str = ""
    psk_remote: str = ""  # asymmetric IKEv2 PSK
    keylife: int = 0  # 0 = FortiOS default
    comment: str | None = None
    source: SourceRef | None = None


@dataclass
class VpnPhase2:
    name: str
    phase1: str = ""
    proposals: list[str] = field(default_factory=list)
    pfs_group: str = ""  # "" = PFS disabled (the ASA default!)
    src: str = ""  # CIDR
    dst: str = ""  # CIDR
    keylife: int = 0
    source: SourceRef | None = None


@dataclass
class Route:
    dest: str = "0.0.0.0/0"  # CIDR
    gateway: str = ""
    interface: str = ""  # vendor-side name; mapped later
    distance: int = 10
    comment: str | None = None
    source: SourceRef | None = None


@dataclass
class BgpNeighbor:
    ip: str
    remote_as: str = ""
    description: str | None = None
    has_password: bool = False  # source had auth; key not carried over
    source: SourceRef | None = None


@dataclass
class BgpConfig:
    asn: str = ""
    router_id: str = ""
    neighbors: list[BgpNeighbor] = field(default_factory=list)
    networks: list[str] = field(default_factory=list)  # announced CIDRs
    redistribute: list[str] = field(default_factory=list)  # connected/...
    source: SourceRef | None = None


@dataclass
class OspfArea:
    id: str = "0.0.0.0"  # dotted form
    networks: list[str] = field(default_factory=list)  # CIDRs in the area
    passive: list[str] = field(default_factory=list)  # interface names
    source: SourceRef | None = None


@dataclass
class OspfConfig:
    router_id: str = ""
    areas: list[OspfArea] = field(default_factory=list)
    redistribute: list[str] = field(default_factory=list)
    source: SourceRef | None = None


@dataclass
class FirewallConfig:
    """The IR root — everything a conversion knows about the source."""

    vendor: str = ""
    hostname: str = ""
    version: str = ""  # source OS version if detected
    zones: list[Zone] = field(default_factory=list)
    interfaces: list[Interface] = field(default_factory=list)
    addresses: list[Address] = field(default_factory=list)
    addr_groups: list[AddressGroup] = field(default_factory=list)
    services: list[Service] = field(default_factory=list)
    svc_groups: list[ServiceGroup] = field(default_factory=list)
    app_lists: list[AppList] = field(default_factory=list)
    policies: list[Policy] = field(default_factory=list)
    vips: list[Vip] = field(default_factory=list)
    nats: list[NatRule] = field(default_factory=list)
    phase1s: list[VpnPhase1] = field(default_factory=list)
    phase2s: list[VpnPhase2] = field(default_factory=list)
    routes: list[Route] = field(default_factory=list)
    bgp: BgpConfig | None = None
    ospf: OspfConfig | None = None
    unparsed: list[SourceRef] = field(default_factory=list)
    meta: dict = field(default_factory=dict)

    def interface_by_name(self, name: str) -> Interface | None:
        for itf in self.interfaces:
            if itf.name == name:
                return itf
        return None

    def address_by_name(self, name: str) -> Address | None:
        for a in self.addresses:
            if a.name == name:
                return a
        return None
