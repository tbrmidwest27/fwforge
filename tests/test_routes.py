import ipaddress

from fwforge.model import Address, FirewallConfig, Interface, Policy, Route
from fwforge.report import Report
from fwforge.transforms.routes import _addr_networks, infer_dst_zones


def test_range_summarized_not_just_endpoints():
    cfg = FirewallConfig()
    cfg.addresses = [Address(name="rng", type="range",
                             value="10.0.0.10-10.0.10.10")]
    nets = _addr_networks(cfg, "rng", set())
    # an interior address (10.0.5.x) is covered, not just the two /32 endpoints
    assert any(ipaddress.IPv4Address("10.0.5.20") in n for n in nets)


def test_range_unrouted_interior_falls_back():
    # both endpoints resolve to portA, but the range's interior (10.0.5.x) has
    # no route at all -> summarizing the whole range surfaces the gap and falls
    # back to 'any'. Regression: endpoint-only resolution inferred portA and
    # silently missed the unroutable middle.
    cfg = FirewallConfig()
    cfg.routes = [Route(dest="10.0.0.0/24", interface="portA"),
                  Route(dest="10.0.9.0/24", interface="portA")]
    cfg.addresses = [Address(name="rng", type="range",
                             value="10.0.0.10-10.0.9.10")]
    cfg.policies = [Policy(name="p", dst_addrs=["rng"])]
    infer_dst_zones(cfg, Report())
    assert cfg.policies[0].dst_zones == ["any"]


def test_range_within_one_subnet_still_infers():
    # a range fully inside one connected subnet still infers that interface
    cfg = FirewallConfig()
    cfg.interfaces = [Interface(name="portA", ip="10.0.0.1/24")]
    cfg.addresses = [Address(name="rng", type="range",
                             value="10.0.0.10-10.0.0.20")]
    cfg.policies = [Policy(name="p", dst_addrs=["rng"])]
    infer_dst_zones(cfg, Report())
    assert cfg.policies[0].dst_zones == ["portA"]
