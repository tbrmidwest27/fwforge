from fwforge.model import FirewallConfig, Interface


def test_interface_by_name_index_and_invalidation():
    # interface_by_name uses a cached index for O(1) lookups; it must stay
    # correct as interfaces are added (the cache invalidates on a length
    # change) and preserve first-match semantics.
    cfg = FirewallConfig()
    cfg.interfaces = [Interface(name="a"), Interface(name="b")]
    assert cfg.interface_by_name("a").name == "a"
    assert cfg.interface_by_name("b").name == "b"
    assert cfg.interface_by_name("missing") is None
    # adding an interface must become visible (cache rebuilds on length change)
    cfg.interfaces.append(Interface(name="c"))
    assert cfg.interface_by_name("c").name == "c"
    assert cfg.interface_by_name("a").name == "a"
    # first-match semantics on a duplicate name (matches the old linear scan)
    first = Interface(name="dup", ip="10.0.0.1/24")
    cfg.interfaces.append(first)
    cfg.interfaces.append(Interface(name="dup", ip="10.0.9.1/24"))
    assert cfg.interface_by_name("dup") is first
