"""Device-level settings (hostname / DNS / NTP) carried cross-vendor into
FortiOS `config system global / dns / ntp`."""
from fwforge import pipeline
from fwforge.emit.fortios import device_system_lines
from fwforge.model import FirewallConfig
from fwforge.parsers import cisco_asa, juniper_srx, paloalto, pfsense

PAN = """<config version="11.0.0"><devices><entry name="localhost.localdomain">
<deviceconfig><system><hostname>pan-fw</hostname>
<dns-setting><servers><primary>10.1.1.1</primary>
<secondary>10.1.1.2</secondary></servers></dns-setting>
<ntp-servers><primary-ntp-server><ntp-server-address>10.2.2.1</ntp-server-address>
</primary-ntp-server><secondary-ntp-server>
<ntp-server-address>10.2.2.2</ntp-server-address></secondary-ntp-server></ntp-servers>
</system></deviceconfig>
<network><interface><ethernet><entry name="ethernet1/1"><layer3><ip>
<entry name="10.0.0.1/24"/></ip></layer3></entry></ethernet></interface></network>
<vsys><entry name="vsys1"><zone><entry name="t"><network><layer3>
<member>ethernet1/1</member></layer3></network></entry></zone></entry></vsys>
</entry></devices></config>"""

PF = """<pfsense><version>21.05</version><system><hostname>pf-fw</hostname>
<dnsserver>10.1.1.1</dnsserver><dnsserver>10.1.1.2</dnsserver>
<timeservers>0.pool.ntp.org 1.pool.ntp.org</timeservers></system>
<interfaces><wan><if>em0</if><ipaddr>10.0.0.1</ipaddr><subnet>24</subnet></wan>
</interfaces></pfsense>"""

ASA = """hostname asa-fw
dns server-group DefaultDNS
 name-server 10.1.1.1 10.1.1.2
ntp server 10.2.2.1
ntp server 10.2.2.2 prefer
interface GigabitEthernet0/0
 nameif outside
 ip address 10.0.0.1 255.255.255.0
"""

SRX = """system {
  host-name srx-fw;
  name-server { 10.1.1.1; 10.1.1.2; }
  ntp { server 10.2.2.1; server 10.2.2.2; }
}
"""


def test_pan_device_system_extracted():
    cfg = paloalto.parse(PAN, "p.xml")
    assert cfg.hostname == "pan-fw"
    assert cfg.dns_servers == ["10.1.1.1", "10.1.1.2"]
    assert cfg.ntp_servers == ["10.2.2.1", "10.2.2.2"]


def test_pfsense_device_system_extracted():
    cfg = pfsense.parse(PF, "pf.xml")
    assert cfg.hostname == "pf-fw"
    assert cfg.dns_servers == ["10.1.1.1", "10.1.1.2"]
    assert cfg.ntp_servers == ["0.pool.ntp.org", "1.pool.ntp.org"]


def test_asa_device_system_extracted():
    cfg = cisco_asa.parse(ASA, "asa.cfg")
    assert cfg.hostname == "asa-fw"
    assert cfg.dns_servers == ["10.1.1.1", "10.1.1.2"]   # nested under server-group
    assert cfg.ntp_servers == ["10.2.2.1", "10.2.2.2"]


def test_srx_device_system_extracted():
    cfg = juniper_srx.parse(SRX, "srx.conf")
    assert cfg.hostname == "srx-fw"
    assert cfg.dns_servers == ["10.1.1.1", "10.1.1.2"]
    assert cfg.ntp_servers == ["10.2.2.1", "10.2.2.2"]


def test_device_system_lines_emits_blocks():
    cfg = FirewallConfig(hostname="fw1", dns_servers=["1.1.1.1", "2.2.2.2"],
                         ntp_servers=["3.3.3.3"])
    txt = "\n".join(device_system_lines(cfg))
    assert 'config system global' in txt and 'set hostname "fw1"' in txt
    assert "config system dns" in txt
    assert "set primary 1.1.1.1" in txt and "set secondary 2.2.2.2" in txt
    assert "config system ntp" in txt and 'set server "3.3.3.3"' in txt


def test_device_system_lines_empty_when_absent():
    # no hostname/DNS/NTP -> no empty config blocks
    assert device_system_lines(FirewallConfig()) == []


def test_run_cross_emits_device_system_first():
    # the device-system block is wired into the pipeline and leads the config
    out = pipeline.run_cross(PAN, "paloalto", "p.xml", {}).out_text
    assert 'config system global' in out and 'set hostname "pan-fw"' in out
    assert "set primary 10.1.1.1" in out and 'set server "10.2.2.1"' in out
    # device settings precede the security config (zones)
    assert out.index("config system global") < out.index("config system zone")
