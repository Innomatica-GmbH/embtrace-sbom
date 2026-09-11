"""FPGA IP-core scanners — Vivado handoff (.hwh) and IP config (.xci).

Fixtures are trimmed extracts of real Digilent reference designs
(Zybo-Z7-20-base-linux), not invented markup: the VLNV attribute is the
IP-XACT / IEEE-1685 identifier every FPGA IP core carries.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from embtrace_sbom.sbom.scanner import scan_directory, scan_vivado_hwh, scan_vivado_xci

if TYPE_CHECKING:
    from pathlib import Path

HWH = """<?xml version="1.0" encoding="UTF-8"?>
<EDKSYSTEM>
  <MODULES>
    <MODULE FULLNAME="/axi_vdma_0" VLNV="xilinx.com:ip:axi_vdma:6.3"/>
    <MODULE FULLNAME="/dvi2rgb_0" VLNV="digilentinc.com:ip:dvi2rgb:1.8"/>
    <MODULE FULLNAME="/axi_i2s_adi_0" VLNV="analog.com:user:axi_i2s_adi:1.0"/>
    <MODULE FULLNAME="/dup_of_vdma" VLNV="xilinx.com:ip:axi_vdma:6.3"/>
    <BUSINTERFACE VLNV="xilinx.com:interface:aximm:1.0"/>
  </MODULES>
</EDKSYSTEM>
"""

XCI = """<?xml version="1.0" encoding="UTF-8"?>
<spirit:design xmlns:spirit="http://www.spiritconsortium.org/XMLSchema/SPIRIT/1685-2009">
  <spirit:componentInstances>
    <spirit:componentInstance>
      <spirit:instanceName>system_PS_GPIO_0_0</spirit:instanceName>
      <spirit:componentRef spirit:vendor="xilinx.com" spirit:library="ip"
                           spirit:name="xlslice" spirit:version="1.0"/>
    </spirit:componentInstance>
  </spirit:componentInstances>
</spirit:design>
"""


def test_hwh_yields_ip_cores_with_supplier_and_version(tmp_path: Path) -> None:
    f = tmp_path / "system.hwh"
    f.write_text(HWH, encoding="utf-8")
    deps = scan_vivado_hwh(f)

    by_name = {d.name: d for d in deps}
    assert by_name["axi_vdma"].version == "6.3"
    assert by_name["axi_vdma"].supplier == "xilinx.com"
    assert by_name["axi_vdma"].ecosystem == "fpga-ip"
    # Third-party IP is the actual supply-chain point
    assert by_name["dvi2rgb"].supplier == "digilentinc.com"
    assert by_name["axi_i2s_adi"].supplier == "analog.com"


def test_hwh_deduplicates_instances_and_drops_bus_interfaces(tmp_path: Path) -> None:
    """A core instantiated ten times is ONE component; bus interfaces are
    specifications, not delivered parts."""
    f = tmp_path / "system.hwh"
    f.write_text(HWH, encoding="utf-8")
    deps = scan_vivado_hwh(f)

    assert [d.name for d in deps].count("axi_vdma") == 1
    assert "aximm" not in {d.name for d in deps}
    assert len(deps) == 3


def test_purl_carries_vendor_namespace(tmp_path: Path) -> None:
    """Same core name from two vendors must stay distinguishable in the purl."""
    f = tmp_path / "system.hwh"
    f.write_text(HWH, encoding="utf-8")
    deps = {d.name: d for d in scan_vivado_hwh(f)}
    assert deps["axi_vdma"].purl == "pkg:generic/xilinx.com/axi_vdma@6.3"
    assert deps["dvi2rgb"].purl == "pkg:generic/digilentinc.com/dvi2rgb@1.8"


def test_xci_reads_component_ref(tmp_path: Path) -> None:
    f = tmp_path / "core.xci"
    f.write_text(XCI, encoding="utf-8")
    deps = scan_vivado_xci(f)

    assert len(deps) == 1
    assert (deps[0].name, deps[0].version, deps[0].supplier) == (
        "xlslice", "1.0", "xilinx.com",
    )


def test_autodetect_finds_handoff_deep_in_build_tree(tmp_path: Path) -> None:
    """Vivado buries the handoff (src/bd/<design>/hw_handoff/), it is not in
    the project root — discovery is by suffix, recursively."""
    d = tmp_path / "src" / "bd" / "system" / "hw_handoff"
    d.mkdir(parents=True)
    (d / "system.hwh").write_text(HWH, encoding="utf-8")

    deps = scan_directory(tmp_path)
    assert {x.name for x in deps if x.ecosystem == "fpga-ip"} == {
        "axi_vdma", "dvi2rgb", "axi_i2s_adi",
    }


def test_xci_skipped_when_handoff_present(tmp_path: Path) -> None:
    """Otherwise every core would appear twice in the inventory."""
    hw = tmp_path / "hw_handoff"
    hw.mkdir()
    (hw / "system.hwh").write_text(HWH, encoding="utf-8")
    ip = tmp_path / "ip" / "core_0"
    ip.mkdir(parents=True)
    (ip / "core_0.xci").write_text(XCI, encoding="utf-8")

    deps = scan_directory(tmp_path)
    assert "xlslice" not in {d.name for d in deps}


def test_sweep_prunes_vcs_and_venv_dirs(tmp_path: Path) -> None:
    """The suffix sweep must not crawl .git or virtualenvs."""
    hidden = tmp_path / ".git" / "objects"
    hidden.mkdir(parents=True)
    (hidden / "stray.hwh").write_text(HWH, encoding="utf-8")
    venv = tmp_path / ".venv" / "lib"
    venv.mkdir(parents=True)
    (venv / "stray.hwh").write_text(HWH, encoding="utf-8")

    assert [d for d in scan_directory(tmp_path) if d.ecosystem == "fpga-ip"] == []


def test_broken_file_does_not_abort_scan(tmp_path: Path) -> None:
    f = tmp_path / "broken.hwh"
    f.write_text('<EDKSYSTEM><MODULE VLNV="nur:drei:teile"/></EDKSYSTEM>', encoding="utf-8")
    assert scan_vivado_hwh(f) == []


LIBERO_TCL = """# Exported component description
create_and_configure_core -core_vlnv {Actel:DirectCore:COREI2C:*} \
    -component_name {COREI2C_C0} -params { "I2C_NUM:1" }
create_and_configure_core -core_vlnv {Actel:DirectCore:CORERESET_PF:*} \
    -component_name {CORERESET} -params { }
create_and_configure_core -core_vlnv {Microchip:SolutionCore:PF_SOC:2.1} \
    -component_name {SOC} -params { }
"""

QUARTUS_HW_TCL = """package require qsys 14.0
set_module_property NAME axi_dmac
set_module_property DESCRIPTION "AXI DMA Controller"
set_module_property VERSION 1.0
set_module_property GROUP "Analog Devices"
set_module_property DISPLAY_NAME axi_dmac
"""


def test_libero_wildcard_version_reported_empty_never_guessed(tmp_path: Path) -> None:
    """Libero pins no version ('*') — honest empty version + note, per BSI
    the audit must be able to flag it; guessing the catalog version is wrong."""
    from embtrace_sbom.sbom.scanner import scan_fpga_tcl

    f = tmp_path / "COREI2C_C0.tcl"
    f.write_text(LIBERO_TCL, encoding="utf-8")
    deps = {d.name: d for d in scan_fpga_tcl(f)}

    assert deps["COREI2C"].version == ""
    assert deps["COREI2C"].supplier == "Actel"
    assert "not pinned" in (deps["COREI2C"].description or "")
    assert deps["COREI2C"].purl == "pkg:generic/Actel/COREI2C"  # no @version
    # A pinned VLNV keeps its concrete version
    assert deps["PF_SOC"].version == "2.1"
    assert deps["PF_SOC"].purl == "pkg:generic/Microchip/PF_SOC@2.1"


def test_quartus_hw_tcl_module_properties(tmp_path: Path) -> None:
    from embtrace_sbom.sbom.scanner import scan_fpga_tcl

    f = tmp_path / "axi_dmac_hw.tcl"
    f.write_text(QUARTUS_HW_TCL, encoding="utf-8")
    deps = scan_fpga_tcl(f)

    assert len(deps) == 1
    d = deps[0]
    assert (d.name, d.version, d.supplier) == ("axi_dmac", "1.0", "Analog Devices")
    assert d.ecosystem == "fpga-ip"
    assert d.purl == "pkg:generic/Analog%20Devices/axi_dmac@1.0"


def test_plain_tcl_without_ip_markers_yields_nothing(tmp_path: Path) -> None:
    from embtrace_sbom.sbom.scanner import scan_fpga_tcl

    f = tmp_path / "build.tcl"
    f.write_text("puts hello\nsource other.tcl\n", encoding="utf-8")
    assert scan_fpga_tcl(f) == []


def test_sweep_finds_libero_components_dir(tmp_path: Path) -> None:
    d = tmp_path / "script_support" / "components"
    d.mkdir(parents=True)
    (d / "COREI2C_C0.tcl").write_text(LIBERO_TCL, encoding="utf-8")

    deps = [x for x in scan_directory(tmp_path) if x.ecosystem == "fpga-ip"]
    assert {x.name for x in deps} == {"COREI2C", "CORERESET_PF", "PF_SOC"}


CXF_THIRD_PARTY = (
    '<?xml version="1.0" encoding="UTF-8" standalone="no" ?>'
    '<Component xmlns="http://actel.com/sweng/afi">'
    "<name>CORERESET_PF</name><vendor>Actel</vendor>"
    "<library>DirectCore</library><version>2.3.100</version>"
    "<fileSets/><hwModel><views/></hwModel></Component>"
)

CXF_FIRST_PARTY_SMARTDESIGN = (
    '<?xml version="1.0" encoding="UTF-8" standalone="no" ?>'
    '<Component xmlns="http://actel.com/sweng/afi">'
    "<name>sp</name><vendor/><library/><version/>"
    "<category>SmartCoreDesign</category>"
    "<vendor>Actel</vendor><version>1.0</version>"
    "</Component>"
)


def test_cxf_resolves_generated_core_version(tmp_path: Path) -> None:
    from embtrace_sbom.sbom.scanner import scan_libero_cxf

    f = tmp_path / "CORERESET_PF.cxf"
    f.write_text(CXF_THIRD_PARTY, encoding="utf-8")
    deps = scan_libero_cxf(f)
    assert len(deps) == 1
    assert (deps[0].name, deps[0].version, deps[0].supplier) == (
        "CORERESET_PF", "2.3.100", "Actel",
    )


def test_cxf_skips_first_party_smartdesign(tmp_path: Path) -> None:
    """Own SmartDesigns carry EMPTY vendor/library/version first (measured) —
    they are the user's code, not supplied IP."""
    from embtrace_sbom.sbom.scanner import scan_libero_cxf

    f = tmp_path / "sp.cxf"
    f.write_text(CXF_FIRST_PARTY_SMARTDESIGN, encoding="utf-8")
    assert scan_libero_cxf(f) == []


def test_post_build_enrichment_merges_script_wildcard_with_cxf(tmp_path: Path) -> None:
    """Script says CORERESET_PF:* — generated .cxf resolves 2.3.100. The SBOM
    gets ONE entry, versioned; the unpinned script entry is superseded."""
    scripts = tmp_path / "script_support" / "components"
    scripts.mkdir(parents=True)
    (scripts / "CORERESET.tcl").write_text(
        "create_and_configure_core -core_vlnv {Actel:DirectCore:CORERESET_PF:*} \\\n"
        "    -component_name {CORERESET} -params { }\n",
        encoding="utf-8",
    )
    gen = tmp_path / "component" / "Actel" / "DirectCore" / "CORERESET_PF" / "2.3.100"
    gen.mkdir(parents=True)
    (gen / "CORERESET_PF.cxf").write_text(CXF_THIRD_PARTY, encoding="utf-8")

    deps = [d for d in scan_directory(tmp_path) if d.ecosystem == "fpga-ip"]
    assert len(deps) == 1
    assert deps[0].version == "2.3.100"
    assert "generated component data" in (deps[0].description or "")
