from __future__ import annotations

from functools import lru_cache

# Small built-in map for common virtualization and OT NIC prefixes.
KNOWN_OUIS = {
    "000569": "VMware",
    "000C29": "VMware",
    "001C14": "VMware",
    "005056": "VMware",
    "080027": "Oracle VirtualBox",
    "525400": "QEMU/KVM",
    "00155D": "Microsoft Hyper-V",
    "0003FF": "Schneider Electric",
    "0027E3": "WAGO",
    "000A45": "Rockwell Automation",
    "000F73": "Siemens AG",
}


@lru_cache(maxsize=4096)
def normalize_mac(mac: str) -> str:
    return mac.replace(":", "").replace("-", "").upper()


@lru_cache(maxsize=4096)
def lookup_oui_vendor(mac: str) -> str | None:
    norm = normalize_mac(mac)
    if len(norm) < 6:
        return None
    return KNOWN_OUIS.get(norm[:6])


def is_virtualization_vendor(vendor: str | None) -> bool:
    if not vendor:
        return False
    text = vendor.lower()
    markers = ["vmware", "virtualbox", "qemu", "kvm", "hyper-v", "xen"]
    return any(marker in text for marker in markers)
