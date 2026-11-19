"""Network Interface Discovery for NIDS.

Provides platform-aware interface enumeration (specifically tailored for Windows 10/11)
using Scapy and Npcap driver queries, presenting friendly names, device identifiers,
and network addresses without initiating captures.
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger("nids.capture.interfaces")


@dataclass
class NetworkInterface:
    """Represents a network interface identified on the host system."""
    name: str
    description: str
    scapy_name: str
    ips: List[str] = field(default_factory=list)
    mac: Optional[str] = None
    is_loopback: bool = False

    def to_dict(self) -> Dict[str, object]:
        """Convert interface attributes to dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "scapy_name": self.scapy_name,
            "ips": self.ips,
            "mac": self.mac,
            "is_loopback": self.is_loopback,
        }

    def __str__(self) -> str:
        ip_str = ", ".join(self.ips) if self.ips else "No IP"
        return f"[{self.name}] {self.description} (Device: {self.scapy_name}, IPs: {ip_str})"


def get_available_interfaces() -> List[NetworkInterface]:
    """Retrieve all available network interfaces using Scapy.

    Queries Scapy and Windows adapter information to combine friendly names
    (e.g., 'Wi-Fi', 'Ethernet') with Scapy device identifiers (e.g., '\\Device\\NPF_...').

    Returns:
        List[NetworkInterface]: List of discovered network interfaces.
    """
    interfaces: List[NetworkInterface] = []
    seen_scapy_names = set()

    try:
        import scapy.all as scapy_all
        from scapy.arch.windows import get_windows_if_list
    except ImportError as exc:
        logger.error("Scapy is not installed or importable: %s", exc)
        return interfaces

    # Step 1: Query Windows interfaces if on Windows
    windows_ifaces = []
    try:
        windows_ifaces = get_windows_if_list()
    except Exception as exc:
        logger.warning("Failed to query get_windows_if_list(): %s", exc)

    # Map Windows adapters
    for w_if in windows_ifaces:
        guid = w_if.get("guid", "")
        # Scapy Npcap device identifier format
        scapy_dev = f"\\Device\\NPF_{guid}" if guid and not guid.startswith("\\Device\\") else guid
        name = w_if.get("name") or "Unnamed Adapter"
        description = w_if.get("description") or "Network Adapter"
        ips = [str(ip) for ip in w_if.get("ips", [])]
        mac = w_if.get("mac")
        is_loop = "loopback" in description.lower() or "loopback" in name.lower()

        if scapy_dev:
            seen_scapy_names.add(scapy_dev.lower())

        interfaces.append(
            NetworkInterface(
                name=name,
                description=description,
                scapy_name=scapy_dev or name,
                ips=ips,
                mac=mac,
                is_loopback=is_loop,
            )
        )

    # Step 2: Query Scapy's direct if_list to catch loopback & NPF devices not listed above
    try:
        scapy_ifaces = scapy_all.get_if_list()
        for s_if in scapy_ifaces:
            s_lower = s_if.lower()
            if s_lower not in seen_scapy_names:
                is_loop = "loopback" in s_lower or "npf_loopback" in s_lower
                desc = "Software Loopback Interface" if is_loop else "Scapy Network Device"
                name = "Loopback" if is_loop else s_if
                interfaces.append(
                    NetworkInterface(
                        name=name,
                        description=desc,
                        scapy_name=s_if,
                        ips=["127.0.0.1", "::1"] if is_loop else [],
                        is_loopback=is_loop,
                    )
                )
                seen_scapy_names.add(s_lower)
    except Exception as exc:
        logger.warning("Scapy get_if_list() failed: %s", exc)

    return interfaces


def find_interface(identifier: str) -> Optional[NetworkInterface]:
    """Find a network interface matching friendly name, description, Scapy device, or IP.

    Args:
        identifier: Search string (e.g., 'Wi-Fi', 'Ethernet', '192.168.1.10', '\\Device\\NPF_...').

    Returns:
        Optional[NetworkInterface]: Matching interface if found, else None.
    """
    if not identifier:
        return None

    cleaned_id = identifier.strip().lower()
    interfaces = get_available_interfaces()

    # Exact match checks
    for iface in interfaces:
        if cleaned_id in (iface.name.lower(), iface.scapy_name.lower()):
            return iface
        if any(cleaned_id == ip.lower() for ip in iface.ips):
            return iface

    # Substring / fuzzy match checks
    for iface in interfaces:
        if cleaned_id in iface.description.lower() or cleaned_id in iface.name.lower():
            return iface

    return None

