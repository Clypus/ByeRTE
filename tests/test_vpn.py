"""byerte.vpn — VPN tüneli algılama birim testleri.

Gerçek `ip route` / PowerShell çağrısı yapılmaz; subprocess.run sahtelenir.
Amaç: ayrıştırma mantığı (çıkış arayüzü / adapter tipi-adı) ve fail-open davranışı.
"""

from __future__ import annotations

import subprocess
import unittest
from types import SimpleNamespace
from unittest import mock

from byerte import vpn


def _run_returning(stdout: str = "", exc: Exception | None = None):
    def _run(*_a, **_k):
        if exc is not None:
            raise exc
        return SimpleNamespace(stdout=stdout)
    return _run


class TunnelNameTest(unittest.TestCase):
    def test_physical_names_are_not_tunnels(self):
        for n in ["eth0", "wlan0", "en0", "enp3s0", "wlp2s0", "Ethernet", "Wi-Fi",
                  "Intel(R) Ethernet Connection", "Realtek PCIe GbE Family Controller",
                  "", None]:
            self.assertFalse(vpn.is_tunnel_iface(n), n)

    def test_tunnel_names_match(self):
        for n in ["tun0", "wg0", "ppp0", "proton0", "nordlynx", "ProtonVPN",
                  "WireGuard Tunnel", "TAP-Windows Adapter V9", "WAN Miniport (IKEv2)",
                  "OpenVPN Data Channel Offload", "Mullvad tunnel", "utun3"]:
            self.assertTrue(vpn.is_tunnel_iface(n), n)


class LinuxDetectTest(unittest.TestCase):
    def test_default_via_tunnel_is_vpn(self):
        out = "1.1.1.1 via 10.2.0.1 dev proton0 src 10.2.0.2 uid 1000\n    cache\n"
        with mock.patch.object(vpn.subprocess, "run", _run_returning(out)):
            self.assertTrue(vpn._linux_active())

    def test_default_via_physical_is_not_vpn(self):
        out = "1.1.1.1 via 192.168.1.1 dev wlan0 src 192.168.1.23 uid 1000\n    cache\n"
        with mock.patch.object(vpn.subprocess, "run", _run_returning(out)):
            self.assertFalse(vpn._linux_active())

    def test_no_dev_token(self):
        with mock.patch.object(vpn.subprocess, "run", _run_returning("unreachable\n")):
            self.assertFalse(vpn._linux_active())

    def test_subprocess_error_fails_open(self):
        with mock.patch.object(vpn.subprocess, "run",
                               _run_returning(exc=OSError("ip yok"))):
            self.assertFalse(vpn._linux_active())
        with mock.patch.object(vpn.subprocess, "run",
                               _run_returning(exc=subprocess.TimeoutExpired("ip", 3))):
            self.assertFalse(vpn._linux_active())


class WindowsDetectTest(unittest.TestCase):
    def test_tunnel_iftype_is_vpn(self):
        with mock.patch.object(vpn.subprocess, "run",
                               _run_returning("131|ProtonVPN|WireGuard Tunnel\n")):
            self.assertTrue(vpn._windows_active())

    def test_ppp_iftype_is_vpn(self):
        with mock.patch.object(vpn.subprocess, "run",
                               _run_returning("23|VPN|WAN Miniport (IKEv2)\n")):
            self.assertTrue(vpn._windows_active())

    def test_ethernet_is_not_vpn(self):
        with mock.patch.object(vpn.subprocess, "run",
                               _run_returning("6|Ethernet|Intel(R) Ethernet Connection\n")):
            self.assertFalse(vpn._windows_active())

    def test_wifi_is_not_vpn(self):
        with mock.patch.object(vpn.subprocess, "run",
                               _run_returning("71|Wi-Fi|Intel(R) Wi-Fi 6 AX201\n")):
            self.assertFalse(vpn._windows_active())

    def test_name_match_when_iftype_unknown(self):
        # Wintun bazen Ethernet(6) olarak görünür → ad/açıklamadan yakala.
        with mock.patch.object(vpn.subprocess, "run",
                               _run_returning("6|Mullvad|Wintun Userspace Tunnel\n")):
            self.assertTrue(vpn._windows_active())

    def test_empty_output_fails_open(self):
        with mock.patch.object(vpn.subprocess, "run", _run_returning("")):
            self.assertFalse(vpn._windows_active())

    def test_error_fails_open(self):
        with mock.patch.object(vpn.subprocess, "run",
                               _run_returning(exc=OSError("powershell yok"))):
            self.assertFalse(vpn._windows_active())


if __name__ == "__main__":
    unittest.main()
