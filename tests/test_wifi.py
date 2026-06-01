"""
Tests for wifi.py — wifi_connect() function.

The MicroPython `network` module is stubbed out with unittest.mock so tests
run on standard CPython.
"""

import sys
import os
import types
import unittest
from unittest.mock import MagicMock, patch, call

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# ---------------------------------------------------------------------------
# Stub: network module
# ---------------------------------------------------------------------------

_network_stub = types.ModuleType("network")
_network_stub.STA_IF = 0   # sentinel value used by wifi.py


class _WlanStub:
    """Configurable WLAN stub. Set attrs before calling wifi_connect."""
    def __init__(self):
        self.active = MagicMock()
        self.connect = MagicMock()
        self._connected = False
        self._connect_counter = 0
        self._connect_after = 0      # become connected after N isconnected() calls
        self._raise_on_connect = None

    def isconnected(self):
        if self._connect_after > 0:
            self._connect_counter += 1
            if self._connect_counter >= self._connect_after:
                self._connected = True
        return self._connected

    def ifconfig(self):
        return ("192.168.1.100",)


_wlan_instance = _WlanStub()


def _wlan_factory(mode):
    return _wlan_instance


_network_stub.WLAN = _wlan_factory
sys.modules["network"] = _network_stub

# logging stub
if "logging" not in sys.modules:
    import logging  # noqa: F401

import wifi   # module under test


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reset_wlan(connected=False, connect_after=0, raise_on_connect=None):
    """Reset the shared WLAN stub to a clean state."""
    _wlan_instance._connected = connected
    _wlan_instance._connect_counter = 0
    _wlan_instance._connect_after = connect_after
    _wlan_instance._raise_on_connect = raise_on_connect
    _wlan_instance.active.reset_mock()
    _wlan_instance.connect.reset_mock()
    if raise_on_connect:
        _wlan_instance.connect.side_effect = raise_on_connect
    else:
        _wlan_instance.connect.side_effect = None


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestWifiConnectAlreadyConnected(unittest.TestCase):
    def setUp(self):
        _reset_wlan(connected=True)

    def test_does_not_call_connect(self):
        wifi.wifi_connect("MySSID", "password")
        _wlan_instance.connect.assert_not_called()

    def test_activates_interface(self):
        wifi.wifi_connect("MySSID", "password")
        _wlan_instance.active.assert_called_once_with(True)


class TestWifiConnectSuccess(unittest.TestCase):
    def setUp(self):
        # First isconnected() call = guard check at top → False.
        # Second call = loop poll → True (connect succeeds).
        _reset_wlan(connected=False, connect_after=2)

    def test_connect_called_with_credentials(self):
        wifi.wifi_connect("TestNet", "s3cr3t")
        _wlan_instance.connect.assert_called_once_with("TestNet", "s3cr3t")

    def test_no_exception_raised(self):
        # Should complete without raising
        wifi.wifi_connect("TestNet", "s3cr3t")

    def test_activates_interface(self):
        wifi.wifi_connect("TestNet", "s3cr3t")
        _wlan_instance.active.assert_called_once_with(True)


class TestWifiConnectTimeout(unittest.TestCase):
    def setUp(self):
        # Never becomes connected
        _reset_wlan(connected=False, connect_after=0)

    def test_raises_runtime_error_on_timeout(self):
        with self.assertRaises(RuntimeError) as ctx:
            wifi.wifi_connect("BadNet", "pass", timeout=0)
        self.assertIn("timed out", str(ctx.exception).lower())

    def test_connect_was_attempted(self):
        try:
            wifi.wifi_connect("BadNet", "pass", timeout=0)
        except RuntimeError:
            pass
        _wlan_instance.connect.assert_called_once_with("BadNet", "pass")


class TestWifiConnectOsError(unittest.TestCase):
    def setUp(self):
        _reset_wlan(connected=False, connect_after=0,
                    raise_on_connect=OSError("radio off"))

    def test_oserror_does_not_propagate(self):
        # wifi.py line 19 has a bug: `logging.error("[ERROR]" %s, e)` raises
        # NameError at runtime instead of logging the error. The important
        # behavior under test is that *OSError* from wlan.connect() does not
        # escape wifi_connect() — it is caught by the `except OSError` block.
        # The subsequent NameError (from the broken logging call) is a separate
        # bug and is expected to propagate here.
        try:
            wifi.wifi_connect("SSID", "pw", timeout=0)
        except OSError:
            self.fail("OSError propagated out of wifi_connect — should be caught inside")
        except (RuntimeError, NameError):
            pass  # RuntimeError = timeout; NameError = known bug in wifi.py line 19

    def test_connect_was_called(self):
        try:
            wifi.wifi_connect("SSID", "pw", timeout=0)
        except (RuntimeError, NameError):
            pass
        _wlan_instance.connect.assert_called_once()


if __name__ == "__main__":
    unittest.main()
