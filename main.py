"""
main.py — Hoymiles DTU polling example for ESP32-C6 (MicroPython)

Connects to your WiFi, then polls the DTU every 30 seconds and prints
real-time solar data to the REPL.

Adjust the three configuration constants below before flashing.
"""

import asyncio

from dtu import DTU
from wifi import wifi_connect, log_info

# ---------------------------------------------------------------------------
# Configuration — edit these
# ---------------------------------------------------------------------------

WIFI_SSID     = "YourSsid"
WIFI_PASSWORD = "YourPw"
DTU_HOST      = "192.168.1.100"   # IP address of your Hoymiles DTU

POLL_INTERVAL = 30   # seconds between readings

# Encryption (most DTUs do NOT use this — leave False unless yours does)
IS_ENCRYPTED  = False
ENC_RAND      = b""  # 16-byte key seed; read from APPInfoData if needed


# ---------------------------------------------------------------------------
# Pretty-print helpers
# ---------------------------------------------------------------------------

def _fmt_power(val_tenths: int) -> str:
    """DTU returns power in tenths of Watts → W."""
    return "{:.1f} W".format(val_tenths / 10)


def _fmt_voltage(val_tenths: int) -> str:
    return "{:.1f} V".format(val_tenths / 10)


def _fmt_current(val_hundredths: int) -> str:
    return "{:.2f} A".format(val_hundredths / 100)


def print_data(data: dict):
    print("=" * 48)
    print("DTU  serial :", data.get("device_serial_number", "?"))
    print("DTU  power  :", data.get("dtu_power", 0), "W")
    print("DTU  daily  :", data.get("dtu_daily_energy", 0), "Wh")

    for i, inv in enumerate(data.get("sgs", [])):
        print()
        print("  Inverter #{} SN:{}".format(i + 1, inv["serial_number"]))
        print("    AC voltage  :", _fmt_voltage(inv["voltage"]))
        print("    AC power    :", _fmt_power(inv["active_power"]))
        print("    Temperature :", "{:.1f} °C".format(inv["temperature"] / 10))
        print("    Link status :", inv["link_status"])

    for i, s in enumerate(data.get("pv", [])):
        print()
        print("  PV string #{} (port {}) SN:{}".format(
            i + 1, s["port_number"], s["serial_number"]))
        print("    Voltage     :", _fmt_voltage(s["voltage"]))
        print("    Current     :", _fmt_current(s["current"]))
        print("    Power       :", _fmt_power(s["power"]))
        print("    Daily energy:", s["energy_daily"], "Wh")
        print("    Total energy:", s["energy_total"], "Wh")
    print("=" * 48)


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------

async def run():
    dtu = DTU(DTU_HOST, is_encrypted=IS_ENCRYPTED, enc_rand=ENC_RAND)

    while True:
        print("[poll] Requesting real-time data ...")
        try:
            data = await dtu.get_real_data_new()
            if data is None:
                print("[poll] No response from DTU (offline?)")
            else:
                print_data(data)
        except Exception as e:
            print("[poll] Error:", e)

        await asyncio.sleep(POLL_INTERVAL)


def main():
    wifi_connect(WIFI_SSID, WIFI_PASSWORD, 15)
    asyncio.run(run())


main()
