# hoymiles-wifi — MicroPython port for ESP32-C6

A lightweight port of [hoymiles-wifi](https://github.com/suaveolent/hoymiles-wifi)
that runs on MicroPython on an **ESP32-C6** (or any other ESP32 with MicroPython).

## Files

| File | Purpose |
|------|---------|
| `dtu.py` | Main DTU class — framing, communication, response parsing |
| `upb.py` | Protobuf encoder/decoder (no external deps) |
| `ucrc16.py` | CRC-16 (poly=0x8005, reflected) — equivalent to crcmod |
| `ucrypt.py` | AES-128-GCM + SHA-256 key derivation for encrypted DTUs |
| `main.py` | WiFi connection + 30-second polling loop (edit config at top) |

## Requirements

- **MicroPython ≥ 1.22** for ESP32-C6
  - Download: https://micropython.org/download/ESP32_GENERIC_C6/
- `uhashlib` (SHA-256) — included in standard ESP32 builds
- `ucryptolib` (AES ECB) — included in standard ESP32 builds
- No additional packages needed via `mip`

## Flash & deploy

```sh
# 1. Flash MicroPython firmware
esptool.py --chip esp32c6 erase_flash
esptool.py --chip esp32c6 write_flash -z 0x0 ESP32_GENERIC_C6-<version>.bin

# 2. Edit main.py — set WIFI_SSID, WIFI_PASSWORD, DTU_HOST

# 3. Upload all four files with mpremote (or Thonny)
mpremote cp ucrc16.py :ucrc16.py
mpremote cp ucrypt.py :ucrypt.py
mpremote cp upb.py    :upb.py
mpremote cp dtu.py    :dtu.py
mpremote cp main.py   :main.py

# 4. Reset the board — main.py runs automatically on boot
mpremote reset
```

## Usage as a library

```python
import asyncio
from dtu import DTU

dtu = DTU("192.168.1.100")   # replace with your DTU's IP

async def main():
    # Real-time data (new format — works with HMS-xT inverters)
    data = await dtu.get_real_data_new()
    if data:
        print("Total power:", data["dtu_power"], "W")
        for inv in data["sgs"]:
            print("Inverter", inv["serial_number"],
                  "→", inv["active_power"] / 10, "W")
        for s in data["pv"]:
            print("PV port", s["port_number"],
                  "→", s["power"] / 10, "W")

    # Heartbeat
    hb = await dtu.heartbeat()
    print("DTU serial:", hb["dtu_sn"] if hb else "offline")

    # Set power limit to 80 %
    ok = await dtu.set_power_limit(80)
    print("Power limit set:", ok)

    # Turn off inverter (integer serial number)
    # ok = await dtu.turn_off_inverter(0x1234567890AB)

asyncio.run(main())
```

## Encrypted DTUs

Some newer DTU firmwares enable AES-128-GCM encryption.
You can check and retrieve the `enc_rand` seed with:

```python
info = await dtu.get_app_info()
dtu_info = info["dtu_info"]
# Bit 25 of dfs == 1 means encrypted
is_enc = bool(dtu_info["dfs"] & (1 << 25))
enc_rand = dtu_info["enc_rand"]   # bytes, length 16
print("Encrypted:", is_enc, "enc_rand:", enc_rand.hex())
```

Then instantiate:
```python
dtu = DTU("192.168.1.100", is_encrypted=True, enc_rand=enc_rand)
```

> **Note:** I didn't test the encryption after porting it to micro python.
> The pure-Python GCM implementation in `ucrypt.py` is ~100 ms per
> message on an ESP32-C6 at 160 MHz.  At 30-second polling intervals this is
> acceptable.

## Value scaling

The DTU returns raw integers; divide to get human-readable values:

| Field | Unit | Scale |
|-------|------|-------|
| `voltage` (AC/PV) | V | ÷ 10 |
| `current` | A | ÷ 100 |
| `active_power` / `power` | W | ÷ 10 |
| `frequency` | Hz | ÷ 100 |
| `temperature` | °C | ÷ 10 |
| `energy_daily` / `energy_total` | Wh | ÷ 1 (already Wh) |
| `dtu_power` | W | ÷ 1 |
| `dtu_daily_energy` | Wh | ÷ 1 |

## Supported commands

| Method | Description |
|--------|-------------|
| `get_real_data_new()` | Real-time inverter data (HMS-xT series) |
| `get_real_data()` | Real-time data (legacy DTU format) |
| `heartbeat()` | DTU heartbeat / keep-alive |
| `get_app_info()` | Device info, firmware version, enc_rand |
| `get_network_info()` | DTU network/WiFi status |
| `set_power_limit(pct)` | Set output power limit 0–100 % |
| `turn_on_inverter(sn)` | Start a specific inverter |
| `turn_off_inverter(sn)` | Shut down a specific inverter |
| `reboot_dtu()` | Reboot the DTU |
