import network
import time
import logging # https://github.com/erikdelange/MicroPython-Logging/blob/main/logging.py

def wifi_connect(ssid, password, timeout=15):
    wlan = network.WLAN(network.STA_IF)
    
    wlan.active(True)
    
    if wlan.isconnected():
        logging.debug("Already connected, IP=%s", wlan.ifconfig()[0])
        return
    
    
    logging.debug("Connecting to WiFi SSID=%s", ssid)
    try:
        wlan.connect(ssid, password)
    except OSError as e:
        logging.error("[ERROR]" %s, e)
    start = time.time()
    while not wlan.isconnected():
        if time.time() - start > timeout:
            raise RuntimeError("WiFi connection timed out")
        time.sleep(1)
    logging.debug("WiFi connected, IP=%s", wlan.ifconfig()[0])
