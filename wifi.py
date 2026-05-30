import network
import time

def log_info(msg, *args):
    print("[INFO]", msg % args if args else msg)

def wifi_connect(ssid, password, timeout=15):
    wlan = network.WLAN(network.STA_IF)
    
    wlan.active(True)
    
    if wlan.isconnected():
        log_info("Already connected, IP=%s", wlan.ifconfig()[0])
        return
    
    
    log_info("Connecting to WiFi SSID=%s", ssid)
    try:
        wlan.connect(ssid, password)
    except OSError as e:
        print("[ERROR]", e)
    start = time.time()
    while not wlan.isconnected():
        if time.time() - start > timeout:
            raise RuntimeError("WiFi connection timed out")
        time.sleep(1)
    log_info("WiFi connected, IP=%s", wlan.ifconfig()[0])