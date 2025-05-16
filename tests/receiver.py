import uasyncio as asyncio
from NoMQ.nomq import NoMQ
import network
import uhashlib
import ubinascii

# Wi-Fi credentials
SSID = "your_wifi_ssid"
PASSWORD = "your_wifi_password"


async def connect_wifi():
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    if not wlan.isconnected():
        print("Connecting to Wi-Fi...")
        wlan.connect(SSID, PASSWORD)
        while not wlan.isconnected():
            await asyncio.sleep(1)
    print("Wi-Fi connected:", wlan.ifconfig())

async def main():
    await connect_wifi()
    nomq = NoMQ(config_file='nomq_config.json', log_level='DEBUG')
    auth_message = b"test_message"
    public_key = ubinascii.unhexlify("abcdef1234567890abcdef1234567890")
    signature = uhashlib.sha256(auth_message + public_key).digest()
    await nomq.subscribe("test/channel", priority=5, signature=signature, message=auth_message, addr=('192.168.18.33', 8888))
    
        
    await nomq.publish("test/channel", "Hello, IoT!" * 10, qos=2, retain=True, ip="192.168.18.33", port=8888, signature=signature, auth_message=auth_message)
    await nomq.listen()
    await nomq.listen()

asyncio.run(main())
