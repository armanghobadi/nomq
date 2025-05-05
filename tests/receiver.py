import network
import uasyncio as asyncio
from machine import Pin
from nomq import NoMQ  # Assume NoMQ class is in nomq.py

# Wi-Fi credentials
SSID = "your_wifi_ssid"
PASSWORD = "your_wifi_password"

# NoMQ configuration
CHANNEL = "test/channel"
PORT = 8888
ENCRYPTION_KEY = b'32_byte_encryption_key_1234567890'  # Must match sender
HMAC_KEY = b'32_byte_hmac_key_1234567890abcdef'  # Must match sender

async def connect_wifi():
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    if not wlan.isconnected():
        print("Connecting to Wi-Fi...")
        wlan.connect(SSID, PASSWORD)
        while not wlan.isconnected():
            await asyncio.sleep(1)
    print("Wi-Fi connected:", wlan.ifconfig())

async def receiver_task():
    # Initialize NoMQ
    nomq = NoMQ(
        ip='0.0.0.0',
        port=PORT,
        encryption_key=ENCRYPTION_KEY,
        hmac_key=HMAC_KEY,
        log_level='DEBUG'
    )
    
    try:
        # Subscribe to the channel
        await nomq.subscribe(CHANNEL, priority=0)
        print(f"Subscribed to {CHANNEL}, listening for messages...")
        
        # Start listening for incoming messages
        await nomq.listen()
    finally:
        nomq.close()

async def main():
    await connect_wifi()
    await receiver_task()

# Run the receiver
loop = asyncio.get_event_loop()
loop.run_until_complete(main())